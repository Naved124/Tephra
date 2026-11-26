#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Boots an Ubuntu 22.04 lab on an upstream 5.15 kernel: the latest 5.15.y
# stable release from kernel.org, with no distribution's patches. Ubuntu stays
# as the userland (containerd, kind, the toolchain); only the kernel is
# upstream. It answers whether Tephra runs on 5.15 itself, not only on
# Canonical's 5.15.
#
# The source tarball is checked against its kernel.org signature, made by
# Greg Kroah-Hartman's or Linus Torvalds's key (fingerprints pinned below).
# The configuration starts from Ubuntu's own 5.15 AWS kernel, so the EC2
# drivers and the container features are there; only Ubuntu's certificate
# paths are cleared and BTF and BPF LSM are made sure of.
#
# Building takes about 30 minutes on 8 vCPUs. With KERNEL_CACHE_S3 set (an
# s3:// prefix, reached with the instance's role), packages already there are
# used instead, and a new build is stored there, so a later lab installs in
# seconds. Set VANILLA_VERSION to pin a release.
#
# Runs as root after provision.sh; leaves /run/tephra-reboot-needed when a
# reboot is due.
set -euo pipefail

. /etc/os-release
[ "$VERSION_ID" = "22.04" ] || {
	echo "kernel-vanilla.sh: for Ubuntu 22.04, this is $VERSION_ID" >&2
	exit 1
}

case "$(uname -r)" in
5.15.*-vanilla)
	echo "already on $(uname -r)"
	exit 0
	;;
esac

# Primary key fingerprints of the kernel.org release signers.
GREGKH=647F28654894E3BD457199BE38DBBDC86092693E
TORVALDS=ABAF11C65A2970B130ABE3C479BE3E4300411886

cache=/var/cache/tephra-kernel
work=/var/tmp/tephra-kernel
mkdir -p "$cache" "$work"

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y build-essential bc bison flex libelf-dev libssl-dev dwarves \
	zstd xz-utils gnupg curl jq cpio kmod rsync >/dev/null
s3="${KERNEL_CACHE_S3:-}"
if [ -n "$s3" ] && ! command -v aws >/dev/null; then
	apt-get -qq install -y awscli >/dev/null
fi

ver="${VANILLA_VERSION:-}"
if [ -z "$ver" ]; then
	ver=$(curl -fsS https://www.kernel.org/releases.json |
		jq -r '.releases[].version' | grep -E '^5\.15\.[0-9]+$' | sort -V | tail -n 1)
fi
[[ "$ver" =~ ^5\.15\.[0-9]+$ ]] || {
	echo "kernel-vanilla.sh: no 5.15 release found ('$ver')" >&2
	exit 1
}
release="$ver-vanilla"

# File by file: the filters of a recursive copy match nothing in the
# AWS CLI that Ubuntu 22.04 ships (1.22), and say nothing about it.
if [ -n "$s3" ]; then
	for f in $(aws s3 ls "$s3/" | awk '{print $4}' | grep -E "^linux-(image|headers)-${release//./\\.}_.*\.deb$" || true); do
		aws s3 cp --only-show-errors "$s3/$f" "$cache/$f" && echo "fetched $f"
	done
fi
# Packages a build left behind before it was interrupted count as built.
find "$work" -maxdepth 1 -name "linux-*${release}_*.deb" ! -name '*-dbg_*' -exec mv -t "$cache" {} + 2>/dev/null || true
image=$(find "$cache" -maxdepth 1 -name "linux-image-${release}_*.deb" ! -name '*-dbg_*' | head -n 1)
if [ -n "$image" ]; then
	echo "installing $release from the cache"
else
	echo "building $release"
	# Ubuntu's 5.15 AWS kernel, for its configuration only.
	apt-get -qq install -y linux-image-aws-lts-22.04 >/dev/null
	base=$(find /boot -maxdepth 1 -name 'config-5.15.*-aws' | sort -V | tail -n 1)
	[ -n "$base" ] || {
		echo "kernel-vanilla.sh: no Ubuntu 5.15 configuration in /boot" >&2
		exit 1
	}

	cd "$work"
	rm -rf "linux-$ver"
	curl -fsSLO "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-$ver.tar.xz"
	curl -fsSLO "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-$ver.tar.sign"
	export GNUPGHOME="$work/gnupg"
	mkdir -p "$GNUPGHOME"
	chmod 700 "$GNUPGHOME"
	gpg -q --batch --auto-key-locate clear,wkd --locate-keys gregkh@kernel.org torvalds@kernel.org >/dev/null
	# The signature covers the uncompressed tarball. Only a good signature
	# by one of the two pinned keys counts.
	xz -cd "linux-$ver.tar.xz" | gpg --batch --status-fd 1 --verify "linux-$ver.tar.sign" - 2>/dev/null >verify.status || true
	grep -Eq "^\[GNUPG:\] VALIDSIG .* ($GREGKH|$TORVALDS)$" verify.status || {
		echo "kernel-vanilla.sh: linux-$ver.tar.xz has no good signature by a kernel.org release key" >&2
		exit 1
	}
	echo "signature good: $(grep -E '^\[GNUPG:\] VALIDSIG' verify.status | awk '{print $NF}')"
	tar -xf "linux-$ver.tar.xz"
	cd "linux-$ver"

	cp "$base" .config
	scripts/config \
		--set-str SYSTEM_TRUSTED_KEYS "" --set-str SYSTEM_REVOCATION_KEYS "" \
		--set-str LOCALVERSION "-vanilla" --disable LOCALVERSION_AUTO \
		--enable BPF_SYSCALL --enable BPF_LSM --enable DEBUG_INFO_BTF --enable DEBUG_INFO_BTF_MODULES
	make olddefconfig >/dev/null
	for opt in BPF_LSM DEBUG_INFO_BTF; do
		grep -qx "CONFIG_$opt=y" .config || {
			echo "kernel-vanilla.sh: CONFIG_$opt is off after olddefconfig" >&2
			exit 1
		}
	done
	# The debug-symbols package is several gigabytes and not kept; left
	# uncompressed it costs seconds instead of most of an hour on one CPU.
	make -j"$(nproc)" bindeb-pkg KDEB_PKGVERSION="$ver-1" KDEB_COMPRESS=none >"$work/build.log" 2>&1 || {
		tail -n 40 "$work/build.log" >&2
		exit 1
	}
	find "$work" -maxdepth 1 -name "linux-*${release}_*.deb" ! -name '*-dbg_*' -exec mv -t "$cache" {} +
	rm -rf "$work/linux-$ver" "$work"/*.deb
	image=$(find "$cache" -maxdepth 1 -name "linux-image-${release}_*.deb" ! -name '*-dbg_*' | head -n 1)
	[ -n "$image" ] || {
		echo "kernel-vanilla.sh: the build produced no image package" >&2
		exit 1
	}
	if [ -n "$s3" ]; then
		for f in "$cache"/linux-*"${release}"_*.deb; do
			aws s3 cp --only-show-errors "$f" "$s3/$(basename "$f")"
			echo "stored $(basename "$f") in $s3"
		done
	fi
fi

dpkg -i "$image" >/dev/null
update-grub >/dev/null 2>&1
entry="Ubuntu, with Linux $release"
grep -q "menuentry '$entry'" /boot/grub/grub.cfg || {
	echo "kernel-vanilla.sh: no GRUB entry '$entry'" >&2
	exit 1
}
echo "GRUB_DEFAULT=\"Advanced options for Ubuntu>$entry\"" >/etc/default/grub.d/99-tephra-kernel.cfg
update-grub >/dev/null 2>&1
echo "next boot: $release"
touch /run/tephra-reboot-needed
