#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Boots an Ubuntu 22.04 lab on the 5.15 kernel, Tephra's oldest supported
# one. Canonical's 22.04 images boot a 6.8 kernel; 5.15 is the
# linux-image-aws-lts-22.04 package, made the GRUB default here. Runs as root
# on the instance after provision.sh; leaves /run/tephra-reboot-needed when a
# reboot is due.
set -euo pipefail

. /etc/os-release
[ "$VERSION_ID" = "22.04" ] || {
	echo "kernel-floor.sh: for Ubuntu 22.04, this is $VERSION_ID" >&2
	exit 1
}

case "$(uname -r)" in
5.15.*)
	echo "already on $(uname -r)"
	exit 0
	;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y linux-image-aws-lts-22.04 linux-headers-aws-lts-22.04 >/dev/null

ver=$(find /boot -maxdepth 1 -name 'vmlinuz-5.15.*-aws' -printf '%f\n' | sed 's/^vmlinuz-//' | sort -V | tail -n 1)
[ -n "$ver" ] || {
	echo "kernel-floor.sh: no 5.15 kernel in /boot after the install" >&2
	exit 1
}
update-grub >/dev/null 2>&1
entry="Ubuntu, with Linux $ver"
grep -q "menuentry '$entry'" /boot/grub/grub.cfg || {
	echo "kernel-floor.sh: no GRUB entry '$entry'" >&2
	exit 1
}
# The image's own files in grub.d are read after /etc/default/grub; this
# one is read last.
echo "GRUB_DEFAULT=\"Advanced options for Ubuntu>$entry\"" >/etc/default/grub.d/99-tephra-kernel.cfg
update-grub >/dev/null 2>&1
echo "next boot: $ver"
touch /run/tephra-reboot-needed
