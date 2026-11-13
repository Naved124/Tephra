#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside the dev VM as root. Installs the pinned toolchain that is not in
# the Ubuntu archive. Safe to run again.
set -euo pipefail

GO_VERSION=1.27.3
GO_SHA256=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KUBECTL_VERSION=v1.37.2
KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
HELM_VERSION=v4.3.1
HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() { # url sha256 dest
	curl -fsSL --retry 3 -o "$3" "$1"
	echo "$2  $3" | sha256sum -c --quiet -
}

if [ "$(/usr/local/go/bin/go env GOVERSION 2>/dev/null)" != "go${GO_VERSION}" ]; then
	fetch "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" "$GO_SHA256" "$tmp/go.tgz"
	rm -rf /usr/local/go
	tar -C /usr/local -xzf "$tmp/go.tgz"
fi
cat >/etc/profile.d/go.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
EOF

if ! kind version 2>/dev/null | grep -q "kind ${KIND_VERSION} "; then
	fetch "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" "$KIND_SHA256" "$tmp/kind"
	install -m 0755 "$tmp/kind" /usr/local/bin/kind
fi

if ! kubectl version --client 2>/dev/null | grep -q "Client Version: ${KUBECTL_VERSION}\$"; then
	fetch "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "$KUBECTL_SHA256" "$tmp/kubectl"
	install -m 0755 "$tmp/kubectl" /usr/local/bin/kubectl
fi

if ! helm version --short 2>/dev/null | grep -q "^${HELM_VERSION}+"; then
	fetch "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" "$HELM_SHA256" "$tmp/helm.tgz"
	tar -C "$tmp" -xzf "$tmp/helm.tgz" linux-amd64/helm
	install -m 0755 "$tmp/linux-amd64/helm" /usr/local/bin/helm
fi

export DEBIAN_FRONTEND=noninteractive

# jq: the acceptance tests read the agent's JSON events with it.
command -v jq >/dev/null || apt-get install -y -q jq

# bpftool: used to regenerate vmlinux.h and to inspect loaded programs.
if ! command -v bpftool >/dev/null || ! bpftool version >/dev/null 2>&1; then
	apt-get install -y -q bpftool || apt-get install -y -q "linux-tools-$(uname -r)"
fi

# Three kind nodes exhaust the default inotify limits.
cat >/etc/sysctl.d/90-tephra-kind.conf <<'EOF'
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512
EOF
sysctl -q --system

systemctl enable --now docker

# Enforcement needs BPF LSM programs to be called. Ubuntu builds them in but
# leaves "bpf" out of the list of active security modules, which is fixed at
# boot. Append it to the list the kernel is running with and ask for a
# reboot; vm.sh and lab.sh do that when they see the marker.
lsm_list=/sys/kernel/security/lsm
if [ -r "$lsm_list" ] && ! tr ',' '\n' <"$lsm_list" | grep -qx bpf; then
	if grep -q 'CONFIG_BPF_LSM=y' "/boot/config-$(uname -r)" 2>/dev/null; then
		# shellcheck disable=SC2016 # grub expands the variable, not this shell
		printf 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=%s,bpf"\n' "$(cat "$lsm_list")" \
			>/etc/default/grub.d/90-tephra-lsm.cfg
		update-grub 2>/dev/null
		touch /run/tephra-reboot-needed
	else
		echo "this kernel is built without BPF LSM; enforcement will not be available"
	fi
fi

echo "provisioned: $(/usr/local/go/bin/go version | cut -d' ' -f3), kind ${KIND_VERSION}, kubectl ${KUBECTL_VERSION}, helm ${HELM_VERSION}, kernel $(uname -r)"
