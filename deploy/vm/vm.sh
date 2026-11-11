#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Dev VM for Tephra: Ubuntu Server LTS under QEMU/libvirt, running the kind lab
# cluster. Every attack scenario runs inside this VM and nowhere else.
#
# The VM lives in the unprivileged libvirt session (qemu:///session) with passt
# networking, so nothing here needs root on the laptop. SSH is forwarded to
# 127.0.0.1:$SSH_PORT.
set -euo pipefail

VM_NAME="${VM_NAME:-tephra-dev}"
VCPUS="${VCPUS:-4}"
MEMORY_MIB="${MEMORY_MIB:-8192}"
DISK_GIB="${DISK_GIB:-40}"
SSH_PORT="${SSH_PORT:-2222}"
UBUNTU_RELEASE="${UBUNTU_RELEASE:-noble}"
UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
STATE="$HERE/.state"
IMAGES="${XDG_DATA_HOME:-$HOME/.local/share}/libvirt/images"
BASE_NAME="ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img"
BASE_URL="https://cloud-images.ubuntu.com/releases/${UBUNTU_RELEASE}/release"
BASE_IMG="$IMAGES/$BASE_NAME"
DISK="$IMAGES/$VM_NAME.qcow2"
KEY="$STATE/id_ed25519"
REMOTE_DIR="tephra"

VIRSH=(virsh --connect qemu:///session)
SSH_OPTS=(-i "$KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=no
	-o "UserKnownHostsFile=$STATE/known_hosts" -o LogLevel=ERROR
	-o IdentitiesOnly=yes -o ConnectTimeout=5)

die() {
	echo "vm.sh: $*" >&2
	exit 1
}

need() {
	local t
	for t in "$@"; do
		command -v "$t" >/dev/null || die "missing '$t' (see README, host packages)"
	done
}

vm_exists() { "${VIRSH[@]}" dominfo "$VM_NAME" >/dev/null 2>&1; }
vm_running() { [ "$("${VIRSH[@]}" domstate "$VM_NAME" 2>/dev/null)" = "running" ]; }

# shellcheck disable=SC2029 # arguments are meant to expand on the laptop
vm_ssh() { ssh "${SSH_OPTS[@]}" tephra@127.0.0.1 "$@"; }

fetch_base() {
	[ -f "$BASE_IMG" ] && return
	mkdir -p "$IMAGES"
	echo "downloading $BASE_NAME"
	curl -fL --retry 3 -o "$BASE_IMG.part" "$BASE_URL/$BASE_NAME"
	# Integrity check against the checksum list published next to the image.
	local want
	want=$(curl -fsSL "$BASE_URL/SHA256SUMS" | awk -v f="*$BASE_NAME" '$2 == f {print $1}')
	[ -n "$want" ] || die "no checksum published for $BASE_NAME"
	echo "$want  $BASE_IMG.part" | sha256sum -c --quiet - || die "checksum mismatch for $BASE_NAME"
	mv "$BASE_IMG.part" "$BASE_IMG"
}

wait_ssh() {
	echo "waiting for SSH on 127.0.0.1:$SSH_PORT"
	local _
	for _ in $(seq 1 90); do
		vm_ssh true 2>/dev/null && return
		sleep 2
	done
	die "VM did not accept SSH within 180s"
}

create() {
	need virt-install qemu-img xorriso passt curl ssh-keygen
	fetch_base
	mkdir -p "$STATE"
	[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "$VM_NAME" -f "$KEY"
	rm -f "$STATE/known_hosts"
	sed "s|__SSH_PUBKEY__|$(cat "$KEY.pub")|" "$HERE/user-data.yaml.tmpl" >"$STATE/user-data.yaml"

	qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMG" "$DISK" "${DISK_GIB}G"
	virt-install --connect qemu:///session \
		--name "$VM_NAME" \
		--vcpus "$VCPUS" --memory "$MEMORY_MIB" --cpu host-passthrough \
		--osinfo linux2022 \
		--import --disk "path=$DISK,format=qcow2,bus=virtio" \
		--network "passt,model=virtio,portForward=127.0.0.1:${SSH_PORT}:22" \
		--cloud-init "user-data=$STATE/user-data.yaml" \
		--graphics none --noautoconsole
}

cmd_up() {
	need virsh ssh rsync
	if ! vm_exists; then
		create
	elif ! vm_running; then
		"${VIRSH[@]}" start "$VM_NAME"
	fi
	wait_ssh
	# passt hands the VM the laptop's DNS servers when the VM starts. If the
	# laptop has changed network since, they are stale.
	if ! vm_ssh 'timeout 10 getent hosts github.com >/dev/null'; then
		die "the VM cannot resolve names; if the laptop changed network, restart the VM: vm.sh down, then vm.sh up"
	fi
	echo "waiting for cloud-init"
	vm_ssh 'cloud-init status --wait' || die "cloud-init failed; see /var/log/cloud-init-output.log in the VM"
	vm_ssh 'sudo bash -s' <"$HERE/provision.sh"
	echo "VM ready: deploy/vm/vm.sh ssh"
}

cmd_sync() {
	rsync -a --delete \
		--exclude /bin/ --exclude /deploy/vm/.state/ \
		-e "ssh ${SSH_OPTS[*]}" \
		"$REPO/" "tephra@127.0.0.1:$REMOTE_DIR/"
}

cmd_ssh() {
	if [ "$#" -eq 0 ]; then
		vm_ssh -t "cd $REMOTE_DIR 2>/dev/null; exec bash -l"
	else
		# Login shell so the Go toolchain is on PATH.
		vm_ssh "cd $REMOTE_DIR && bash -lc $(printf '%q' "$*")"
	fi
}

cmd_down() {
	vm_running && "${VIRSH[@]}" shutdown "$VM_NAME"
}

cmd_destroy() {
	if vm_exists; then
		vm_running && "${VIRSH[@]}" destroy "$VM_NAME"
		"${VIRSH[@]}" undefine "$VM_NAME" --nvram 2>/dev/null || "${VIRSH[@]}" undefine "$VM_NAME"
	fi
	rm -f "$DISK"
	rm -rf "$STATE"
}

cmd_status() {
	if vm_exists; then
		"${VIRSH[@]}" domstate "$VM_NAME"
	else
		echo "not created"
	fi
}

case "${1:-}" in
up) cmd_up ;;
sync) cmd_sync ;;
ssh)
	shift
	cmd_ssh "$@"
	;;
down) cmd_down ;;
destroy) cmd_destroy ;;
status) cmd_status ;;
*)
	echo "usage: vm.sh {up|sync|ssh [command...]|down|destroy|status}" >&2
	exit 2
	;;
esac
