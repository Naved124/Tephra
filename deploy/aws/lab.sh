#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The Tephra lab on EC2: the same machine as deploy/vm/vm.sh builds on the
# laptop, created with Terraform (deploy/terraform/lab). It costs money while
# it runs; "down" stops it (the disk is still billed), "destroy" removes
# everything.
#
# The instance has no inbound port. SSH and rsync run inside an AWS Systems
# Manager session, so the laptop needs the aws CLI, a login (aws sso login),
# session-manager-plugin and terraform.
set -euo pipefail
# The AWS CLI profile to use; set AWS_PROFILE to override.
export AWS_PROFILE="${AWS_PROFILE:-admin}"

LAB_NAME="${LAB_NAME:-tephra-dev}"
INSTANCE_TYPE="${INSTANCE_TYPE:-m7i.xlarge}"
UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"
DISK_GIB="${DISK_GIB:-60}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TF="$REPO/deploy/terraform/lab"
STATE="$REPO/deploy/vm/.state/aws-$LAB_NAME"
KEY="$STATE/id_ed25519"
REMOTE_DIR="tephra"

die() {
	echo "lab.sh: $*" >&2
	exit 1
}

need() {
	local t
	for t in "$@"; do
		command -v "$t" >/dev/null || die "missing '$t'"
	done
}

tf() {
	TF_WORKSPACE="$LAB_NAME" terraform -chdir="$TF" "$@"
}

instance_id() {
	tf output -raw instance_id 2>/dev/null | grep -E '^i-[0-9a-f]+$' || true
}

instance_state() {
	aws ec2 describe-instances --instance-ids "$1" \
		--query 'Reservations[0].Instances[0].State.Name' --output text
}

# shellcheck disable=SC2029 # arguments are meant to expand on the laptop
lab_ssh() {
	local id
	id=$(instance_id)
	[ -n "$id" ] || die "no instance; run: lab.sh up"
	ssh -i "$KEY" -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$STATE/known_hosts" \
		-o LogLevel=ERROR -o IdentitiesOnly=yes -o ConnectTimeout=20 -o ServerAliveInterval=30 \
		-o "ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p" \
		"tephra@$id" "$@"
}

wait_ssh() {
	echo "waiting for the instance to accept a session"
	local _
	for _ in $(seq 1 60); do
		lab_ssh true 2>/dev/null && return
		sleep 5
	done
	die "the instance did not accept a session within 5 minutes"
}

cmd_up() {
	need aws terraform session-manager-plugin ssh ssh-keygen rsync
	aws sts get-caller-identity >/dev/null 2>&1 || die "not logged in to AWS; run: aws sso login"
	mkdir -p "$STATE"
	[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "$LAB_NAME" -f "$KEY"
	tf init -input=false >/dev/null
	tf workspace select -or-create "$LAB_NAME" >/dev/null 2>&1 || true

	local id
	id=$(instance_id)
	if [ -n "$id" ] && [ "$(instance_state "$id")" = "stopped" ]; then
		aws ec2 start-instances --instance-ids "$id" >/dev/null
		aws ec2 wait instance-running --instance-ids "$id"
	elif [ -z "$id" ]; then
		rm -f "$STATE/known_hosts"
		tf apply -input=false -auto-approve \
			-var "name=$LAB_NAME" -var "instance_type=$INSTANCE_TYPE" \
			-var "ubuntu_version=$UBUNTU_VERSION" -var "disk_gib=$DISK_GIB" \
			-var "user_data=$(sed "s|__SSH_PUBKEY__|$(cat "$KEY.pub")|" "$REPO/deploy/vm/user-data.yaml.tmpl")"
	fi
	wait_ssh
	echo "waiting for cloud-init"
	lab_ssh 'cloud-init status --wait' || die "cloud-init failed; see /var/log/cloud-init-output.log on the instance"
	lab_ssh 'sudo bash -s' <"$REPO/deploy/vm/provision.sh"
	if lab_ssh 'test -e /run/tephra-reboot-needed'; then
		echo "rebooting to activate BPF LSM"
		lab_ssh 'sudo systemctl reboot' || true
		sleep 20
		wait_ssh
	fi
	echo "lab ready: deploy/aws/lab.sh ssh"
}

cmd_sync() {
	local id
	id=$(instance_id)
	[ -n "$id" ] || die "no instance; run: lab.sh up"
	rsync -a --delete \
		--exclude /bin/ --exclude /deploy/vm/.state/ --exclude '.terraform/' --exclude '*.tfstate*' \
		-e "ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=$STATE/known_hosts -o LogLevel=ERROR -o IdentitiesOnly=yes -o 'ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p'" \
		"$REPO/" "tephra@$id:$REMOTE_DIR/"
}

cmd_ssh() {
	if [ "$#" -eq 0 ]; then
		lab_ssh -t "cd $REMOTE_DIR 2>/dev/null; exec bash -l"
	else
		# Login shell so the Go toolchain is on PATH.
		lab_ssh "cd $REMOTE_DIR && bash -lc $(printf '%q' "$*")"
	fi
}

cmd_down() {
	local id
	id=$(instance_id)
	[ -n "$id" ] || return 0
	aws ec2 stop-instances --instance-ids "$id" >/dev/null
	echo "stopping $id (the disk is still billed until: lab.sh destroy)"
}

cmd_destroy() {
	tf init -input=false >/dev/null
	tf destroy -input=false -auto-approve -var "name=$LAB_NAME" -var "user_data=-"
	rm -rf "$STATE"
}

cmd_status() {
	local id
	id=$(instance_id)
	if [ -z "$id" ]; then
		echo "not created"
	else
		echo "$id $(instance_state "$id")"
	fi
}

case "${1:-}" in
up | sync | ssh | down | destroy | status)
	cmd="$1"
	shift
	"cmd_$cmd" "$@"
	;;
*)
	echo "usage: lab.sh up|sync|ssh [command]|down|destroy|status" >&2
	exit 2
	;;
esac
