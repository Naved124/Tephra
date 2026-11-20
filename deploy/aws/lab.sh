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
#
# Several labs can run at once, each named by LAB_NAME. SPOT=1 runs one on
# spot capacity (cheaper, a separate vCPU quota, may be taken back; it cannot
# be stopped, only destroyed). KERNEL_FLOOR=1 with UBUNTU_VERSION=22.04 boots
# it on the 5.15 kernel.
set -euo pipefail
# The AWS CLI profile to use; set AWS_PROFILE to override.
export AWS_PROFILE="${AWS_PROFILE:-claude}"

LAB_NAME="${LAB_NAME:-tephra-dev}"
INSTANCE_TYPE="${INSTANCE_TYPE:-m7i.xlarge}"
UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"
DISK_GIB="${DISK_GIB:-60}"
SPOT="${SPOT:-0}"
KERNEL_FLOOR="${KERNEL_FLOOR:-0}"

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
	aws sts get-caller-identity >/dev/null 2>&1 || die "no AWS credentials for profile $AWS_PROFILE"
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
		local spot=false
		if [ "$SPOT" = 1 ]; then
			spot=true
			touch "$STATE/spot"
		fi
		tf apply -input=false -auto-approve \
			-var "name=$LAB_NAME" -var "instance_type=$INSTANCE_TYPE" -var "spot=$spot" \
			-var "ubuntu_version=$UBUNTU_VERSION" -var "disk_gib=$DISK_GIB" \
			-var "user_data=$(sed "s|__SSH_PUBKEY__|$(cat "$KEY.pub")|" "$REPO/deploy/vm/user-data.yaml.tmpl")"
	fi
	wait_ssh
	echo "waiting for cloud-init"
	lab_ssh 'cloud-init status --wait' || die "cloud-init failed; see /var/log/cloud-init-output.log on the instance"
	lab_ssh 'sudo bash -s' <"$REPO/deploy/vm/provision.sh"
	if [ "$KERNEL_FLOOR" = 1 ]; then
		lab_ssh 'sudo bash -s' <"$REPO/deploy/vm/kernel-floor.sh"
	fi
	if lab_ssh 'test -e /run/tephra-reboot-needed'; then
		echo "rebooting to activate BPF LSM and the chosen kernel"
		lab_ssh 'sudo systemctl reboot' || true
		sleep 20
		wait_ssh
	fi
	echo "lab ready on kernel $(lab_ssh 'uname -r'): LAB_NAME=$LAB_NAME deploy/aws/lab.sh ssh"
}

cmd_sync() {
	local id
	id=$(instance_id)
	[ -n "$id" ] || die "no instance; run: lab.sh up"
	rsync -a --delete \
		--exclude /bin/ --exclude /tephrad --exclude /bench/raw/ --exclude /bench/.cache/ --exclude /bench/DONE --exclude /.tools/ --exclude /deploy/vm/.state/ --exclude '.terraform/' --exclude '*.tfstate*' \
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
	[ ! -e "$STATE/spot" ] || die "$LAB_NAME runs on spot capacity and cannot be stopped; destroy it"
	aws ec2 stop-instances --instance-ids "$id" >/dev/null
	echo "stopping $id (the disk is still billed until: lab.sh destroy)"
}

cmd_destroy() {
	tf init -input=false >/dev/null
	tf destroy -input=false -auto-approve -var "name=$LAB_NAME" -var "user_data=-"
	rm -rf "$STATE"
}

# Every lab instance in the account, not only LAB_NAME's, so that none is
# forgotten.
# shellcheck disable=SC2016,SC2001 # backticks are JMESPath literals; sed works per line
cmd_status() {
	local out
	out=$(aws ec2 describe-instances --filters Name=tag-key,Values=lab \
		Name=instance-state-name,Values=pending,running,stopping,stopped \
		--query 'Reservations[].Instances[].[Tags[?Key==`lab`]|[0].Value,InstanceId,State.Name,InstanceType,InstanceLifecycle]' \
		--output text)
	if [ -z "$out" ]; then
		echo "no lab instance"
	else
		echo "$out" | sed 's/None$/on-demand/'
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
