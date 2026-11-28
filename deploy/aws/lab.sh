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
# Several labs can run at once, each named by LAB_NAME. A profile picks the
# image and the kernel, and a default region, one per kernel so the labs can
# run side by side within each region's 8-vCPU quota:
#
#   LAB_PROFILE=floor-ubuntu    eu-central-1    Ubuntu 22.04, Canonical's 5.15
#   LAB_PROFILE=current-ubuntu  us-east-1       Ubuntu 26.04, its 7.0 kernel
#   LAB_PROFILE=floor-vanilla   ap-northeast-1  Ubuntu 22.04, upstream 5.15.y
#                                               from kernel.org, unpatched
#
# A profile names the lab after itself unless LAB_NAME is set, and uses an
# 8-vCPU c8a.2xlarge on demand: AMD, one whole core per vCPU, so a sensor
# never shares a core with the workload it watches. c8a is offered in only a
# few regions (C8A_REGIONS); LAB_REGION runs a lab in another one, for
# instance to run several labs of one kernel at once. A region that does not
# offer the instance type is refused before anything is created. Without a
# profile the variables below apply
# as before: KERNEL_FLOOR=1 with UBUNTU_VERSION=22.04 boots Canonical's 5.15,
# KERNEL_VANILLA=1 the upstream one, and the region is the AWS profile's.
# SPOT=1 runs a lab on spot capacity (cheaper, a separate vCPU quota, may be
# taken back; it cannot be stopped, only destroyed). Each lab remembers its
# region, so later commands need only LAB_NAME.
set -euo pipefail
# The AWS CLI profile to use; set AWS_PROFILE to override.
export AWS_PROFILE="${AWS_PROFILE:-claude}"

LAB_PROFILE="${LAB_PROFILE:-}"
PROFILE_REGION=""
case "$LAB_PROFILE" in
"") ;;
floor-ubuntu)
	PROFILE_REGION=eu-central-1
	: "${UBUNTU_VERSION:=22.04}" "${KERNEL_FLOOR:=1}"
	;;
current-ubuntu)
	PROFILE_REGION=us-east-1
	: "${UBUNTU_VERSION:=26.04}"
	;;
floor-vanilla)
	PROFILE_REGION=ap-northeast-1
	: "${UBUNTU_VERSION:=22.04}" "${KERNEL_VANILLA:=1}"
	;;
*)
	echo "lab.sh: unknown LAB_PROFILE '$LAB_PROFILE' (floor-ubuntu, current-ubuntu, floor-vanilla)" >&2
	exit 2
	;;
esac
# Every region that offers c8a (checked 28 Nov 2026; eu-south-2 also does,
# but is not enabled on the account).
C8A_REGIONS="us-east-1 us-east-2 us-west-2 eu-west-1 eu-central-1 ap-northeast-1"
[ -z "${LAB_REGION:-}" ] || PROFILE_REGION="$LAB_REGION"
# The regions lab.sh status looks in, besides any a lab was created in: the
# c8a ones and those the earlier c7i labs used.
LAB_REGIONS="$C8A_REGIONS ap-south-1 ap-northeast-2"
# Built upstream kernels are kept in one bucket, in the region where they
# were first built, and fetched from there by labs in any region.
KERNEL_CACHE_REGION="${KERNEL_CACHE_REGION:-ap-northeast-2}"

if [ -n "$LAB_PROFILE" ]; then
	LAB_NAME="${LAB_NAME:-$LAB_PROFILE}"
	INSTANCE_TYPE="${INSTANCE_TYPE:-c8a.2xlarge}"
fi
LAB_NAME="${LAB_NAME:-tephra-dev}"
INSTANCE_TYPE="${INSTANCE_TYPE:-m7i.xlarge}"
UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"
DISK_GIB="${DISK_GIB:-60}"
SPOT="${SPOT:-0}"
KERNEL_FLOOR="${KERNEL_FLOOR:-0}"
KERNEL_VANILLA="${KERNEL_VANILLA:-0}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TF="$REPO/deploy/terraform/lab"
STATE="$REPO/deploy/vm/.state/aws-$LAB_NAME"
KEY="$STATE/id_ed25519"
REMOTE_DIR="tephra"

# The lab's region: the one it was created in, else the profile's, else the
# AWS profile's own.
if [ -f "$STATE/region" ]; then
	AWS_REGION="$(cat "$STATE/region")"
	export AWS_REGION
elif [ -n "$PROFILE_REGION" ]; then
	export AWS_REGION="$PROFILE_REGION"
fi
[ -z "${AWS_REGION:-}" ] || export AWS_DEFAULT_REGION="$AWS_REGION"

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

# The ssh command rsync runs, the same session as lab_ssh.
rsync_ssh() {
	echo "ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=$STATE/known_hosts -o LogLevel=ERROR -o IdentitiesOnly=yes -o 'ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p'"
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

# The bucket that keeps upstream kernel packages between labs, in
# KERNEL_CACHE_REGION whatever the lab's region, so a kernel is built once.
# It is not part of any lab, so lab.sh destroy leaves it; it is private,
# encrypted, and holds about 100 MB per kernel release.
kernel_cache_bucket() {
	local account bucket r="$KERNEL_CACHE_REGION"
	account=$(aws sts get-caller-identity --query Account --output text)
	bucket="tephra-kernel-cache-$account-$r"
	if ! aws s3api head-bucket --region "$r" --bucket "$bucket" >/dev/null 2>&1; then
		if [ "$r" = us-east-1 ]; then
			aws s3api create-bucket --region "$r" --bucket "$bucket" >/dev/null
		else
			aws s3api create-bucket --region "$r" --bucket "$bucket" \
				--create-bucket-configuration "LocationConstraint=$r" >/dev/null
		fi
		aws s3api put-public-access-block --region "$r" --bucket "$bucket" --public-access-block-configuration \
			BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
		aws s3api put-bucket-tagging --region "$r" --bucket "$bucket" --tagging 'TagSet=[{Key=project,Value=tephra-demo}]'
		echo "created s3://$bucket for built kernels" >&2
	fi
	echo "$bucket"
}

# Refuses a region that does not offer the instance type, before Terraform
# creates anything there.
check_offered() {
	local got
	got=$(aws ec2 describe-instance-type-offerings --location-type region \
		--filters "Name=instance-type,Values=$INSTANCE_TYPE" \
		--query 'InstanceTypeOfferings[0].InstanceType' --output text 2>/dev/null || true)
	[ "$got" = "$INSTANCE_TYPE" ] ||
		die "$INSTANCE_TYPE is not offered in ${AWS_REGION:-this region}; c8a regions: $C8A_REGIONS (set LAB_REGION)"
}

cmd_up() {
	need aws terraform session-manager-plugin ssh ssh-keygen rsync
	aws sts get-caller-identity >/dev/null 2>&1 || die "no AWS credentials for profile $AWS_PROFILE"
	mkdir -p "$STATE"
	[ -z "${AWS_REGION:-}" ] || echo "$AWS_REGION" >"$STATE/region"
	[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "$LAB_NAME" -f "$KEY"
	tf init -input=false >/dev/null
	tf workspace select -or-create "$LAB_NAME" >/dev/null 2>&1 || true
	local cache_bucket=""
	if [ -z "$(instance_id)" ]; then
		check_offered
	fi
	if [ "$KERNEL_VANILLA" = 1 ]; then
		cache_bucket=$(kernel_cache_bucket)
	fi

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
			-var "kernel_cache_bucket=$cache_bucket" \
			-var "user_data=$(sed "s|__SSH_PUBKEY__|$(cat "$KEY.pub")|" "$REPO/deploy/vm/user-data.yaml.tmpl")"
	fi
	wait_ssh
	# Polled with short sessions: one long one can be dropped while idle,
	# which is not cloud-init failing.
	echo "waiting for cloud-init"
	local ci=""
	while :; do
		ci=$(lab_ssh 'cloud-init status 2>/dev/null | sed -n "s/^status: //p"' 2>/dev/null || echo unknown)
		case "$ci" in
		done) break ;;
		error | degraded*) die "cloud-init failed; see /var/log/cloud-init-output.log on the instance" ;;
		esac
		sleep 15
	done
	lab_ssh 'sudo bash -s' <"$REPO/deploy/vm/provision.sh"
	if [ "$KERNEL_FLOOR" = 1 ]; then
		lab_ssh 'sudo bash -s' <"$REPO/deploy/vm/kernel-floor.sh"
	fi
	if [ "$KERNEL_VANILLA" = 1 ]; then
		# The build takes long enough for an idle session to be dropped, so
		# it runs as a job on the instance and is polled with short sessions.
		lab_ssh 'cat >/tmp/kernel-vanilla.sh' <"$REPO/deploy/vm/kernel-vanilla.sh"
		lab_ssh "sudo systemctl reset-failed tephra-kernel 2>/dev/null; sudo systemd-run --unit tephra-kernel --setenv VANILLA_VERSION=${VANILLA_VERSION:-} --setenv KERNEL_CACHE_S3=s3://$cache_bucket/kernel-vanilla --setenv AWS_DEFAULT_REGION=$KERNEL_CACHE_REGION bash /tmp/kernel-vanilla.sh"
		local state=""
		while :; do
			state=$(lab_ssh 'systemctl show -p ActiveState --value tephra-kernel' 2>/dev/null || echo unknown)
			case "$state" in active | activating | unknown) ;; *) break ;; esac
			lab_ssh 'sudo tail -n 1 /var/tmp/tephra-kernel/build.log 2>/dev/null | cut -c1-100' 2>/dev/null || true
			sleep 30
		done
		lab_ssh 'sudo journalctl -u tephra-kernel -o cat --no-pager | tail -n 20'
		[ "$(lab_ssh 'systemctl show -p Result --value tephra-kernel')" = success ] || die "the upstream kernel was not installed; see journalctl -u tephra-kernel on the instance"
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
		--exclude-from "$REPO/.git/info/exclude" \
		-e "$(rsync_ssh)" "$REPO/" "tephra@$id:$REMOTE_DIR/"
}

cmd_ssh() {
	if [ "$#" -eq 0 ]; then
		lab_ssh -t "cd $REMOTE_DIR 2>/dev/null; exec bash -l"
	else
		# Login shell so the Go toolchain is on PATH. Before the first sync
		# or clone there is no repository yet; run from the home directory.
		lab_ssh "{ cd $REMOTE_DIR 2>/dev/null || true; } && bash -lc $(printf '%q' "$*")"
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

# Every lab instance in the account, not only LAB_NAME's, in every region a
# profile uses or a lab was created in, so that none is forgotten.
# shellcheck disable=SC2016,SC2001 # backticks are JMESPath literals; sed works per line
cmd_status() {
	local regions region out any=0
	regions=$({
		echo "$LAB_REGIONS" | tr ' ' '\n'
		cat "$REPO"/deploy/vm/.state/aws-*/region 2>/dev/null || true
		[ -z "${AWS_REGION:-}" ] || echo "$AWS_REGION"
		aws configure get region 2>/dev/null || true
	} | grep . | sort -u)
	for region in $regions; do
		out=$(aws ec2 describe-instances --region "$region" --filters Name=tag-key,Values=lab \
			Name=instance-state-name,Values=pending,running,stopping,stopped \
			--query 'Reservations[].Instances[].[Tags[?Key==`lab`]|[0].Value,InstanceId,State.Name,InstanceType,InstanceLifecycle]' \
			--output text)
		[ -n "$out" ] || continue
		any=1
		echo "$out" | sed 's/None$/on-demand/' | sed "s/^/$region\t/"
	done
	[ "$any" = 1 ] || echo "no lab instance in: $(echo "$regions" | tr '\n' ' ')"
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
