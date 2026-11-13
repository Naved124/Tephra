#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M12 acceptance test: enforcement, against a lab cluster whose chart has
# agent.enforcement.enabled=true (make dev-enforce). What is refused, and
# that nothing ordinary is, is the harness's part: harness run --enforce and
# harness fp --enforce.
#   1. Every agent has the enforcement programs attached and runs the mode
#      the chart asks for (MODE: dry-run or on).
#   2. Pinned: the policy maps and links are on the node's BPF filesystem.
#   3. A pod with the opt-in label comes into scope; one without does not.
#   4. The kill switch in the agent pod turns enforcement off in the kernel,
#      and a restarted agent sets it from its configuration again.
set -euo pipefail
# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MODE="${MODE:-dry-run}"
case "$MODE" in
dry-run) want_mode=1 ;;
on) want_mode=2 ;;
*) fail "MODE must be dry-run or on, not ${MODE}" ;;
esac
PIN_DIR=/sys/fs/bpf/tephra

gauge() { # pod, metric
	scrape "$1" | awk -v k="$2" '$1 == k {print $2}'
}

# A restarted agent serves /metrics a moment after its pod is Running.
wait_metrics() {
	local pod
	for pod in $(agent_pods); do
		for _ in $(seq 1 60); do
			scrape "$pod" >/dev/null 2>&1 && break
			sleep 1
		done
		scrape "$pod" >/dev/null || fail "${pod}: no /metrics after 60 s"
	done
}

# --- 1. programs and mode --------------------------------------------------------

wait_metrics
for pod in $(agent_pods); do
	avail=$(scrape "$pod" | awk '$1 == "tephra_event_type_available{type=\"enforce\"}" {print $2}')
	[ "$avail" = "1" ] || fail "${pod}: enforcement programs not attached; see its start-up log for the reason"
	mode=$(gauge "$pod" tephra_enforce_mode)
	[ "$mode" = "$want_mode" ] || fail "${pod}: enforcement mode ${mode}, want ${want_mode} (${MODE})"
done
pass "enforcement programs attached on every node, mode ${MODE}"

# --- 2. pinned on the node -------------------------------------------------------

for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
	pins=$(docker exec "$node" ls "$PIN_DIR")
	for want in enforce_cfg enforce_cgroups protect_cgroups runtime_inodes runtime_tasks \
		link_tephra_lsm_exec link_tephra_lsm_file_open link_tephra_lsm_ptrace \
		link_tephra_lsm_mount link_tephra_lsm_read_file link_tephra_lsm_load_data; do
		grep -qx "$want" <<<"$pins" || fail "${node}: ${PIN_DIR}/${want} is not pinned"
	done
done
pass "policy maps and the six links pinned under ${PIN_DIR} on every node"

# --- 3. scope follows the label --------------------------------------------------

kubectl delete namespace "$TEST_NS" --ignore-not-found --wait=true >/dev/null
kubectl create namespace "$TEST_NS" >/dev/null
trap 'kubectl delete namespace "$TEST_NS" --ignore-not-found --wait=false >/dev/null' EXIT
pods_in_scope() {
	local n=0 pod x
	for pod in $(agent_pods); do
		x=$(gauge "$pod" tephra_enforce_pods)
		n=$((n + ${x:-0}))
	done
	echo "$n"
}
before=$(pods_in_scope)
kubectl -n "$TEST_NS" run plain --image=busybox:1.37 --restart=Never -- sleep 600 >/dev/null
kubectl -n "$TEST_NS" wait --for=condition=Ready pod/plain --timeout=120s >/dev/null
sleep 2
[ "$(pods_in_scope)" = "$before" ] || fail "a pod without the label came into scope"
kubectl -n "$TEST_NS" label pod plain tephra.dev/enforce=true >/dev/null
for _ in $(seq 1 20); do
	[ "$(pods_in_scope)" = "$((before + 1))" ] && break
	sleep 0.5
done
[ "$(pods_in_scope)" = "$((before + 1))" ] || fail "the labelled pod did not come into scope"
pass "a pod comes into scope when labelled tephra.dev/enforce=true, not before"

# --- 4. kill switch --------------------------------------------------------------

pod=$(agent_pods | head -n1)
kubectl -n "$NAMESPACE" exec "${pod#pod/}" -- /tephrad enforce status | grep -q "^mode ${MODE}," ||
	fail "${pod}: tephrad enforce status does not report mode ${MODE}"
kubectl -n "$NAMESPACE" exec "${pod#pod/}" -- /tephrad enforce off | grep -qx "enforcement is off" ||
	fail "${pod}: tephrad enforce off did not report success"
[ "$(gauge "$pod" tephra_enforce_mode)" = "0" ] || fail "${pod}: still enforcing after the kill switch"
pass "the kill switch turns enforcement off in the kernel"
kubectl -n "$NAMESPACE" delete "$pod" --wait=true >/dev/null
kubectl -n "$NAMESPACE" rollout status "daemonset/${RELEASE}-agent" --timeout=180s >/dev/null
wait_metrics
for pod in $(agent_pods); do
	[ "$(gauge "$pod" tephra_enforce_mode)" = "$want_mode" ] || fail "${pod}: mode not restored after restart"
done
pass "a restarted agent sets the mode from its configuration again"

echo "PASS: M12"
