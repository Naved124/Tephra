#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M6 acceptance test: the agent works without privileged mode.
#   1. The DaemonSet asks for no privilege beyond a short capability list.
#   2. The running agent on every node really holds exactly those
#      capabilities, as the kernel reports them.
#   3. Every event type has its hook attached on every node.
# That the sensor still does its job this way is what the other acceptance
# tests show: they run against the same unprivileged agents.
set -euo pipefail
# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

want_caps="BPF PERFMON SYS_PTRACE SYS_RESOURCE"
# Bit numbers from include/uapi/linux/capability.h.
declare -A capbit=([BPF]=39 [PERFMON]=38 [SYS_RESOURCE]=24 [SYS_PTRACE]=19)
mask=0
for cap in $want_caps; do
	mask=$((mask | 1 << capbit[$cap]))
done
want_mask=$(printf '%016x' "$mask")

# --- 1. what the chart asks for ---------------------------------------------------

sc=$(kubectl -n "$NAMESPACE" get daemonset "${RELEASE}-agent" -o json | jq -c '.spec.template.spec.containers[0].securityContext')
jq -e '.privileged == false and .allowPrivilegeEscalation == false and .readOnlyRootFilesystem == true' <<<"$sc" >/dev/null ||
	fail "agent security context is not restricted: ${sc}"
jq -e '.capabilities.drop == ["ALL"]' <<<"$sc" >/dev/null || fail "agent does not drop all capabilities: ${sc}"
added=$(jq -r '.capabilities.add | sort | join(" ")' <<<"$sc")
[ "$added" = "$want_caps" ] || fail "agent adds capabilities '${added}', want '${want_caps}'"
pass "DaemonSet: privileged false, no privilege escalation, read-only root, drop ALL, add ${added}"

# --- 2. what the kernel says the agents hold ---------------------------------------

for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
	status=$(docker exec "$node" sh -c 'cat /proc/$(pgrep -x tephrad | head -n1)/status')
	for set in CapEff CapPrm CapBnd; do
		got=$(awk -v k="${set}:" '$1 == k {print $2}' <<<"$status")
		[ "$got" = "$want_mask" ] || fail "${node}: tephrad ${set} is ${got}, want ${want_mask}"
	done
	[ "$(awk '$1 == "NoNewPrivs:" {print $2}' <<<"$status")" = "1" ] || fail "${node}: tephrad can gain privileges"
done
pass "on every node the running agent holds exactly ${want_mask} (effective, permitted and bounding) and cannot gain more"

# --- 3. every hook attached --------------------------------------------------------

for pod in $(agent_pods); do
	# enforce has a hook only where enforcement is enabled; hack/accept-m12.sh
	# checks it.
	missing=$(scrape "$pod" | awk '/^tephra_event_type_available/ && !/type="enforce"/ && $2 != 1 {print $1}' | tr '\n' ' ')
	[ -z "$missing" ] || fail "${pod}: event types without a hook: ${missing}"
	n=$(scrape "$pod" | grep -c '^tephra_event_type_available')
	[ "$n" -eq 17 ] || fail "${pod}: ${n} event types reported, want 17"
done
pass "all 16 detection event types have a hook attached on every node"

echo "PASS: M6"
