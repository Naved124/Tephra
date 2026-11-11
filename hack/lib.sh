#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for the acceptance tests. Sourced, not executed.

NAMESPACE="${NAMESPACE:-tephra}"
RELEASE="${RELEASE:-tephra}"
CLUSTER="${CLUSTER:-tephra}"
TEST_NS="tephra-test"
SELECTOR="app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=agent"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

pass() {
	echo "ok: $*"
}

# Timestamp in the format the agent writes, so strings compare in time order.
now() {
	date -u +%Y-%m-%dT%H:%M:%S.%6NZ
}

# Running agent pods, leaving out ones that are terminating: after a rollout
# the old pod of a node is still Running for a moment.
agent_pods() { # optional node name
	kubectl -n "$NAMESPACE" get pods -l "$SELECTOR" -o json |
		jq -r --arg node "${1:-}" '.items[]
			| select(.metadata.deletionTimestamp == null and .status.phase == "Running")
			| select($node == "" or .spec.nodeName == $node)
			| "pod/" + .metadata.name'
}

# The agent pod running on a node.
agent_on() {
	agent_pods "$1" | head -n1
}

# Events from every agent at or after a timestamp, one JSON object per line.
# The agent's own log shares the stream; those lines have no "type".
events_since() {
	local since="$1" pod
	for pod in $(agent_pods); do
		kubectl -n "$NAMESPACE" logs "$pod" --since-time="${since%.*}Z" 2>/dev/null |
			jq -cR --arg since "$since" 'fromjson? | select(.type != null and .ts >= $since)'
	done
}

# An agent's /metrics, through the API server proxy.
scrape() {
	kubectl get --raw "/api/v1/namespaces/${NAMESPACE}/pods/${1#pod/}:9090/proxy/metrics"
}

# One kernel counter out of a scrape read on stdin.
counter() { # type, outcome
	awk -v k="tephra_kernel_events_total{type=\"$1\",outcome=\"$2\"}" '$1 == k {print $2}'
}

# Deploys the probe pod and prints the node it landed on.
probe_up() {
	kubectl apply -f "$HERE/testdata/probe.yaml" >/dev/null
	if ! kubectl -n "$TEST_NS" wait --for=condition=Ready pod/probe --timeout=120s >/dev/null; then
		kubectl -n "$TEST_NS" get events --field-selector involvedObject.name=probe \
			-o custom-columns=REASON:.reason,MESSAGE:.message | tail -n 5 >&2
		fail "probe pod did not become ready (if its image cannot be pulled, check the VM's network)"
	fi
	kubectl -n "$TEST_NS" get pod probe -o jsonpath='{.spec.nodeName}'
}

probe_exec() {
	kubectl -n "$TEST_NS" exec probe -- "$@"
}
