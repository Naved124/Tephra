#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M2 acceptance test:
#   1. A pod's exec event carries namespace, pod, container, image and an
#      ancestor chain.
#   2. A host process is labelled host.
#   3. After an agent restart, events from long-running processes still
#      resolve.
set -euo pipefail
# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

node=$(probe_up) || exit 1
cid=$(kubectl -n "$TEST_NS" get pod probe -o jsonpath='{.status.containerStatuses[?(@.name=="probe")].containerID}')
cid="${cid#containerd://}"

# Waits for one exec event matching a jq filter and prints it.
wait_event() { # since, jq filter, timeout seconds
	local since="$1" filter="$2" deadline=$((SECONDS + $3)) found=""
	while [ "$SECONDS" -lt "$deadline" ]; do
		found=$(events_since "$since" | jq -c "select(.type == \"exec\" and (${filter}))" | sed -n 1p)
		[ -n "$found" ] && break
		sleep 1
	done
	printf '%s' "$found"
}

check() { # event, description, jq filter that must be true
	jq -e "$3" <<<"$1" >/dev/null || fail "$2: $1"
}

# --- 1. pod attribution and ancestry -------------------------------------------

t0=$(now)
probe_exec ls -la /var >/dev/null
ev=$(wait_event "$t0" '.process.CommandLine == "ls -la /var"' 5)
[ -n "$ev" ] || fail "no exec event for 'ls -la /var'"
check "$ev" "wrong namespace" ".k8s.namespace == \"${TEST_NS}\""
check "$ev" "wrong pod" '.k8s.pod == "probe"'
check "$ev" "pod labels missing" '.k8s.labels.app == "probe"'
check "$ev" "wrong container name" '.container.name == "probe"'
check "$ev" "wrong container ID" ".container.id == \"${cid}\""
check "$ev" "wrong image" '.container.image | test("busybox:1.37")'
check "$ev" "no parent" '.parent.Image != null and .parent.Image != ""'
check "$ev" "ancestor chain does not reach the container shim" '.ancestors | any(test("containerd-shim"))'
pass "pod event attributed: $(jq -c '{k8s, container: {name: .container.name, image: .container.image}, ancestors}' <<<"$ev")"

# --- 2. host process ------------------------------------------------------------

# A process started directly on the node, outside every pod.
t0=$(now)
docker exec "$node" ls -la /etc/kubernetes >/dev/null
ev=$(wait_event "$t0" '.process.CommandLine == "ls -la /etc/kubernetes"' 5)
[ -n "$ev" ] || fail "no exec event for the host process on ${node}"
check "$ev" "host process not labelled host" '.k8s.namespace == "host" and .k8s.pod == null'
check "$ev" "host process has a container" '.container == null'
check "$ev" "wrong node" ".node == \"${node}\""
n=$(events_since "$t0" | jq -c 'select(.type == "exec" and .process.CommandLine == "ls -la /etc/kubernetes")' | grep -c . || true)
[ "$n" -eq 1 ] || fail "host exec reported ${n} times; each node's agent must report only its own node"
pass "host process labelled host, reported once: $(jq -c '{node, k8s, Image: .process.Image}' <<<"$ev")"

# --- 3. agent restart -----------------------------------------------------------

# The probe's shell started long before the new agent does. Its next child
# must still resolve to the pod, with the shell as parent.
kubectl -n "$NAMESPACE" rollout restart "daemonset/${RELEASE}-agent" >/dev/null
kubectl -n "$NAMESPACE" rollout status "daemonset/${RELEASE}-agent" --timeout=180s >/dev/null
t0=$(now)
ev=$(wait_event "$t0" ".process.CommandLine == \"sleep 5\" and .container.id == \"${cid}\"" 30)
[ -n "$ev" ] || fail "no 'sleep 5' exec from the probe pod after the agent restart"
check "$ev" "pod lost after restart" ".k8s.namespace == \"${TEST_NS}\" and .k8s.pod == \"probe\" and .container.name == \"probe\""
check "$ev" "parent is not the pre-existing shell" '.parent.Image == "/bin/sh" and (.parent.CommandLine | test("while true"))'
check "$ev" "ancestor chain does not reach the container shim" '.ancestors | any(test("containerd-shim"))'
pass "after agent restart, a child of a pre-existing process resolves: $(jq -c '{parent, k8s: {pod: .k8s.pod}, ancestors}' <<<"$ev")"

echo "PASS: M2"
