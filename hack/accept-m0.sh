#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M0 acceptance test: every node runs an agent pod, and every agent pod logs
# that its program attached.
set -euo pipefail

# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TIMEOUT="${TIMEOUT:-60}"

dump() {
	echo "--- pods ---" >&2
	kubectl -n "$NAMESPACE" get pods -l "$SELECTOR" -o wide >&2 || true
	echo "--- logs ---" >&2
	# The agent's own log lines carry "level"; events share the stream.
	kubectl -n "$NAMESPACE" logs -l "$SELECTOR" --prefix --tail=2000 | grep '"level":' | tail -n 60 >&2 || true
}

if ! kubectl -n "$NAMESPACE" rollout status "daemonset/${RELEASE}-agent" --timeout=180s; then
	dump
	echo "FAIL: agent DaemonSet did not become ready" >&2
	exit 1
fi

nodes=$(kubectl get nodes -o name | wc -l)
mapfile -t pods < <(agent_pods)
if [ "${#pods[@]}" -ne "$nodes" ]; then
	dump
	echo "FAIL: ${#pods[@]} running agent pods for ${nodes} nodes" >&2
	exit 1
fi

for pod in "${pods[@]}"; do
	line=""
	deadline=$((SECONDS + TIMEOUT))
	while [ "$SECONDS" -lt "$deadline" ]; do
		line=$(kubectl -n "$NAMESPACE" logs "$pod" | grep -m1 '"msg":"program attached"' || true)
		[ -n "$line" ] && break
		sleep 2
	done
	if [ -z "$line" ]; then
		dump
		echo "FAIL: ${pod} did not log 'program attached' within ${TIMEOUT}s" >&2
		exit 1
	fi
	echo "${pod}: ${line}"
done

echo "PASS: program attached on ${#pods[@]}/${nodes} nodes"
