#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M0 acceptance test: every node runs an agent pod, and every agent pod logs
# that its program attached.
set -euo pipefail

NAMESPACE="${NAMESPACE:-tephra}"
RELEASE="${RELEASE:-tephra}"
TIMEOUT="${TIMEOUT:-60}"
SELECTOR="app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=agent"

dump() {
	echo "--- pods ---" >&2
	kubectl -n "$NAMESPACE" get pods -l "$SELECTOR" -o wide >&2 || true
	echo "--- logs ---" >&2
	kubectl -n "$NAMESPACE" logs -l "$SELECTOR" --prefix --tail=40 >&2 || true
}

if ! kubectl -n "$NAMESPACE" rollout status "daemonset/${RELEASE}-agent" --timeout=180s; then
	dump
	echo "FAIL: agent DaemonSet did not become ready" >&2
	exit 1
fi

nodes=$(kubectl get nodes -o name | wc -l)
mapfile -t pods < <(kubectl -n "$NAMESPACE" get pods -l "$SELECTOR" \
	--field-selector=status.phase=Running -o name)
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
