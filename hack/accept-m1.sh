#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M1 acceptance test:
#   1. `ls -la /tmp` in a pod gives exactly one exec event, with the right
#      path, argv and uid, within one second.
#   2. After a 10,000-exec loop, emitted + dropped + filtered == seen.
# The third criterion, matching Go and C struct sizes, is a unit test
# (TestLayoutMatchesBTF).
set -euo pipefail
# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

node=$(probe_up) || exit 1
agent=$(agent_on "$node")
[ -n "$agent" ] || fail "no agent pod on $node"
echo "probe pod on ${node}, agent ${agent}"

# --- 1. one exec, one event ---------------------------------------------------

t0=$(now)
probe_exec ls -la /tmp >/dev/null
t1=$(now)
sleep 1
found=$(events_since "$t0" | jq -c 'select(.type == "exec" and .process.CommandLine == "ls -la /tmp")')
count=$(printf '%s' "$found" | grep -c . || true)
[ "$count" -eq 1 ] || fail "expected exactly one exec event for 'ls -la /tmp' across all agents, got ${count}: ${found}"

check() { # description, jq filter that must be true
	jq -e "$2" <<<"$found" >/dev/null || fail "$1: ${found}"
}
check "wrong path" '.process.Image == "/bin/ls"'
check "wrong uid (probe runs as 1000)" '.process.uid == 1000'
check "wrong node" ".node == \"${node}\""
check "timestamp outside the window of the command" ".ts >= \"${t0}\" and .ts <= \"${t1}\""
pass "one exec event within 1s: $(jq -c '{ts, node, Image: .process.Image, CommandLine: .process.CommandLine, uid: .process.uid}' <<<"$found")"

# --- 2. counters add up after 10,000 execs -------------------------------------

before=$(scrape "$agent" | counter exec seen)
# shellcheck disable=SC2016 # the loop expands in the pod, not here
probe_exec sh -c 'i=0; while [ $i -lt 10000 ]; do /bin/true; i=$((i+1)); done'
after=$(scrape "$agent" | counter exec seen)
[ $((after - before)) -ge 10000 ] || fail "exec seen grew by $((after - before)) on ${node}, want at least 10000"

for pod in $(agent_pods); do
	# All counters of a type come from one scrape: every command this
	# script runs is itself an exec that each agent counts, so separate
	# scrapes would never agree. The agent reads a type's four counters in
	# one map lookup; a scrape can still land between two increments, so a
	# mismatch is retried. A real accounting bug shows on every scrape.
	for type in exec fork exit; do
		ok=""
		for _ in 1 2 3 4 5; do
			snap=$(scrape "$pod")
			seen=$(counter "$type" seen <<<"$snap")
			filtered=$(counter "$type" filtered <<<"$snap")
			emitted=$(counter "$type" emitted <<<"$snap")
			dropped=$(counter "$type" dropped <<<"$snap")
			if [ "$seen" -gt 0 ] && [ "$seen" -eq $((filtered + emitted + dropped)) ]; then
				ok=1
				break
			fi
		done
		[ -n "$ok" ] || fail "${pod} ${type}: seen ${seen} != filtered ${filtered} + emitted ${emitted} + dropped ${dropped}"
		echo "  ${pod} ${type}: seen ${seen} = filtered ${filtered} + emitted ${emitted} + dropped ${dropped}"
	done
done
pass "after 10,000 execs (+$((after - before)) seen on ${node}), emitted + dropped + filtered == seen on every agent"

echo "PASS: M1"
