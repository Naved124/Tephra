#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M3 acceptance test:
#   1. A request from a pod gives a connect event with the right destination,
#      over IPv4 and over IPv6, and the server side gives an accept event.
#   2. Opening a watched path gives exactly one event; so does opening the
#      same file through a hard link under another name.
#   3. Opening an unwatched path gives none and increments filtered.
#   4. A file-heavy workload ends with zero drops.
set -euo pipefail
# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

node=$(probe_up) || exit 1
agent=$(agent_on "$node")
[ -n "$agent" ] || fail "no agent pod on $node"

for type in connect accept unix_connect file_open; do
	[ "$(scrape "$agent" | awk -v k="tephra_event_type_available{type=\"${type}\"}" '$1 == k {print $2}')" = "1" ] ||
		fail "event type ${type} has no hook attached on ${node}"
done
pass "connect, accept, unix_connect and file_open hooks attached on ${node}"

# --- 1. connect and accept, IPv4 and IPv6 ----------------------------------------

mapfile -t ips < <(kubectl -n "$TEST_NS" get pod probe -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}')
[ "${#ips[@]}" -eq 2 ] || fail "probe pod has ${#ips[@]} addresses, want one IPv4 and one IPv6 (dual-stack cluster)"

for ip in "${ips[@]}"; do
	case "$ip" in
	*:*) family=ipv6 url="http://[${ip}]:8080/" ;;
	*) family=ipv4 url="http://${ip}:8080/" ;;
	esac
	t0=$(now)
	# The web server in the root container answers 404; the connection is
	# what matters.
	probe_exec wget -q -T 5 -O /dev/null "$url" 2>/dev/null || true
	sleep 1

	found=$(events_since "$t0" | jq -c "select(.type == \"connect\" and .network.DestinationIp == \"${ip}\" and .network.DestinationPort == 8080)")
	n=$(printf '%s' "$found" | grep -c . || true)
	[ "$n" -eq 1 ] || fail "${family}: expected exactly one connect event to ${ip}:8080, got ${n}: ${found}"
	check_record "$found" "${family} connect: wrong family or protocol" ".network.family == \"${family}\" and .network.protocol == \"tcp\" and .network.direction == \"outbound\""
	check_record "$found" "${family} connect: wrong process" '.process.Image == "/bin/wget" and .process.uid == 1000'
	check_record "$found" "${family} connect: wrong pod" ".k8s.pod == \"probe\" and .container.name == \"probe\" and .node == \"${node}\""

	acc=$(wait_record "$t0" ".type == \"accept\" and .network.DestinationPort == 8080 and .network.SourceIp == \"${ip}\"" 10)
	[ -n "$acc" ] || fail "${family}: no accept event on the server side"
	check_record "$acc" "${family} accept: wrong addresses" ".network.DestinationIp == \"${ip}\" and .network.direction == \"inbound\" and .network.family == \"${family}\""
	check_record "$acc" "${family} accept: wrong process" '.process.Image == "/bin/httpd" and .container.name == "root"'
	pass "${family}: one connect event to ${ip}:8080 and its accept: $(jq -c '{Image: .process.Image, network}' <<<"$found")"
done

# --- 2. watched file, by path and by identity ------------------------------------

# /etc/shadow is watched by the shipped rule R005.
t0=$(now)
root_exec cat /etc/shadow >/dev/null
sleep 1
found=$(events_since "$t0" | jq -c 'select(.type == "file_open" and .rule == null and .file.path == "/etc/shadow")')
n=$(printf '%s' "$found" | grep -c . || true)
[ "$n" -eq 1 ] || fail "expected exactly one file_open event for /etc/shadow, got ${n}: ${found}"
check_record "$found" "wrong process or flags" '.process.Image == "/bin/cat" and .file.write == false and .process.uid == 0'
check_record "$found" "wrong pod" ".k8s.pod == \"probe\" and .container.name == \"root\" and .node == \"${node}\""
pass "one file_open event for a watched path: $(jq -c '{Image: .process.Image, file}' <<<"$found")"

# A hard link under an unwatched directory, with an unwatched name.
root_exec sh -c 'rm -f /tmp/innocent && ln /etc/shadow /tmp/innocent'
t0=$(now)
root_exec cat /tmp/innocent >/dev/null
sleep 1
found=$(events_since "$t0" | jq -c 'select(.type == "file_open" and .rule == null and .file.path == "/tmp/innocent")')
root_exec rm -f /tmp/innocent
n=$(printf '%s' "$found" | grep -c . || true)
[ "$n" -eq 1 ] || fail "expected exactly one file_open event for the hard link /tmp/innocent, got ${n}: ${found}"
check_record "$found" "hard link not recognised by identity" '.file.matched_by == "inode" and .file.target == "/etc/shadow"'
pass "the same file through a hard link is reported by identity: $(jq -c '.file' <<<"$found")"

# --- 3. unwatched file ---------------------------------------------------------------

before=$(scrape "$agent")
t0=$(now)
root_exec cat /etc/hostname >/dev/null
sleep 1
n=$(events_since "$t0" | jq -c 'select(.type == "file_open" and .file.path == "/etc/hostname")' | grep -c . || true)
[ "$n" -eq 0 ] || fail "unwatched /etc/hostname produced ${n} file_open events"
after=$(scrape "$agent")
grew=$(($(counter file_open filtered <<<"$after") - $(counter file_open filtered <<<"$before")))
[ "$grew" -gt 0 ] || fail "file_open filtered did not grow on ${node}"
pass "an unwatched path gives no event; filtered grew by ${grew}"

# --- 4. file-heavy workload, zero drops ------------------------------------------

before=$(scrape "$agent" | counter file_open seen)
# shellcheck disable=SC2016 # the loop expands in the pod, not here
root_exec sh -c 'i=0; while [ $i -lt 25 ]; do find /bin /etc /proc/sys -type f 2>/dev/null | xargs cat >/dev/null 2>&1; i=$((i+1)); done' || true
after=$(scrape "$agent" | counter file_open seen)
[ $((after - before)) -ge 20000 ] || fail "file_open seen grew by $((after - before)) on ${node}, want at least 20000"

for pod in $(agent_pods); do
	snap=$(scrape "$pod")
	# Every event type the agent reports, whatever milestone added it.
	mapfile -t types < <(awk -F'"' '/^tephra_kernel_events_total.*outcome="dropped"/ {print $2}' <<<"$snap")
	for type in "${types[@]}"; do
		dropped=$(counter "$type" dropped <<<"$snap")
		[ "$dropped" -eq 0 ] || fail "${pod}: ${dropped} ${type} events dropped"
	done
done
pass "after a file-heavy workload (+$((after - before)) opens seen on ${node}), zero drops of any type on every agent"

echo "PASS: M3"
