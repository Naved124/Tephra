#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M5 acceptance test:
#   1. An alert appears on the dashboard within 5 seconds of the action. The
#      check runs the dashboard's alert query through Grafana's API, the
#      same path a browser uses; it does not render the page.
#   2. Restarting the collector loses nothing beyond the counted queue
#      overflow.
set -euo pipefail
# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for workload in "deployment/${RELEASE}-collector" "statefulset/${RELEASE}-loki" "deployment/${RELEASE}-grafana"; do
	kubectl -n "$NAMESPACE" rollout status "$workload" --timeout=300s >/dev/null ||
		fail "${workload} did not become ready: $(kubectl -n "$NAMESPACE" get pods -o wide | tr '\n' ';')"
done

node=$(probe_up) || exit 1
agent=$(agent_on "$node")
[ -n "$agent" ] || fail "no agent pod on $node"

# Grafana is queried from outside the cluster, through a port-forward, with
# the credentials passed on stdin: nothing this script runs with the password
# is a process the sensor can see, and no command line holds it.
port=13000
kubectl -n "$NAMESPACE" port-forward "service/${RELEASE}-grafana" "${port}:3000" >/dev/null 2>&1 &
forward=$!
trap 'kill "$forward" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
	curl -fsS -o /dev/null "http://127.0.0.1:${port}/api/health" 2>/dev/null && break
	sleep 1
done

grafana_get() { # path and query
	{
		printf 'user = "%s:%s"\n' \
			"$(kubectl -n "$NAMESPACE" get secret "${RELEASE}-grafana" -o jsonpath='{.data.admin-user}' | base64 -d)" \
			"$(kubectl -n "$NAMESPACE" get secret "${RELEASE}-grafana" -o jsonpath='{.data.admin-password}' | base64 -d)"
	} | curl -fsS --max-time 10 -K - "http://127.0.0.1:${port}$1"
}

# Instant LogQL query through Grafana's Loki datasource; prints the JSON.
loki_instant() { # query
	grafana_get "/api/datasources/proxy/uid/loki/loki/api/v1/query?query=$(jq -rn --arg q "$1" '$q | @uri')"
}

# Log query over the last 10 minutes; prints the matching lines.
loki_lines() { # query
	local start
	start=$(($(date +%s) - 600))
	grafana_get "/api/datasources/proxy/uid/loki/loki/api/v1/query_range?limit=100&start=${start}000000000&query=$(jq -rn --arg q "$1" '$q | @uri')" |
		jq -r '.data.result[].values[][1]'
}

# --- provisioning ---------------------------------------------------------------

grafana_get /api/health >/dev/null || fail "Grafana is not answering"
title=$(grafana_get /api/dashboards/uid/tephra | jq -r '.dashboard.title')
[ "$title" = "Tephra" ] || fail "dashboard 'tephra' is not provisioned"
panels=$(grafana_get /api/dashboards/uid/tephra | jq -r '[.dashboard.panels[] | select(.type != "row") | .title] | join("; ")')
grafana_get /api/v1/provisioning/alert-rules | jq -e '.[] | select(.uid == "tephra-high-critical")' >/dev/null ||
	fail "alert rule tephra-high-critical is not provisioned"
if probe_exec wget -q -T 5 -O /dev/null "http://${RELEASE}-grafana.${NAMESPACE}.svc:3000/api/dashboards/uid/tephra" 2>/dev/null; then
	fail "Grafana answered an API call without credentials"
fi
pass "Grafana has the dashboard (${panels}) and the high-or-critical alert rule; anonymous access is refused"

# Loki has no authentication; only the collector and Grafana may reach it.
if probe_exec wget -q -T 3 -O /dev/null "http://${RELEASE}-loki.${NAMESPACE}.svc:3100/ready" 2>/dev/null; then
	fail "Loki is reachable from an ordinary pod; the NetworkPolicy is not enforced"
fi
pass "Loki is not reachable from an ordinary pod"

# --- 1. alert on the dashboard within 5 seconds ------------------------------------

nonce="m5-$(date +%s)-$RANDOM"
# The "Latest alerts" panel's stream selector, narrowed to this run.
query="{stream=\"alert\"} |= \"${nonce}\""
start=$(date +%s%N)
# R004: a download tool run in a container. Nothing listens on the port.
probe_exec wget -q -T 1 -O /dev/null "http://127.0.0.1:9/${nonce}" 2>/dev/null || true
line=""
while [ -z "$line" ] && [ $((($(date +%s%N) - start) / 1000000)) -lt 15000 ]; do
	line=$(loki_lines "$query" | sed -n 1p)
done
elapsed=$((($(date +%s%N) - start) / 1000000))
[ -n "$line" ] || fail "the alert did not reach Grafana within 15 s"
[ "$elapsed" -le 5000 ] || fail "the alert took ${elapsed} ms to reach Grafana, want at most 5000"
check_record "$line" "wrong alert on the dashboard" '.rule.id == "R004" and .k8s.pod == "probe" and .process.Image == "/bin/wget" and (.process.CommandLine | contains("http://127.0.0.1:9/"))'
pass "alert visible through Grafana ${elapsed} ms after the action: $(jq -c '{rule: .rule.id, level: .rule.level, pod: .k8s.pod, CommandLine: .process.CommandLine}' <<<"$line")"

# Sensor health arrives in the same store.
health=$(loki_lines "{stream=\"health\", node=\"${node}\"}" | sed -n 1p)
for _ in $(seq 1 20); do
	[ -n "$health" ] && break
	sleep 2
	health=$(loki_lines "{stream=\"health\", node=\"${node}\"}" | sed -n 1p)
done
[ -n "$health" ] || fail "no health record from ${node} in Loki"
check_record "$health" "health record lacks counters" '.health.kernel_seen > 0 and (.health | has("ringbuf_dropped")) and (.health | has("export_queue_depth"))'
pass "sensor health for the dashboard: $(jq -c '.health | {kernel_seen, ringbuf_dropped, export_queue_depth, export_dropped_events}' <<<"$health")"

# --- 2. collector restart ------------------------------------------------------------

total=3000
nonce="m5r-$(date +%s)-$RANDOM"
dropped_before=$(scrape "$agent" | awk '$1 == "tephra_export_dropped_total{stream=\"event\"}" {print $2}')
retries_before=$(scrape "$agent" | metric tephra_export_retries_total)

# 3000 marked execs over about half a minute, with the collector killed in
# the middle.
# shellcheck disable=SC2016 # the loop expands in the pod, not here
probe_exec sh -c 'i=0; while [ $i -lt '"$total"' ]; do /bin/true "$0-$i"; i=$((i+1)); [ $((i % 100)) -eq 0 ] && sleep 1; done' "$nonce" &
loop=$!
sleep 8
old=$(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/component=collector -o name)
kubectl -n "$NAMESPACE" delete "$old" --grace-period=0 --force >/dev/null 2>&1
wait "$loop"
kubectl -n "$NAMESPACE" rollout status "deployment/${RELEASE}-collector" --timeout=120s >/dev/null
new=$(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/component=collector -o name)
[ "$new" != "$old" ] || fail "the collector pod was not replaced"

count_query="sum(count_over_time({stream=\"event\", type=\"exec\"} |= \"/bin/true ${nonce}-\" [30m]))"
stored=0
dropped=0
for _ in $(seq 1 45); do
	stored=$(loki_instant "$count_query" | jq -r '.data.result[0].value[1] // "0"')
	dropped=$(($(scrape "$agent" | awk '$1 == "tephra_export_dropped_total{stream=\"event\"}" {print $2}') - dropped_before))
	[ "$stored" -ge $((total - dropped)) ] && break
	sleep 2
done
retries=$(($(scrape "$agent" | metric tephra_export_retries_total) - retries_before))
[ "$stored" -le "$total" ] || fail "${stored} records stored for ${total} sent: duplicates"
[ "$stored" -ge $((total - dropped)) ] ||
	fail "${stored} of ${total} marked events stored, with only ${dropped} counted as dropped: $((total - dropped - stored)) lost silently"
[ "$retries" -gt 0 ] || fail "no stream was retried on ${node}; the restart did not interrupt the export"
pass "collector killed mid-stream: ${stored} of ${total} marked events stored, ${dropped} counted as queue overflow, ${retries} streams sent again, none lost silently"

echo "PASS: M5"
