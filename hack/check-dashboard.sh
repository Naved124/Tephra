#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs every query of the provisioned dashboard through Grafana, over the last
# hour, and fails if one is rejected or returns nothing. It reads the
# dashboard Grafana actually serves, not the file in the chart. It does not
# render the page: what a panel looks like still needs a browser
# (kubectl -n tephra port-forward service/tephra-grafana 3000:3000).
#
# Run it after the cluster has seen some alerts, for example after
# `make coverage`.
set -euo pipefail
# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

port=13001
kubectl -n "$NAMESPACE" port-forward "service/${RELEASE}-grafana" "${port}:3000" >/dev/null 2>&1 &
forward=$!
trap 'kill "$forward" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
	curl -fsS -o /dev/null "http://127.0.0.1:${port}/api/health" 2>/dev/null && break
	sleep 1
done

# Credentials go to curl on stdin, never on a command line.
grafana_get() { # path and query
	{
		printf 'user = "%s:%s"\n' \
			"$(kubectl -n "$NAMESPACE" get secret "${RELEASE}-grafana" -o jsonpath='{.data.admin-user}' | base64 -d)" \
			"$(kubectl -n "$NAMESPACE" get secret "${RELEASE}-grafana" -o jsonpath='{.data.admin-password}' | base64 -d)"
	} | curl -sS --max-time 30 -K - "http://127.0.0.1:${port}$1"
}

end=$(date +%s)
start=$((end - 3600))
bad=0
# One line per query: panel title, a tab, the expression with the dashboard
# variables set to "everything" and the intervals to fixed values.
while IFS=$'\t' read -r title expr; do
	out=$(grafana_get "/api/datasources/proxy/uid/loki/loki/api/v1/query_range?start=${start}000000000&end=${end}000000000&step=60&limit=50&query=$(jq -rn --arg q "$expr" '$q | @uri')")
	status=$(jq -r '.status // "error"' <<<"$out" 2>/dev/null || echo error)
	n=$(jq -r '.data.result | length' <<<"$out" 2>/dev/null || echo 0)
	if [ "$status" != "success" ]; then
		echo "FAIL: ${title}: query rejected: $(head -c 300 <<<"$out")"
		bad=1
	elif [ "$n" -eq 0 ]; then
		echo "FAIL: ${title}: no data in the last hour"
		bad=1
	else
		echo "ok: ${title}: ${n} series or streams"
	fi
done < <(grafana_get /api/dashboards/uid/tephra | jq -r '
	.dashboard.panels[] | select(.type != "row") | .title as $t | .targets[] |
	[$t, (.expr
		| gsub("\\$cluster"; ".*") | gsub("\\$namespace"; ".*")
		| gsub("\\$__rate_interval"; "1m") | gsub("\\$__interval"; "1m") | gsub("\\$__range"; "1h"))] | @tsv')

[ "$bad" -eq 0 ] || fail "some dashboard panels have no data or a broken query"
pass "every dashboard query is accepted and returns data"
