#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bench/run.sh <configuration> <workload> <run number>
#
# One benchmark cell, in the configuration bench/config.sh has set up. Runs
# the workload pod on tephra-worker and writes
# bench/raw/<configuration>/<workload>/<run>.json with the workload's result
# and, measured on that node over the same interval, the sensor's CPU time
# and resident memory, and Tephra's event and drop counts.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

config="$1" workload="$2" run="$3"
CTX=kind-tephra
NODE=tephra-worker
NS=tephra-bench
out="bench/raw/${config}/${workload}/${run}.json"
k() { kubectl --context "$CTX" "$@"; }

# Sensor processes by configuration, matched on the command name.
case "$config" in
none) procs="" ;;
tephra-*) procs="tephrad" ;;
falco) procs="falco" ;;
tetragon) procs="tetragon" ;;
*) echo "unknown configuration $config" >&2; exit 2 ;;
esac

# CPU ticks (user + system) and resident kB of the sensor's processes on the
# node, from /proc.
sensor_usage() {
	[ -n "$procs" ] || { echo "0 0"; return; }
	docker exec "$NODE" sh -c '
		t=0; r=0
		for p in /proc/[0-9]*; do
			c=$(cat $p/comm 2>/dev/null) || continue
			case " '"$procs"' " in *" $c "*) ;; *) continue ;; esac
			set -- $(cut -d" " -f14,15 $p/stat)
			t=$((t + $1 + $2))
			r=$((r + $(awk "/^VmRSS/ {print \$2}" $p/status)))
		done
		echo "$t $r"'
}

# Tephra's kernel counters on the node: events emitted and dropped.
tephra_counts() {
	case "$config" in tephra-*) ;; *) echo "0 0"; return ;; esac
	local pod
	pod=$(k -n tephra get pods -l app.kubernetes.io/component=agent --field-selector "spec.nodeName=$NODE" -o jsonpath='{.items[0].metadata.name}')
	k get --raw "/api/v1/namespaces/tephra/pods/${pod}:9090/proxy/metrics" |
		awk '/^tephra_kernel_events_total/ && /outcome="emitted"/ {e += $2} /^tephra_kernel_events_total/ && /outcome="dropped"/ {d += $2} END {printf "%d %d\n", e, d}'
}

# The file workload's source, fetched once, checked against the checksum
# published next to it, and put on the node.
if [ "$workload" = file ]; then
	src=bench/.cache/busybox-1.37.0.tar.bz2
	if [ ! -f "$src" ]; then
		mkdir -p bench/.cache
		curl -fsSL -o "$src.part" https://busybox.net/downloads/busybox-1.37.0.tar.bz2
		want=$(curl -fsSL https://busybox.net/downloads/busybox-1.37.0.tar.bz2.sha256 | awk '{print $1}')
		echo "$want  $src.part" | sha256sum -c --quiet -
		mv "$src.part" "$src"
	fi
	docker exec "$NODE" mkdir -p /var/tmp/tephra-bench
	docker cp "$src" "$NODE:/var/tmp/tephra-bench/busybox.tar.bz2"
fi

k delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
k create namespace "$NS" >/dev/null
trap 'k delete namespace "$NS" --ignore-not-found --wait=false >/dev/null' EXIT
if [ "$workload" = network ]; then
	k -n "$NS" apply -f bench/workloads/network-server.yaml >/dev/null
	k -n "$NS" wait --for=condition=Ready pod/bench-server --timeout=180s >/dev/null
fi
# Pull the image before the clock starts.
image=$(awk '/image:/ {print $2; exit}' "bench/workloads/${workload}.yaml")
docker exec "$NODE" crictl pull "$image" >/dev/null

read -r cpu0 _ < <(sensor_usage)
read -r ev0 dr0 < <(tephra_counts)
t0=$(date +%s%N)
k -n "$NS" apply -f "bench/workloads/${workload}.yaml" >/dev/null
# Until the workload ends, either way; one that failed is not a result.
phase=
for _ in $(seq 1 1800); do
	phase=$(k -n "$NS" get pod bench -o jsonpath='{.status.phase}')
	[ "$phase" = Succeeded ] || [ "$phase" = Failed ] && break
	sleep 1
done
if [ "$phase" != Succeeded ]; then
	echo "workload ended $phase:" >&2
	k -n "$NS" logs bench >&2 || true
	exit 1
fi
t1=$(date +%s%N)
read -r cpu1 rss1 < <(sensor_usage)
read -r ev1 dr1 < <(tephra_counts)
result=$(k -n "$NS" logs bench | awk '/^RESULT / {sub(/^RESULT /, ""); print}')
[ -n "$result" ] || { echo "no RESULT line from the workload" >&2; exit 1; }

mkdir -p "$(dirname "$out")"
{
	printf '{"config":"%s","workload":"%s","run":%d,"wall_ns":%d' "$config" "$workload" "$run" "$((t1 - t0))"
	for kv in $result; do
		printf ',"%s":%s' "${kv%%=*}" "${kv#*=}"
	done
	printf ',"sensor_cpu_ticks":%d,"sensor_rss_kb":%d,"events":%d,"drops":%d}\n' \
		"$((cpu1 - cpu0))" "${rss1:-0}" "$((ev1 - ev0))" "$((dr1 - dr0))"
} >"$out"
cat "$out"
