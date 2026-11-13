#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bench/config.sh <configuration>
#
# Puts the lab cluster in one benchmark configuration, one sensor at a time:
#   none            no sensor
#   tephra-all      Tephra exporting every event
#   tephra-alerts   Tephra exporting alerts only
#   tephra-enforce  Tephra, alerts only, enforcement on (BPF LSM needed)
#   falco           Falco, modern eBPF probe, default rules
#   tetragon        Tetragon, default tracing
# Falco and Tetragon come from their official charts at the versions below.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CTX=kind-tephra
FALCO_CHART_VERSION="${FALCO_CHART_VERSION:?set FALCO_CHART_VERSION (bench/versions.env)}"
TETRAGON_CHART_VERSION="${TETRAGON_CHART_VERSION:?set TETRAGON_CHART_VERSION (bench/versions.env)}"

k() { kubectl --context "$CTX" "$@"; }
h() { helm --kube-context "$CTX" "$@"; }

tephra_off() {
	# The backend stays; only the agents go.
	h upgrade tephra deploy/helm/tephra -n tephra --reset-then-reuse-values --set agent.enabled=false --set agent.enforcement.enabled=false >/dev/null
	k -n tephra wait --for=delete pod -l app.kubernetes.io/component=agent --timeout=120s >/dev/null 2>&1 || true
	# Pinned enforcement outlives the agents; removing the pins detaches it.
	local node
	for node in $(kind get nodes --name tephra); do
		docker exec "$node" rm -rf /sys/fs/bpf/tephra
	done
}
others_off() {
	h uninstall falco -n falco --wait >/dev/null 2>&1 || true
	h uninstall tetragon -n kube-system --wait >/dev/null 2>&1 || true
}
tephra_on() { # rawEvents enforce
	h upgrade tephra deploy/helm/tephra -n tephra --reset-then-reuse-values \
		--set agent.enabled=true --set agent.rawEvents="$1" \
		--set agent.enforcement.enabled="$2" --set agent.enforcement.dryRun=false >/dev/null
	k -n tephra rollout status daemonset/tephra-agent --timeout=300s >/dev/null
}

case "${1:-}" in
none)
	others_off
	tephra_off
	;;
tephra-all)
	others_off
	tephra_on true false
	;;
tephra-alerts)
	others_off
	tephra_on false false
	;;
tephra-enforce)
	others_off
	tephra_on false true
	# The workload pod carries no label, so nothing is refused; what is
	# measured is the cost of the LSM programs on every guarded action.
	# Opting the bench namespace in would refuse nothing the workloads do
	# either, and is left to the false-positive run.
	;;
falco)
	tephra_off
	h uninstall tetragon -n kube-system --wait >/dev/null 2>&1 || true
	h repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
	h repo update falcosecurity >/dev/null
	h upgrade --install falco falcosecurity/falco --version "$FALCO_CHART_VERSION" -n falco --create-namespace \
		--set driver.kind=modern_ebpf --set tty=true --wait --timeout 10m >/dev/null
	;;
tetragon)
	tephra_off
	h uninstall falco -n falco --wait >/dev/null 2>&1 || true
	h repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
	h repo update cilium >/dev/null
	h upgrade --install tetragon cilium/tetragon --version "$TETRAGON_CHART_VERSION" -n kube-system --wait --timeout 10m >/dev/null
	;;
*)
	echo "usage: bench/config.sh none|tephra-all|tephra-alerts|tephra-enforce|falco|tetragon" >&2
	exit 2
	;;
esac
# Let start-up work settle before anything is measured.
sleep 20
echo "configuration $1 ready"
