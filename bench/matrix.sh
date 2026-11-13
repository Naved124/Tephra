#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bench/matrix.sh [runs]
#
# Every configuration by every workload, RUNS times each (default 5). Cells
# already in bench/raw are skipped, so an interrupted matrix resumes where
# it stopped. Lab cluster only. Ends by writing docs/benchmarks.md.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=bench/versions.env
. bench/versions.env
export FALCO_CHART_VERSION TETRAGON_CHART_VERSION

RUNS="${1:-5}"
CONFIGS="${CONFIGS:-none tephra-all tephra-alerts tephra-enforce falco tetragon}"
WORKLOADS="${WORKLOADS:-idle exec file network}"

for config in $CONFIGS; do
	todo=0
	for w in $WORKLOADS; do
		for r in $(seq 1 "$RUNS"); do
			[ -f "bench/raw/$config/$w/$r.json" ] || todo=1
		done
	done
	[ "$todo" = 1 ] || { echo "== $config: done already"; continue; }
	echo "== $config"
	bench/config.sh "$config"
	# Runs interleave the workloads, so drift over time spreads evenly.
	for r in $(seq 1 "$RUNS"); do
		for w in $WORKLOADS; do
			[ -f "bench/raw/$config/$w/$r.json" ] && continue
			echo "-- $config $w $r"
			bench/run.sh "$config" "$w" "$r" || echo "!! $config $w $r failed"
		done
	done
done
go run ./cmd/bench bench/raw docs/benchmarks.md
