#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bench/supervise.sh [runs]
#
# The whole benchmark, unattended, on the lab instance: the matrix twice
# (the second pass retries only the cells the first could not finish),
# docs/benchmarks.md, a summary in bench/DONE, then the instance powers
# itself off. EC2 stops an instance that shuts itself down, so only its disk
# is billed until "deploy/aws/lab.sh destroy".
#
# Start it detached so it outlives the SSH session:
#   sudo systemd-run --unit tephra-bench --uid "$USER" --same-dir \
#     -E HOME="$HOME" -E PATH="$PATH" bench/supervise.sh
# Set NO_POWEROFF=1 to keep the instance running at the end.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

RUNS="${1:-5}"
CONFIGS="${CONFIGS:-none tephra-all tephra-alerts tephra-enforce falco tetragon}"
WORKLOADS="${WORKLOADS:-idle exec file network loopback}"
export CONFIGS WORKLOADS

rm -f bench/DONE
for pass in 1 2; do
	echo "=== pass $pass $(date -u +%FT%TZ)"
	bench/matrix.sh "$RUNS" || echo "=== pass $pass ended with an error"
done

total=0 missing=""
for c in $CONFIGS; do
	for w in $WORKLOADS; do
		for r in $(seq 1 "$RUNS"); do
			total=$((total + 1))
			[ -f "bench/raw/$c/$w/$r.json" ] || missing="$missing $c/$w/$r"
		done
	done
done
n_missing=$(wc -w <<<"$missing")
{
	echo "finished $(date -u +%FT%TZ) on $(uname -r)"
	echo "cells $((total - n_missing))/$total"
	[ -z "$missing" ] || echo "missing:$missing"
} | tee bench/DONE

[ "${NO_POWEROFF:-0}" = 1 ] || sudo shutdown -h +1 "benchmark finished"
