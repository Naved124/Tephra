#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# Eight loops of processes that exit at once; the read happens in the middle.
for _ in 1 2 3 4 5 6 7 8; do
	(i=0; while [ $i -lt 4000 ]; do /bin/true; i=$((i + 1)); done) &
done
sleep 2
cat /etc/shadow >/dev/null
wait
