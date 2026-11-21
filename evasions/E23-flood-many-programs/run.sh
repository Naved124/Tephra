#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# Let the flood run long enough to fill the agent's queue.
sleep 10
pid=
for p in /proc/[0-9]*; do
	[ "$(cat "$p/comm" 2>/dev/null)" = tephrad ] && pid=${p#/proc/} && break
done
[ -n "$pid" ] || { echo "no tephrad on this node"; exit 99; }
kill -9 "$pid"
sleep 5
dd if=/etc/shadow of=/dev/null 2>/dev/null || exit 99
echo "killed tephrad $pid during a flood from 200 programs and read /etc/shadow with dd"
