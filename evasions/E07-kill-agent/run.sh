#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# busybox pgrep does not find it by name; /proc does.
pid=
for p in /proc/[0-9]*; do
	[ "$(cat "$p/comm" 2>/dev/null)" = tephrad ] && pid=${p#/proc/} && break
done
[ -n "$pid" ] || { echo "no tephrad on this node"; exit 99; }
kill -9 "$pid"
cat /etc/shadow >/dev/null
echo "killed tephrad $pid and read /etc/shadow"
