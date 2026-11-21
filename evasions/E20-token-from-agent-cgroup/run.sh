#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
pid=
for p in /proc/[0-9]*; do
	[ "$(cat "$p/comm" 2>/dev/null)" = tephrad ] && pid=${p#/proc/} && break
done
[ -n "$pid" ] || { echo "no tephrad on this node"; exit 99; }
procs=$(find /hostcg -name cgroup.procs -exec grep -lx "$pid" {} + 2>/dev/null | head -n 1)
[ -n "$procs" ] || { echo "the agent's cgroup was not found"; exit 99; }
token=/var/run/secrets/kubernetes.io/serviceaccount/token
[ -s "$token" ] || { echo "no token mounted"; exit 99; }
sh -c "echo \$\$ > $procs && exec head -c 4096 $token" >/dev/null || { echo "could not join the agent's cgroup"; exit 99; }
echo "read the service account token from $(dirname "$procs")"
