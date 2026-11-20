#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs in the helper container of the scenario's target pod.
pid=
for p in /proc/[0-9]*; do
	case "$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null)" in
	"python3 -m http.server"*) pid=${p#/proc/} && break ;;
	esac
done
[ -n "$pid" ] || { echo "the application's process was not found"; exit 99; }
token=/proc/$pid/root/var/run/secrets/kubernetes.io/serviceaccount/token
cat "$token" >/dev/null || { echo "could not read $token"; exit 99; }
echo "read the application's token through $token"
