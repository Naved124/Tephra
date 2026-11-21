#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
token=
for t in /hostkubelet/pods/*/volumes/kubernetes.io~projected/e27-token/token; do
	[ -s "$t" ] && token=$t && break
done
[ -n "$token" ] || { echo "the other pod's token was not found"; exit 99; }
dd if="$token" of=/dev/null 2>/dev/null || exit 99
echo "read another pod's token at $token"
