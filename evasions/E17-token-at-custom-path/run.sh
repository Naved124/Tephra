#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
[ -s /var/run/app/token ] || exit 99
cat /var/run/app/token >/dev/null || exit 99
echo "read the service account token at /var/run/app/token"
