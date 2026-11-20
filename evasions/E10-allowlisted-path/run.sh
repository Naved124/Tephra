#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
cp /bin/cat /usr/bin/passwd || exit 99
/usr/bin/passwd /etc/shadow >/dev/null || exit 99
echo "read /etc/shadow as /usr/bin/passwd"
