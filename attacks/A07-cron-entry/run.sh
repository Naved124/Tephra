#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
mkdir -p /etc/cron.d
echo '* * * * * root /bin/true' > /etc/cron.d/harness
