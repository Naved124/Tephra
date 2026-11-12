#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod, as uid 1000.
#
# Both attempts fail. The second names the file relative to the working
# directory, which the sensor has to put together itself.
cat /etc/shadow 2>/dev/null
cd /etc && cat ./shadow 2>/dev/null
exit 0
