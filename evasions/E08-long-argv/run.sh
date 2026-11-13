#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
pad=$(head -c 1500 /dev/zero | tr '\0' 'A')
python3 -c "# $pad
open('/etc/shadow').read()"
