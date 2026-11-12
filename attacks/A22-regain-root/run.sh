#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
#
# No exploit: the process starts as root, drops its effective uid and takes
# it back from its saved uid. The credential change the sensor sees is the
# one a kernel privilege-escalation exploit ends with, a non-zero effective
# uid becoming zero with no setuid binary executed.
python3 -c 'import os; os.seteuid(1000); os.seteuid(0)'
