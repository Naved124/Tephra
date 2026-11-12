#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
#
# The library does not exist; the loader ignores it.
LD_PRELOAD=/tmp/tephra-lab-missing.so /bin/true
