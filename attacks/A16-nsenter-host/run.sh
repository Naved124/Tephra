#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
nsenter -t 1 -m -u -i -n -p true
