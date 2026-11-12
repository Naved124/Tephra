#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
echo 'id' >>/root/.ash_history
rm /root/.ash_history
ln -s /dev/null /root/.ash_history
