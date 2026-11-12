#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
echo /tmp/not-a-library.so >> /etc/ld.so.preload
