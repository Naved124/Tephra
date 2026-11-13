#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# /tmp/notes.txt is a hard link to /etc/shadow, made when the pod started.
cat /tmp/notes.txt >/dev/null
