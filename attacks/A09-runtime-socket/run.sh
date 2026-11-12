#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/containerd/containerd.sock")
s.close()
PY
