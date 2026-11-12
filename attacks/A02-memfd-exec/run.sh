#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY'
import os
fd = os.memfd_create("payload")
with open("/bin/busybox", "rb") as src:
    os.write(fd, src.read())
# busybox picks its applet from argv[0]; "true" does nothing.
os.execve(f"/proc/self/fd/{fd}", ["true"], {})
PY
