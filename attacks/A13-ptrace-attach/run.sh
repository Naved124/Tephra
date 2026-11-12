#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY'
import ctypes, os, subprocess
libc = ctypes.CDLL(None, use_errno=True)
target = subprocess.Popen(["sleep", "30"])
PTRACE_ATTACH, PTRACE_DETACH = 16, 17
if libc.ptrace(PTRACE_ATTACH, target.pid, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "ptrace attach")
os.waitpid(target.pid, 0)
libc.ptrace(PTRACE_DETACH, target.pid, 0, 0)
target.kill()
PY
