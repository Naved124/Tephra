#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY' || exit 99
import os, socket, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9001)); srv.listen(4096)
kids = []
for _ in range(2):
    pid = os.fork()
    if pid == 0:
        srv.settimeout(1); end = time.time() + 20
        while time.time() < end:
            try:
                c, _ = srv.accept(); c.close()
            except OSError:
                pass
        os._exit(0)
    kids.append(pid)
for _ in range(6):
    pid = os.fork()
    if pid == 0:
        end = time.time() + 15
        while time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", 9001), timeout=1).close()
            except OSError:
                pass
        os._exit(0)
    kids.append(pid)
time.sleep(5)
open("/etc/shadow", "rb").read()
for k in kids:
    os.waitpid(k, 0)
PY
