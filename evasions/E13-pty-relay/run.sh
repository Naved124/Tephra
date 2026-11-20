#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY' || exit 99
import os, pty, select, socket, threading
srv = socket.socket(); srv.bind(("127.0.0.1", 9001)); srv.listen(1)
def operator():
    c, _ = srv.accept(); c.settimeout(30); c.sendall(b"id\nexit\n"); got = b""
    while True:
        try:
            chunk = c.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        got += chunk
    print("shell said:", got); c.close()
t = threading.Thread(target=operator); t.start()
s = socket.create_connection(("127.0.0.1", 9001))
pid, fd = pty.fork()
if pid == 0:
    os.execv("/bin/sh", ["sh"])
while True:
    ready, _, _ = select.select([s, fd], [], [], 10)
    if not ready:
        break
    if s in ready:
        d = s.recv(4096)
        if not d:
            break
        os.write(fd, d)
    if fd in ready:
        try:
            d = os.read(fd, 4096)
        except OSError:
            break
        if not d:
            break
        s.sendall(d)
s.close(); os.waitpid(pid, 0); t.join()
PY
