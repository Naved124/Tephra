#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY'
import os, socket, threading
srv = socket.socket(); srv.bind(("127.0.0.1", 9001)); srv.listen(1)
def operator():
    c, _ = srv.accept(); c.settimeout(30)
    for cmd in (b"ls /\n", b"cat /etc/hostname\n", b"exit\n"):
        c.sendall(cmd); print("session said:", c.recv(4096))
    c.close()
t = threading.Thread(target=operator); t.start()
s = socket.create_connection(("127.0.0.1", 9001)); s.settimeout(30); f = s.makefile("rwb")
for line in f:
    words = line.decode().split()
    if not words or words[0] == "exit":
        break
    if words[0] == "ls":
        out = "\n".join(os.listdir(words[1])).encode()
    elif words[0] == "cat":
        out = open(words[1], "rb").read()
    else:
        out = b"?"
    f.write(out + b"\n"); f.flush()
# The file object holds the socket open; both must be closed.
f.close(); s.close(); t.join()
PY
