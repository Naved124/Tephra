#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY' || exit 99
import os, socket
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 9002)); srv.listen(1); srv.settimeout(40)
c, peer = srv.accept(); c.settimeout(30); f = c.makefile("rwb")
n = 0
for line in f:
    words = line.decode().split()
    if not words or words[0] == "exit":
        break
    if words[0] == "ls":
        out = " ".join(os.listdir(words[1])).encode()
    elif words[0] == "cat":
        out = open(words[1], "rb").read()
    else:
        out = b"?"
    f.write(out + b"\n"); f.flush(); n += 1
f.close(); c.close()
if n == 0:
    raise SystemExit("no command arrived")
print("ran", n, "commands from", peer[0])
PY
