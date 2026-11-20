#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
python3 - <<'PY' || exit 99
import urllib.request
data = urllib.request.urlopen("http://files:8080/tool", timeout=20).read()
open("/tmp/tool", "wb").write(data)
PY
chmod +x /tmp/tool
/tmp/tool
