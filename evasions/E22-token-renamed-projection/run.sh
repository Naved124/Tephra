#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
[ -s /opt/svc/creds ] || exit 99
dd if=/opt/svc/creds of=/dev/null 2>/dev/null || exit 99
echo "read the service account token projected at /opt/svc/creds"
