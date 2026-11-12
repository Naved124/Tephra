#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
#
# The file is written under another name and renamed into place, so the
# watched name is never opened. It names a library that does not exist and
# is removed straight away.
echo '/tmp/tephra-lab-missing.so' >/tmp/preload
mv /tmp/preload /etc/ld.so.preload
rm -f /etc/ld.so.preload
