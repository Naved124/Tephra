#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# A named cgroup v1 hierarchy of the scenario's own. Nothing is put in it and
# notify_on_release stays off, so the agent written here is never run.
mkdir -p /tmp/cgrp
mount -t cgroup -o none,name=tephra-harness cgroup /tmp/cgrp
echo /bin/true > /tmp/cgrp/release_agent
