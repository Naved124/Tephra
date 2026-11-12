#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# The block device behind the files the kubelet gave this pod is the node's
# disk. Mounted read-only; nothing on it is touched.
dev=$(awk '$2 == "/etc/hosts" {print $1}' /proc/mounts)
mkdir -p /mnt/host
mount -o ro "$dev" /mnt/host 2>/dev/null || mount -t tmpfs none /mnt/host
ls /mnt/host >/dev/null
