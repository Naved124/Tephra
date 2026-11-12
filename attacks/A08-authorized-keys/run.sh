#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
mkdir -p /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHarnessKeyNotARealKeyxxxxxxxxxxxxxxxxxxxxxx harness' >> /root/.ssh/authorized_keys
