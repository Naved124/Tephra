#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
echo '{"method":"login"}' | nc -w 2 pool 3333 || true
