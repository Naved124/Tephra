#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
# The token is read, as a thief would, but not used: a command line is
# recorded by the sensor, and a credential does not belong in its events.
# The connection to the API is what the second rule detects.
cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null
wget -q -T 5 -O /dev/null --no-check-certificate \
	"https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api" || true
