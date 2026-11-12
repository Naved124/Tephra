#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# M4 acceptance test:
#   1. The shipped rules fire on live actions: a shell on a socket (R001) and
#      a read of /etc/shadow, also through a hard link (R005).
#   2. An invalid rule stops start-up, naming the file and the line.
#   3. A rule added to the ConfigMap takes effect on SIGHUP without a restart,
#      and an invalid one is refused while the running rules stay in force.
# That every rule has one matching and one non-matching recorded event is a
# unit test (TestShippedRules).
set -euo pipefail
# shellcheck source=hack/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

node=$(probe_up) || exit 1
agent=$(agent_on "$node")
[ -n "$agent" ] || fail "no agent pod on $node"
shipped=$(find "$HERE/../rules" -maxdepth 1 -name '*.yaml' | wc -l)
loaded=$(scrape "$agent" | metric tephra_rules_loaded)
[ "$loaded" -eq "$shipped" ] || fail "${agent} has ${loaded} rules loaded, the repository ships ${shipped}"

# Sends SIGHUP to the agent on the probe's node. The agent image has no
# shell, so the signal is sent from the node itself.
hup() {
	docker exec "$node" pkill -HUP -x tephrad
}

cleanup() {
	kubectl -n "$TEST_NS" delete pod bad-rule --ignore-not-found --wait=false >/dev/null 2>&1 || true
	kubectl -n "$TEST_NS" delete configmap bad-rule --ignore-not-found >/dev/null 2>&1 || true
	# Back to the shipped rule set: drop the test keys and reload.
	kubectl -n "$NAMESPACE" patch configmap "${RELEASE}-rules" --type merge \
		-p '{"data":{"R900-reload-test.yaml":null,"R901-broken.yaml":null}}' >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- 1. live detections -----------------------------------------------------------

# A bind shell: nc hands the accepted socket to /bin/sh as stdin and stdout.
t0=$(now)
root_exec sh -c '(nc -l -p 4444 -e /bin/sh &) ; sleep 1; echo "exit 0" | nc 127.0.0.1 4444' >/dev/null 2>&1 || true
alert=$(wait_record "$t0" '.rule.id == "R001"' 10)
[ -n "$alert" ] || fail "no R001 alert for a shell with a socket as stdin and stdout"
check_record "$alert" "R001: wrong event" '.type == "exec" and .process.Image == "/bin/sh" and .process.stdin_is_socket and .process.stdout_is_socket'
check_record "$alert" "R001: wrong rule metadata" '.rule.level == "high" and (.rule.tags | index("attack.t1059.004"))'
check_record "$alert" "R001: wrong pod" ".k8s.namespace == \"${TEST_NS}\" and .k8s.pod == \"probe\" and .container.name == \"root\""
pass "R001 fired on a bind shell: $(jq -c '{rule: .rule.id, level: .rule.level, Image: .process.Image, parent: .parent.Image, pod: .k8s.pod}' <<<"$alert")"

t0=$(now)
root_exec cat /etc/shadow >/dev/null
alert=$(wait_record "$t0" '.rule.id == "R005" and .file.path == "/etc/shadow"' 10)
[ -n "$alert" ] || fail "no R005 alert for cat /etc/shadow"
check_record "$alert" "R005: wrong event" '.type == "file_open" and .process.Image == "/bin/cat" and .rule.level == "high"'
root_exec sh -c 'rm -f /tmp/innocent && ln /etc/shadow /tmp/innocent'
t0=$(now)
root_exec cat /tmp/innocent >/dev/null
alert=$(wait_record "$t0" '.rule.id == "R005" and .file.path == "/tmp/innocent"' 10)
root_exec rm -f /tmp/innocent
[ -n "$alert" ] || fail "no R005 alert for /etc/shadow read through a hard link"
pass "R005 fired on /etc/shadow, and on a hard link to it: $(jq -c '{rule: .rule.id, file: {path: .file.path, target: .file.target}}' <<<"$alert")"

# --- 2. an invalid rule stops start-up --------------------------------------------

image=$(kubectl -n "$NAMESPACE" get daemonset "${RELEASE}-agent" -o jsonpath='{.spec.template.spec.containers[0].image}')
policy=$(kubectl -n "$NAMESPACE" get daemonset "${RELEASE}-agent" -o jsonpath='{.spec.template.spec.containers[0].imagePullPolicy}')
bad=$(mktemp -d)
cat >"$bad/R999-broken.yaml" <<'RULE'
id: R999
title: Broken on purpose
level: high
event: exec
detection:
  selection:
    process.Image: /bin/sh
    process.Imagee|endswith: /sh
  condition: selection
RULE
kubectl -n "$TEST_NS" delete pod bad-rule --ignore-not-found >/dev/null
kubectl -n "$TEST_NS" create configmap bad-rule --from-file="$bad" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
rm -rf "$bad"
kubectl apply -f - >/dev/null <<POD
apiVersion: v1
kind: Pod
metadata:
  name: bad-rule
  namespace: ${TEST_NS}
spec:
  restartPolicy: Never
  nodeName: ${node}
  containers:
    - name: tephrad
      image: ${image}
      imagePullPolicy: ${policy}
      args: ["--rules-dir=/etc/tephra/rules", "--metrics-addr="]
      volumeMounts:
        - name: rules
          mountPath: /etc/tephra/rules
  volumes:
    - name: rules
      configMap:
        name: bad-rule
POD
phase=""
for _ in $(seq 1 60); do
	phase=$(kubectl -n "$TEST_NS" get pod bad-rule -o jsonpath='{.status.phase}')
	[ "$phase" = "Failed" ] || [ "$phase" = "Succeeded" ] && break
	sleep 1
done
[ "$phase" = "Failed" ] || fail "agent with an invalid rule ended in phase '${phase}', want Failed"
log=$(kubectl -n "$TEST_NS" logs bad-rule)
grep -q '/etc/tephra/rules/R999-broken.yaml:8: rule R999: unknown field' <<<"$log" ||
	fail "start-up error does not name file and line: ${log}"
if grep -q '"msg":"program attached"' <<<"$log"; then
	fail "the agent attached programs before rejecting the rule"
fi
pass "an invalid rule stops start-up: $(jq -r 'select(.level == "ERROR") | .error' <<<"$log")"

# --- 3. reload on SIGHUP ----------------------------------------------------------

restarts_before=$(kubectl -n "$NAMESPACE" get "$agent" -o jsonpath='{.status.containerStatuses[0].restartCount}')

t0=$(now)
probe_exec /bin/true tephra-reload-marker
sleep 2
n=$(events_since "$t0" | jq -c 'select(.rule.id == "R900")' | grep -c . || true)
[ "$n" -eq 0 ] || fail "R900 fired before it was added"

# Patched into the ConfigMap in place: nothing rolls the DaemonSet.
kubectl -n "$NAMESPACE" patch configmap "${RELEASE}-rules" --type merge -p "$(jq -n '{data: {"R900-reload-test.yaml": "id: R900\ntitle: Reload test\nlevel: info\ntags: [attack.execution, attack.t1059]\nevent: exec\ndetection:\n  selection:\n    process.CommandLine|contains: tephra-reload-marker\n  condition: selection\n"}}')" >/dev/null
# The kubelet refreshes ConfigMap volumes on its own schedule; touching the
# pod makes it look now.
kubectl -n "$NAMESPACE" annotate "$agent" --overwrite "tephra.dev/sync=$(date +%s)" >/dev/null
loaded=""
for _ in $(seq 1 60); do
	hup
	sleep 3
	loaded=$(scrape "$agent" | metric tephra_rules_loaded)
	[ "$loaded" -eq $((shipped + 1)) ] && break
done
[ "$loaded" -eq $((shipped + 1)) ] || fail "after SIGHUP the agent has ${loaded} rules, want $((shipped + 1))"

t0=$(now)
probe_exec /bin/true tephra-reload-marker
alert=$(wait_record "$t0" '.rule.id == "R900"' 10)
[ -n "$alert" ] || fail "the rule added by reload did not fire"
[ "$(agent_on "$node")" = "$agent" ] || fail "the agent pod on ${node} was replaced"
restarts_after=$(kubectl -n "$NAMESPACE" get "$agent" -o jsonpath='{.status.containerStatuses[0].restartCount}')
[ "$restarts_after" -eq "$restarts_before" ] || fail "the agent restarted (${restarts_before} -> ${restarts_after})"
pass "a rule added to the ConfigMap fires after SIGHUP, same pod, ${restarts_after} restarts: $(jq -c '{rule: .rule.id, CommandLine: .process.CommandLine}' <<<"$alert")"

# An invalid rule must not replace the running set.
errors_before=$(scrape "$agent" | metric tephra_agent_reload_errors_total)
kubectl -n "$NAMESPACE" patch configmap "${RELEASE}-rules" --type merge \
	-p '{"data":{"R901-broken.yaml":"id: R901\ntitle: Broken\nlevel: high\nevent: exec\ndetection:\n  selection:\n    nope: 1\n  condition: selection\n"}}' >/dev/null
kubectl -n "$NAMESPACE" annotate "$agent" --overwrite "tephra.dev/sync=$(date +%s)" >/dev/null
errors_after="$errors_before"
for _ in $(seq 1 60); do
	hup
	sleep 3
	errors_after=$(scrape "$agent" | metric tephra_agent_reload_errors_total)
	[ "$errors_after" -gt "$errors_before" ] && break
done
[ "$errors_after" -gt "$errors_before" ] || fail "reloading an invalid rule was not refused"
[ "$(scrape "$agent" | metric tephra_rules_loaded)" -eq $((shipped + 1)) ] || fail "the rule set changed after a refused reload"
t0=$(now)
probe_exec /bin/true tephra-reload-marker
alert=$(wait_record "$t0" '.rule.id == "R900"' 10)
[ -n "$alert" ] || fail "the running rules stopped working after a refused reload"
pass "an invalid rule is refused on reload and the running rules stay in force: $(kubectl -n "$NAMESPACE" logs "$agent" | jq -r 'select((.msg // "") | startswith("reload failed")) | .error' | tail -n1)"

# Restore the shipped set and confirm it.
cleanup
kubectl -n "$NAMESPACE" annotate "$agent" --overwrite "tephra.dev/sync=$(date +%s)" >/dev/null
for _ in $(seq 1 60); do
	hup
	sleep 3
	loaded=$(scrape "$agent" | metric tephra_rules_loaded)
	[ "$loaded" -eq "$shipped" ] && break
done
[ "$loaded" -eq "$shipped" ] || fail "could not restore the shipped rules (${loaded} loaded)"

echo "PASS: M4"
