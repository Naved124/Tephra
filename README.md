# Tephra

A runtime threat-detection sensor for Kubernetes nodes. eBPF programs observe
process, file, network and privilege activity in the kernel; a Go agent
(`tephrad`) attributes each event to a pod and evaluates detection rules; alerts
land in Grafana. A scripted attack harness shows what it detects and what it
misses.

The full design is in [docs/design.md](docs/design.md).

> **Lab use only.** The attack scenarios in this repository are meant for the
> dev VM or a throwaway cluster that you own. Do not run them anywhere else.

## Status

Milestones follow section 10 of the design.

| Milestone | State |
|---|---|
| M0 Skeleton and dev environment | Done |
| M1 Process events | Done |
| M2 Process tree and pod attribution | Done |
| M3 Network and file events | Done |
| M4 Rule engine | Done |
| M5 Backend | Done |
| M6 Packaging | Done |
| M7 Harness and first coverage report | Done |
| M8 Remaining hooks | Done |
| M9 Evasion work | Not started |

What works today: the agent watches process starts and exits, connections
(IPv4, IPv6 and Unix sockets), opens of watched files, ptrace attach,
credential changes, mounts, namespace switches, kernel module loads, BPF
program loads and memfd creation on its node. It attributes each event to a
pod, evaluates the 21 detection rules in [rules/](rules/), and writes events
and alerts as JSON lines on stdout. A collector forwards both to Loki, and a
Grafana dashboard shows the alerts and the sensor's own health.

The agent does not run privileged. It holds four capabilities (BPF, PERFMON,
SYS_PTRACE, SYS_RESOURCE), drops the rest, and has a read-only root
filesystem.

[docs/coverage.md](docs/coverage.md) is the evidence: 17 attack techniques
run for real in the lab cluster, each with the rule that caught it, and a
30-minute run of ordinary workloads listing every alert that fired.

Not built yet: the evasion scenarios and their write-ups, benchmarks against
Falco and Tetragon, the EKS demo, blocking (the sensor only detects), and
rules that correlate several events.

An alert, as `kubectl logs` shows it: the event that matched, with the rule
in front. This one is a bind shell started with `nc -l -p 4445 -e /bin/sh` in
a test pod; the shell's parent is the container's first process because the
process that started it had already exited.

```json
{
  "ts": "2026-11-11T19:49:26.482869Z", "type": "exec", "node": "tephra-worker",
  "rule": {"id": "R001", "title": "Shell with a network socket as stdin and stdout", "level": "high", "tags": ["attack.execution", "attack.t1059.004"]},
  "process": {
    "pid": 15643, "start_time_ns": 1930144414492,
    "Image": "/bin/sh", "CommandLine": "/bin/sh", "User": "root", "uid": 0, "gid": 0, "cgroup_id": 51745,
    "stdin_is_socket": true, "stdout_is_socket": true, "unlinked": false, "setuid": false, "argv_truncated": false,
    "inode": 812090, "dev": 355, "cap_effective": 2818844155, "env_truncated": false
  },
  "parent": {"pid": 1147, "Image": "/bin/httpd", "CommandLine": "/bin/httpd -f -p 8080 -h /tmp"},
  "ancestors": ["/bin/httpd", "/usr/local/bin/containerd-shim-runc-v2", "/usr/lib/systemd/systemd"],
  "container": {"id": "6a47c327a3cec33a154dc6f851804207ac257115f9bee65412cf1be9e0496f12", "name": "root", "image": "docker.io/library/busybox:1.37"},
  "k8s": {"namespace": "tephra-test", "pod": "probe", "labels": {"app": "probe"}}
}
```

Connection events add a `network` object (direction, family, protocol,
`SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, or `unix_path`);
file events add a `file` object (path, flags, `write`, `truncate`, and
`target` when a file was recognised through a hard link). A process outside
every pod has `"k8s": {"namespace": "host"}` and no `container`. The agent's
own log goes to stderr; its lines have `level` and `msg` instead of `type`.

Counters per hook (seen, filtered, emitted, dropped), per rule, and for the
export queue are on `/metrics`, port 9090 of each agent pod.

## Rules

A rule is a YAML file: one event type, named blocks of field tests, and a
condition that combines the blocks. [rules/](rules/) holds R001 to R021;
section 6 of the design describes the schema.

```sh
bin/tephrad rules validate rules/                 # check every rule, errors carry file and line
bin/tephrad rules test rules/ events.jsonl        # run rules over recorded events, print the alerts
```

`events.jsonl` can be `kubectl logs` output of an agent. Each rule has
recorded events it must and must not fire on in `rules/testdata/`; `make test`
checks them.

File rules decide what the kernel reports. Only opens of files that some rule
names by exact path, by path prefix or by file name leave the kernel, and a
file rule that cannot be turned into such a filter is refused when it is
loaded.

The agent re-reads its configuration and rules on SIGHUP. If either is
invalid it keeps running on what it had and logs why.

## Attack harness

> **Lab use only.** The harness runs real attack techniques: it opens a
> reverse shell, mounts the node's disk, loads a kernel module. It refuses to
> start unless every node of the cluster is labelled `tephra.dev/lab=true`,
> which the kind cluster of this repository is. There is no flag to override
> that.

```sh
bin/harness list                     # the scenarios and the rules each must trigger
bin/harness run A01 A04              # run two scenarios
make coverage                        # run all of them, rewrite docs/coverage.md
make false-positives                 # 30 minutes of ordinary workloads, list every alert
```

Each scenario is a directory under [attacks/](attacks/): the victim workload
(`target.yaml`), the technique (`run.sh`, executed inside the target pod),
and what must fire (`scenario.yaml`). A run creates a fresh namespace,
applies the workload, runs the technique, asks Loki through Grafana for the
alerts of that namespace, and deletes the namespace. The verdict per rule is
detected, partial (the alert fired but names the wrong pod or no container)
or missed.

`make coverage` also saves the event behind every detection to
`rules/testdata/<rule>.live.jsonl`, and the rule tests check that each rule
still fires on it.

## Backend

The chart installs a collector, a single-binary Loki and Grafana next to the
agents. Open the dashboard with:

```sh
kubectl -n tephra port-forward svc/tephra-grafana 3000:3000
kubectl -n tephra get secret tephra-grafana -o jsonpath='{.data.admin-password}' | base64 -d
```

The user is `admin`; the password is generated at install time. The bundled
Loki keeps its data in an `emptyDir` unless `loki.persistence.enabled` is set,
and is meant for a lab or a demo. To use your own Loki, set
`loki.enabled=false` and `collector.lokiUrl`.

An agent keeps a record until the collector confirms that Loki stored it, so
a collector restart loses nothing that was queued. The queue is bounded
(8,192 records by default); when it overflows, raw events are dropped before
alerts and every drop is counted in `tephra_export_dropped_total`.

## Requirements

The sensor needs an x86-64 kernel, 5.15 or newer, with BTF
(`/sys/kernel/btf/vmlinux`) and cgroup v2.

Building on the host needs Go 1.27, clang, llvm and the libbpf headers.

The dev VM needs QEMU/KVM and libvirt. On Arch:

```sh
sudo pacman -S --needed libvirt virt-install qemu-img passt libisoburn bpf
```

Docker, kind, kubectl and helm are installed inside the VM, not on the host.

## Quick start

```sh
make vm-up      # create and provision the VM (first run downloads an Ubuntu cloud image)
make vm-sync    # copy the working tree into the VM
make vm-ssh     # shell in the VM, in ~/tephra

# inside the VM
make dev        # kind cluster, image build, helm install, acceptance tests
```

`make dev` ends by running the acceptance test of every finished milestone
(`hack/accept-m*.sh`), each printing what it checked and a verdict:

```
PASS: program attached on 3/3 nodes
ok: one exec event within 1s: {"node":"tephra-worker","Image":"/bin/ls","CommandLine":"ls -la /tmp","uid":1000}
ok: after 10,000 execs (+10068 seen on tephra-worker), emitted + dropped + filtered == seen on every agent
PASS: M1
ok: pod event attributed: ...
ok: host process labelled host, reported once: ...
ok: after agent restart, a child of a pre-existing process resolves: ...
PASS: M2
...
PASS: M3
...
PASS: M4
...
PASS: M5
...
PASS: M6
```

`make accept` reruns only the tests against the cluster that is already up.

The VM runs in the unprivileged libvirt session and is reachable only through
`127.0.0.1:2222`. `make vm-down` stops it and `make vm-destroy` deletes it with
its disk.

To test on the 5.15 kernel floor, create a second VM from Ubuntu 22.04 with
the same script and run `make dev` inside it:

```sh
VM_NAME=tephra-floor SSH_PORT=2223 UBUNTU_RELEASE=jammy UBUNTU_VERSION=22.04 deploy/vm/vm.sh up
```

Pass the same variables to `vm.sh sync`, `ssh` and `destroy`.

The VM takes its DNS servers from the laptop when it starts. If the laptop
moves to another network while the VM is running, image pulls inside it fail;
`make vm-down && make vm-up` fixes that.

## Other targets

```sh
make build      # compile the BPF programs, build bin/tephrad, bin/collector and bin/harness
make test       # unit tests, unprivileged
make rules-validate  # check the shipped rules
make proto      # regenerate the Go code of the agent-to-collector API
make test-root  # load the programs into the running kernel and check real events (use the VM)
make lint       # go vet, golangci-lint, clang-format, shellcheck
make vmlinux    # regenerate bpf/vmlinux.h from the running kernel
make help
```

## Layout

```
api/                 protobuf definition of the agent-to-collector API
bpf/                 eBPF programs (C, CO-RE)
cmd/tephrad/         agent entrypoint, rules subcommands
cmd/collector/       gRPC -> Loki
cmd/harness/         attack runner and coverage report
attacks/             one directory per attack scenario
internal/loader/     bpf2go bindings, attach, kernel feature probes
internal/events/     Go mirrors of the kernel structs, decoder
internal/proctree/   process cache and /proc seeding
internal/k8s/        cgroup ID -> container -> pod
internal/enrich/     ancestry, user and pod attribution per event
internal/filter/     what the kernel is told to report
internal/inodewatch/ watched files by device and inode, per root filesystem
internal/rules/      rule parser, compiler and matcher
internal/config/     configuration file
internal/export/     wire format, JSON lines on stdout, gRPC client
internal/collector/  stream handling, batching, Loki push
internal/harness/    scenario runner, verdicts, report
rules/               shipped detection rules and their recorded events
deploy/docker/       image builds
deploy/helm/tephra/  Helm chart
deploy/kind/         lab cluster definition
deploy/vm/           dev VM definition
hack/                acceptance tests, one script per milestone
docs/                design, coverage report
```

## Licence

The eBPF programs under `bpf/` are GPL-2.0. Everything else is Apache-2.0. Each
source file carries an SPDX identifier, and the licence texts are in
[LICENSES/](LICENSES/).
