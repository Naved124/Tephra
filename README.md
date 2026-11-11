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
| M3 Network and file events | Not started |

What works today: the agent captures every exec, fork and exit on its node,
keeps a process tree, and writes each event as one JSON line on stdout with
its parent, ancestor chain, container and pod. There are no network or file
events and no detection rules yet.

An exec event, as `kubectl logs` shows it:

```json
{
  "ts": "2026-11-11T08:32:33.501046Z", "type": "exec", "node": "tephra-worker2",
  "process": {
    "pid": 11337, "start_time_ns": 100207744246,
    "Image": "/bin/ls", "CommandLine": "ls -la /var", "uid": 1000, "gid": 1000, "cgroup_id": 22269,
    "stdin_is_socket": false, "stdout_is_socket": false, "unlinked": false, "setuid": false, "argv_truncated": false,
    "inode": 810234, "dev": 321, "cap_effective": 0
  },
  "parent": {"pid": 11324, "Image": "/usr/local/sbin/runc", "CommandLine": "runc --root /run/containerd/runc/k8s.io --log /run/containerd/io.containerd.runtime.v2.task/k8s.io/f603c429b8b70c31a9599e038437c0041dd4cf99bad3e9313b0653c8fcd984fb/log.json --log-format json --systemd-cgroup exec --process /tmp/runc-process3135238854 --detach --pid-file /run/containerd/io.containerd.runtime.v2.task/k8s.io/f603c429b8b70c31a9599e038437c0041dd4cf99bad3e9313b0653c8fcd984fb/89a2ba462eefd7bbb5b44884761f0842b7fdcc5d8f1c9129b406dcfd2fac65f7.pid f603c429b8b70c31a9599e038437c0041dd4cf99bad3e9313b0653c8fcd984fb"},
  "ancestors": ["/usr/local/sbin/runc", "/usr/local/bin/containerd-shim-runc-v2", "/usr/lib/systemd/systemd"],
  "container": {"id": "f603c429b8b70c31a9599e038437c0041dd4cf99bad3e9313b0653c8fcd984fb", "name": "probe", "image": "docker.io/library/busybox:1.37"},
  "k8s": {"namespace": "tephra-test", "pod": "probe", "labels": {"app": "probe"}}
}
```

A process outside every pod has `"k8s": {"namespace": "host"}` and no
`container`. The agent's own log goes to stderr; its lines have `level` and
`msg` instead of `type`.

Per-hook counters (seen, filtered, emitted, dropped) are on `/metrics`, port
9090 of each agent pod.

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
make build      # compile the BPF programs and build bin/tephrad
make test       # unit tests, unprivileged
make test-root  # load the programs into the running kernel and check real events (use the VM)
make lint       # go vet, golangci-lint, clang-format, shellcheck
make vmlinux    # regenerate bpf/vmlinux.h from the running kernel
make help
```

## Layout

```
bpf/                 eBPF programs (C, CO-RE)
cmd/tephrad/         agent entrypoint
internal/loader/     bpf2go bindings, attach, kernel feature probes
internal/events/     Go mirrors of the kernel structs, decoder
internal/proctree/   process cache and /proc seeding
internal/k8s/        cgroup ID -> container -> pod
internal/enrich/     ancestry, user and pod attribution per event
internal/export/     wire format, JSON lines on stdout
deploy/docker/       image build
deploy/helm/tephra/  Helm chart
deploy/kind/         lab cluster definition
deploy/vm/           dev VM definition
hack/                acceptance tests, one script per milestone
docs/                design
```

## Licence

The eBPF programs under `bpf/` are GPL-2.0. Everything else is Apache-2.0. Each
source file carries an SPDX identifier, and the licence texts are in
[LICENSES/](LICENSES/).
