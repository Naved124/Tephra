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
| M1 Process events | Not started |

What M0 gives you: the agent loads one eBPF program on the
`sched_process_exec` tracepoint, counts execs in a per-CPU map and logs the
counter every 10 seconds. It emits no events and evaluates no rules yet.

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
make dev        # kind cluster, image build, helm install, acceptance check
```

`make dev` ends with one line per node and a verdict:

```
pod/tephra-agent-xxxxx: {"level":"INFO","msg":"program attached","program":"tephra_exec","hook":"tp_btf/sched_process_exec"}
PASS: program attached on 3/3 nodes
```

The VM runs in the unprivileged libvirt session and is reachable only through
`127.0.0.1:2222`. `make vm-down` stops it and `make vm-destroy` deletes it with
its disk.

## Other targets

```sh
make build      # compile the BPF programs and build bin/tephrad
make test       # unit tests, unprivileged
make test-root  # load the programs into the running kernel (use the VM)
make lint       # go vet, golangci-lint, clang-format, shellcheck
make vmlinux    # regenerate bpf/vmlinux.h from the running kernel
make help
```

## Layout

```
bpf/                 eBPF programs (C, CO-RE)
cmd/tephrad/         agent entrypoint
internal/loader/     bpf2go bindings, attach, kernel feature probes
deploy/docker/       image build
deploy/helm/tephra/  Helm chart
deploy/kind/         lab cluster definition
deploy/vm/           dev VM definition
hack/                acceptance-test scripts
docs/                design
```

## Licence

The eBPF programs under `bpf/` are GPL-2.0. Everything else is Apache-2.0. Each
source file carries an SPDX identifier, and the licence texts are in
[LICENSES/](LICENSES/).
