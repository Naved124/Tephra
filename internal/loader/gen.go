// SPDX-License-Identifier: Apache-2.0

package loader

// -fms-extensions: vmlinux.h from recent kernels embeds tagged structs
// anonymously, which plain C rejects.
//
// The generated Go bindings and the compiled BPF object are build artefacts:
// run `make generate` (or `go generate ./...`) before building.

//go:generate go tool bpf2go -cc clang -strip llvm-strip -target amd64 -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag" tephra ../../bpf/tephra.bpf.c -- -I../../bpf
