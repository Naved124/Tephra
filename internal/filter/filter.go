// SPDX-License-Identifier: Apache-2.0

// Package filter describes what the kernel programs are told to report: the
// files to watch and the network destinations to skip. The rule compiler and
// the configuration produce these values; the loader writes them into BPF
// maps.
package filter

import (
	"net/netip"
	"path"
	"strings"
)

// Watch bits, WATCH_* in bpf/common.h.
const (
	Read  uint32 = 1 << 0
	Write uint32 = 1 << 1
	// Denied reports refused opens of the file and nothing else.
	Denied uint32 = 1 << 2
	// Block refuses opens for writing where enforcement applies. It
	// reports nothing by itself.
	Block uint32 = 1 << 3
)

// What enforcement can refuse, enum enforce_action in bpf/common.h.
const (
	// ActionExecUnlinked is the exec of a file with no name on disk: a
	// memory file, or a binary deleted after it was opened.
	ActionExecUnlinked uint32 = 1
	// ActionFileWrite is an open for writing of a file watched with
	// Block.
	ActionFileWrite uint32 = 2
	// ActionPtrace is attach-level access to another process.
	ActionPtrace uint32 = 3
	// ActionModule is loading a kernel module.
	ActionModule uint32 = 4
	// ActionMount is a mount.
	ActionMount uint32 = 5
)

// Kind is how a watch selects files.
type Kind int

const (
	// Exact is one file by full path. It is also watched by identity, so a
	// hard link to it is reported.
	Exact Kind = iota
	// Prefix is every path that starts with the value.
	Prefix
	// Name is every file whose last path component equals the value,
	// wherever it is.
	Name
)

func (k Kind) String() string {
	switch k {
	case Exact:
		return "exact"
	case Prefix:
		return "prefix"
	case Name:
		return "name"
	}
	return "unknown"
}

// Limits of the kernel maps, WATCH_PATH_LEN and WATCH_NAME_LEN.
const (
	MaxPathLen = 128
	MaxNameLen = 31
)

// Watch is one file watch.
type Watch struct {
	Kind Kind
	// Path is a full path, a path prefix or a file name, by Kind.
	Path string
	// Bits says which opens are reported: Read, Write or both.
	Bits uint32
}

// Set is everything the kernel filters on.
type Set struct {
	Watches   []Watch
	NetIgnore []netip.Prefix
}

// Exacts returns the watches of kind Exact, merged by path.
func (s Set) Exacts() map[string]uint32 {
	out := map[string]uint32{}
	for _, w := range s.Watches {
		if w.Kind == Exact {
			out[w.Path] |= w.Bits
		}
	}
	return out
}

// Match returns the bits of every watch that covers a path, the way the
// kernel maps would. The agent uses it for events the kernel sends
// unfiltered.
func (s Set) Match(p string) uint32 {
	var bits uint32
	for _, w := range s.Watches {
		switch w.Kind {
		case Exact:
			if p == w.Path {
				bits |= w.Bits
			}
		case Prefix:
			if strings.HasPrefix(p, w.Path) {
				bits |= w.Bits
			}
		case Name:
			if path.Base(p) == w.Path {
				bits |= w.Bits
			}
		}
	}
	return bits
}
