// SPDX-License-Identifier: Apache-2.0

// Package filter describes what the kernel programs are told to report: the
// files to watch and the network destinations to skip. The rule compiler and
// the configuration produce these values; the loader writes them into BPF
// maps.
package filter

import "net/netip"

// Watch bits, WATCH_* in bpf/common.h.
const (
	Read  uint32 = 1 << 0
	Write uint32 = 1 << 1
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
