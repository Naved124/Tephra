// SPDX-License-Identifier: Apache-2.0

// Package runtimeid recognises the node's container runtime binaries by the
// identity of their files. A rule that has to let the runtime through cannot
// go by a path or a command line: a process in a container chooses both. It
// cannot choose the device and inode of the binary it runs, and the node's
// own binaries are not reachable from inside a container.
package runtimeid

import (
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// maxIDs bounds the set; identities are only ever added, so that a process
// still running a binary that was since upgraded keeps being recognised.
const maxIDs = 1024

type fileID struct {
	dev   uint32 // kernel encoding
	inode uint64
}

// Set is safe for concurrent use.
type Set struct {
	procRoot string
	paths    []string

	mu  sync.RWMutex
	ids map[fileID]string
}

// New returns an empty set for the binaries at the given absolute paths of
// the node's root filesystem.
func New(procRoot string, paths []string) *Set {
	return &Set{procRoot: procRoot, paths: paths, ids: map[fileID]string{}}
}

// SetPaths replaces the paths looked at by the next Refresh.
func (s *Set) SetPaths(paths []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = paths
}

// Refresh resolves every path in the root filesystem of the node's first
// process and returns the number of identities known.
func (s *Set) Refresh() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	rootFD, err := unix.Open(filepath.Join(s.procRoot, "1", "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return len(s.ids)
	}
	defer func() { _ = unix.Close(rootFD) }()

	for _, p := range s.paths {
		// Resolved beneath the node's root, so a symlink there (/lib to
		// usr/lib) is followed in the node's filesystem and not the
		// agent's.
		fd, err := unix.Openat2(rootFD, strings.TrimPrefix(p, "/"), &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT,
		})
		if err != nil {
			continue
		}
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		_ = unix.Close(fd)
		if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		id := fileID{dev: unix.Major(st.Dev)<<20 | unix.Minor(st.Dev), inode: st.Ino}
		if _, ok := s.ids[id]; !ok && len(s.ids) < maxIDs {
			s.ids[id] = p
		}
	}
	return len(s.ids)
}

// Has reports whether a file is one of the runtime binaries. dev is in the
// kernel's encoding, as events carry it.
func (s *Set) Has(dev uint32, inode uint64) bool {
	if inode == 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.ids[fileID{dev: dev, inode: inode}]
	return ok
}
