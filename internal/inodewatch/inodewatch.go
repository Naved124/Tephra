// SPDX-License-Identifier: Apache-2.0

// Package inodewatch keeps the kernel's identity watches in step with the
// filesystems on the node. A file watched by exact path is also watched by
// device and inode, so that a hard link or an unexpected path to it is still
// reported. The same path is a different file in every container, so each
// root filesystem is resolved once, through /proc/<pid>/root.
package inodewatch

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Sink is where watches are written; the loaded sensor implements it.
type Sink interface {
	PutInode(dev uint32, inode uint64, bits uint32) error
	DeleteInode(dev uint32, inode uint64) error
}

// HostOwner is the owner name of the node's own root filesystem.
const HostOwner = ""

type fileID struct {
	dev   uint32 // kernel encoding
	inode uint64
}

// Tracker is safe for concurrent use.
type Tracker struct {
	procRoot string
	sink     Sink

	mu     sync.Mutex
	exacts map[string]uint32
	// roots are the root directories already resolved.
	roots map[fileID]string
	// owned lists what each owner (a container ID, or HostOwner) put in.
	owned map[string][]fileID
	refs  map[fileID]int
	// paths is the watched path each identity was resolved from.
	paths map[fileID]string
	errs  uint64
}

// New returns a tracker with no watches.
func New(procRoot string, sink Sink) *Tracker {
	return &Tracker{
		procRoot: procRoot,
		sink:     sink,
		exacts:   map[string]uint32{},
		roots:    map[fileID]string{},
		owned:    map[string][]fileID{},
		refs:     map[fileID]int{},
		paths:    map[fileID]string{},
	}
}

// SetWatches replaces the watched paths (path to watch bits) and forgets
// every root, so the caller must Observe the node's processes again.
func (t *Tracker) SetWatches(exacts map[string]uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id := range t.refs {
		t.delete(id)
	}
	t.exacts = exacts
	t.roots = map[fileID]string{}
	t.owned = map[string][]fileID{}
	t.refs = map[fileID]int{}
	t.paths = map[fileID]string{}
}

func (t *Tracker) delete(id fileID) {
	if err := t.sink.DeleteInode(id.dev, id.inode); err != nil {
		t.errs++
	}
}

// Observe resolves the watched paths in the root filesystem of a process,
// unless that root has been done. owner names who the entries belong to.
func (t *Tracker) Observe(pid uint32, owner string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.exacts) == 0 {
		return
	}

	// The root is opened once and every path is resolved beneath it, so a
	// symlink inside the container cannot lead out into the agent's own
	// filesystem.
	rootFD, err := unix.Open(filepath.Join(t.procRoot, strconv.FormatUint(uint64(pid), 10), "root"),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return // the process is gone
	}
	defer func() { _ = unix.Close(rootFD) }()
	root, ok := identify(rootFD)
	if !ok {
		return
	}
	if _, done := t.roots[root]; done {
		return
	}
	t.roots[root] = owner

	for path, bits := range t.exacts {
		fd, err := unix.Openat2(rootFD, strings.TrimPrefix(path, "/"), &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT,
		})
		if err != nil {
			continue // not present in this root
		}
		id, ok := identify(fd)
		_ = unix.Close(fd)
		if !ok {
			continue
		}
		if err := t.sink.PutInode(id.dev, id.inode, bits); err != nil {
			t.errs++
			continue
		}
		t.refs[id]++
		t.paths[id] = path
		t.owned[owner] = append(t.owned[owner], id)
	}
}

func identify(fd int) (fileID, bool) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileID{}, false
	}
	// stat reports the device in the user-space encoding; the kernel
	// programs compare super_block.s_dev, which is major << 20 | minor.
	return fileID{dev: unix.Major(st.Dev)<<20 | unix.Minor(st.Dev), inode: st.Ino}, true
}

// GC drops the entries of every owner for which alive is false. The host's
// entries are never dropped.
func (t *Tracker) GC(alive func(owner string) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for owner, ids := range t.owned {
		if owner == HostOwner || alive(owner) {
			continue
		}
		for _, id := range ids {
			if t.refs[id]--; t.refs[id] <= 0 {
				delete(t.refs, id)
				delete(t.paths, id)
				t.delete(id)
			}
		}
		delete(t.owned, owner)
		for root, o := range t.roots {
			if o == owner {
				delete(t.roots, root)
			}
		}
	}
}

// WatchedPath returns the watched path a file identity was resolved from. dev
// is in the kernel's encoding.
func (t *Tracker) WatchedPath(dev uint32, inode uint64) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.paths[fileID{dev, inode}]
	return p, ok
}

// Stats reports the number of identity watches, of root filesystems
// resolved, and of failed map writes.
func (t *Tracker) Stats() (inodes, roots int, errs uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.refs), len(t.roots), t.errs
}
