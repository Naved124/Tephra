// SPDX-License-Identifier: Apache-2.0

// Package credwatch watches Kubernetes credentials by what they are, not by
// where they are found. A pod may project its service account token at any
// path and under any name; the same file is also reachable through
// /proc/<pid>/root and from the node's side of the volume, under
// /var/lib/kubelet. The pod spec says which file is the token. The agent
// resolves it inside the container and watches it in the kernel by identity.
//
// A projected volume is a tmpfs of its own, and the kubelet replaces its
// files at every rotation, so a watch on one inode would go blind at the
// next rotation. A tmpfs volume is watched as a whole device instead, and
// each open on it is matched against the token's name from the spec. A
// volume that is not a tmpfs of its own is watched by the token file's inode,
// re-resolved by the caller.
package credwatch

import (
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/k8s"
)

// Sink is where watches are written; the loaded sensor implements it.
type Sink interface {
	PutInode(dev uint32, inode uint64, bits uint32) error
	DeleteInode(dev uint32, inode uint64) error
}

// KindSAToken is the kind of a service account token.
const KindSAToken = "sa_token"

// Credential is what a watched file is.
type Credential struct {
	Kind string
	// Namespace and Pod own the credential.
	Namespace, Pod string
}

type fileID struct {
	dev   uint32 // kernel encoding
	inode uint64 // 0: the whole device
}

type entry struct {
	cred Credential
	// rels are token paths inside the volume; paths are where containers
	// see them. An open on a watched device is the token if its path is
	// one of these.
	rels, paths map[string]bool
}

// Watcher is safe for concurrent use.
type Watcher struct {
	procRoot string
	sink     Sink
	// ownFS reports whether a file is on a tmpfs of its own, not on the
	// container's root filesystem; a variable for tests.
	ownFS func(fd int, file, root *unix.Stat_t) bool
	// bits are the watch bits written for each entry.
	bits uint32

	mu      sync.Mutex
	entries map[fileID]*entry
	// resolved maps a container and token path to what it resolved to.
	resolved map[string]fileID
	errs     uint64
}

// New returns a watcher with no watches. bits are the kernel watch bits for
// a read.
func New(procRoot string, sink Sink, bits uint32) *Watcher {
	return &Watcher{
		procRoot: procRoot,
		sink:     sink,
		ownFS:    ownTmpfs,
		bits:     bits,
		entries:  map[fileID]*entry{},
		resolved: map[string]fileID{},
	}
}

func ownTmpfs(fd int, file, root *unix.Stat_t) bool {
	var st unix.Statfs_t
	return file.Dev != root.Dev && unix.Fstatfs(fd, &st) == nil && st.Type == unix.TMPFS_MAGIC
}

// Resolve resolves a container's token mounts in the root filesystem of pid,
// a process of that container, and watches what it finds. It is cheap to
// call again: a device already watched is not resolved twice, and a file
// watched by inode is re-resolved, so a rotated token is picked up.
func (w *Watcher) Resolve(pid uint32, tokens []k8s.TokenMount) {
	if len(tokens) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	pending := tokens[:0:0]
	for _, t := range tokens {
		if id, ok := w.resolved[t.ContainerID+"\x00"+t.Path]; ok && id.inode == 0 {
			continue
		}
		pending = append(pending, t)
	}
	if len(pending) == 0 {
		return
	}
	// Opened once, every path resolved beneath it: a symlink inside the
	// container cannot lead out into the agent's own filesystem.
	rootFD, err := unix.Open(filepath.Join(w.procRoot, strconv.FormatUint(uint64(pid), 10), "root"),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(rootFD) }()
	var root unix.Stat_t
	if unix.Fstat(rootFD, &root) != nil {
		return
	}
	for _, t := range pending {
		fd, err := unix.Openat2(rootFD, strings.TrimPrefix(t.Path, "/"), &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT,
		})
		if err != nil {
			continue
		}
		var st unix.Stat_t
		ok := unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
		whole := ok && w.ownFS(fd, &st, &root)
		_ = unix.Close(fd)
		if !ok {
			continue
		}
		id := fileID{dev: unix.Major(st.Dev)<<20 | unix.Minor(st.Dev), inode: st.Ino}
		if whole {
			id.inode = 0
		}
		w.add(id, t)
	}
}

// add records a resolved token. Called with the lock held.
func (w *Watcher) add(id fileID, t k8s.TokenMount) {
	key := t.ContainerID + "\x00" + t.Path
	if old, ok := w.resolved[key]; ok && old != id {
		delete(w.resolved, key)
		w.release(old)
	}
	w.resolved[key] = id
	e := w.entries[id]
	if e == nil {
		if err := w.sink.PutInode(id.dev, id.inode, w.bits); err != nil {
			w.errs++
			delete(w.resolved, key)
			return
		}
		e = &entry{
			cred:  Credential{Kind: KindSAToken, Namespace: t.Namespace, Pod: t.Pod},
			rels:  map[string]bool{},
			paths: map[string]bool{},
		}
		w.entries[id] = e
	}
	e.rels[t.Rel] = true
	e.paths[path.Clean(t.Path)] = true
}

// release drops an entry no container resolves to any more. Called with the
// lock held.
func (w *Watcher) release(id fileID) {
	if _, ok := w.entries[id]; !ok {
		return
	}
	for _, other := range w.resolved {
		if other == id {
			return
		}
	}
	delete(w.entries, id)
	if err := w.sink.DeleteInode(id.dev, id.inode); err != nil {
		w.errs++
	}
}

// Lookup says whether an open of a file is a watched credential. dev is in
// the kernel's encoding, and p is the path the opener used.
func (w *Watcher) Lookup(dev uint32, inode uint64, p string) (Credential, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e, ok := w.entries[fileID{dev, inode}]; ok {
		return e.cred, true
	}
	e, ok := w.entries[fileID{dev: dev}]
	if !ok {
		return Credential{}, false
	}
	// The kubelet writes a volume's files into a hidden directory named
	// ..<time> and links them from the top; that directory is not part of
	// the token's name.
	clean := path.Clean(p)
	var kept []string
	for _, c := range strings.Split(clean, "/") {
		if !strings.HasPrefix(c, "..") {
			kept = append(kept, c)
		}
	}
	name := strings.Join(kept, "/")
	if e.paths[clean] || e.paths[name] {
		return e.cred, true
	}
	for rel := range e.rels {
		if name == rel || strings.HasSuffix(name, "/"+rel) {
			return e.cred, true
		}
	}
	return Credential{}, false
}

// GC drops the watches of containers for which alive is false.
func (w *Watcher) GC(alive func(container string) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for key, id := range w.resolved {
		container, _, _ := strings.Cut(key, "\x00")
		if alive(container) {
			continue
		}
		delete(w.resolved, key)
		w.release(id)
	}
}

// Stats reports the number of watched credential files and devices, and of
// failed map writes.
func (w *Watcher) Stats() (watches int, errs uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries), w.errs
}
