// SPDX-License-Identifier: Apache-2.0

// Package k8s joins what the kernel knows (cgroups) with what Kubernetes
// knows (pods): cgroup ID to cgroup path, path to container ID, container ID
// to pod.
package k8s

import (
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Attribution is what an event learns about its container and pod.
type Attribution struct {
	ContainerID   string
	ContainerName string
	Image         string
	Namespace     string
	Pod           string
	Labels        map[string]string
}

// Complete reports whether the container itself was resolved, not just its
// pod.
func (a *Attribution) Complete() bool {
	return a != nil && a.ContainerName != ""
}

var (
	// containerd names a container's cgroup "cri-containerd-<id>.scope"
	// with the systemd driver and "<id>" with the cgroupfs driver.
	containerRe = regexp.MustCompile(`^(?:cri-containerd-)?([0-9a-f]{64})(?:\.scope)?$`)
	// The pod level is "...-pod<uid>.slice" (systemd, '-' in the UID
	// written as '_') or "pod<uid>" (cgroupfs).
	podRe = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})(?:\.slice)?$`)
)

// ContainerID extracts the container ID from a cgroup path, or returns "".
// The deepest matching segment wins, so a container that builds its own
// cgroups below its scope still resolves. Only containerd is recognised.
func ContainerID(cgroupPath string) string {
	segs := strings.Split(cgroupPath, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if m := containerRe.FindStringSubmatch(segs[i]); m != nil {
			return m[1]
		}
	}
	return ""
}

// PodUID extracts the pod UID from a cgroup path, or returns "".
func PodUID(cgroupPath string) string {
	segs := strings.Split(cgroupPath, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if m := podRe.FindStringSubmatch(segs[i]); m != nil {
			return strings.ReplaceAll(m[1], "_", "-")
		}
	}
	return ""
}

// CheckCgroupV2 rejects a root that is not a cgroup v2 mount.
func CheckCgroupV2(root string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return err
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New(root + " is not a cgroup v2 mount; cgroup v1 nodes are not supported")
	}
	return nil
}

// CgroupResolver maps cgroup IDs to paths. On cgroup v2 the ID the kernel
// reports is the inode number of the cgroup's directory, so the resolver
// walks the mounted hierarchy and indexes directories by inode.
//
// The root is the node's own view of the hierarchy. In kind that view starts
// at the node container's cgroup, so pod cgroups resolve without knowing the
// prefix the outer host puts in front.
type CgroupResolver struct {
	root string
	// minRescan bounds how often an unknown ID can trigger a walk.
	minRescan time.Duration

	mu       sync.Mutex
	paths    map[uint64]string
	lastScan time.Time
	scans    uint64
}

// NewCgroupResolver returns a resolver for the hierarchy mounted at root.
func NewCgroupResolver(root string) *CgroupResolver {
	return &CgroupResolver{
		root:      root,
		minRescan: 50 * time.Millisecond,
		paths:     make(map[uint64]string),
	}
}

// Path returns the cgroup path for an ID, relative to the root and starting
// with "/". An unknown ID triggers one rescan, rate-limited.
func (r *CgroupResolver) Path(id uint64) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if p, ok := r.paths[id]; ok {
		return p, true
	}
	if time.Since(r.lastScan) < r.minRescan {
		return "", false
	}
	r.scan()
	p, ok := r.paths[id]
	return p, ok
}

// Alive reports whether the cgroup with this ID still exists.
func (r *CgroupResolver) Alive(id uint64) bool {
	r.mu.Lock()
	p, ok := r.paths[id]
	r.mu.Unlock()
	if !ok {
		return false
	}
	var st syscall.Stat_t
	return syscall.Stat(filepath.Join(r.root, p), &st) == nil && st.Ino == id
}

// Scans is the number of hierarchy walks so far.
func (r *CgroupResolver) Scans() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scans
}

// scan rebuilds the whole index. A node has a few hundred cgroups, so a full
// walk is cheap and also drops IDs of cgroups that are gone.
func (r *CgroupResolver) scan() {
	paths := make(map[uint64]string, len(r.paths))
	_ = filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Cgroups come and go during the walk.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		rel := strings.TrimPrefix(path, r.root)
		if rel == "" {
			rel = "/"
		}
		paths[st.Ino] = rel
		return nil
	})
	r.paths = paths
	r.lastScan = time.Now()
	r.scans++
}

// PodCgroups walks the hierarchy at root and returns the cgroup ID of every
// pod's own cgroup, by pod UID. A pod's cgroup is the directory named after
// the pod; its containers' cgroups are below it.
func PodCgroups(root string) map[string]uint64 {
	out := map[string]uint64{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		uid := PodUID(d.Name())
		if uid == "" {
			return nil
		}
		var st syscall.Stat_t
		if syscall.Stat(path, &st) == nil {
			out[uid] = st.Ino
		}
		// Nothing below a pod's cgroup is another pod's.
		return fs.SkipDir
	})
	return out
}
