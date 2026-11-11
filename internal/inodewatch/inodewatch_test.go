// SPDX-License-Identifier: Apache-2.0

package inodewatch

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeSink map[fileID]uint32

func (f fakeSink) PutInode(dev uint32, inode uint64, bits uint32) error {
	f[fileID{dev, inode}] = bits
	return nil
}

func (f fakeSink) DeleteInode(dev uint32, inode uint64) error {
	delete(f, fileID{dev, inode})
	return nil
}

// root builds <proc>/<pid>/root with the given files and returns the
// identity of each.
func root(t *testing.T, proc, pid string, files ...string) map[string]fileID {
	t.Helper()
	ids := map[string]fileID{}
	for _, f := range files {
		p := filepath.Join(proc, pid, "root", f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(pid), 0o600); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		ids[f] = fileID{unix.Major(st.Dev)<<20 | unix.Minor(st.Dev), st.Ino}
	}
	return ids
}

func TestTracker(t *testing.T) {
	proc := t.TempDir()
	host := root(t, proc, "1", "etc/shadow", "etc/ld.so.preload")
	web := root(t, proc, "200", "etc/shadow")
	if err := os.MkdirAll(filepath.Join(proc, "300", "root"), 0o755); err != nil {
		t.Fatal(err)
	}

	sink := fakeSink{}
	tr := New(proc, sink)
	tr.Observe(1, HostOwner)
	if len(sink) != 0 {
		t.Fatalf("entries written with no watches: %v", sink)
	}

	tr.SetWatches(map[string]uint32{"/etc/shadow": 3, "/etc/ld.so.preload": 2, "/etc/missing": 1})
	tr.Observe(1, HostOwner)
	tr.Observe(200, "web")
	tr.Observe(200, "web") // same root, resolved once
	tr.Observe(300, "empty")
	tr.Observe(999, "gone")
	want := fakeSink{host["etc/shadow"]: 3, host["etc/ld.so.preload"]: 2, web["etc/shadow"]: 3}
	if len(sink) != len(want) {
		t.Fatalf("sink = %v, want %v", sink, want)
	}
	for id, bits := range want {
		if sink[id] != bits {
			t.Errorf("%v: bits %d, want %d", id, sink[id], bits)
		}
	}
	if inodes, roots, errs := tr.Stats(); inodes != 3 || roots != 3 || errs != 0 {
		t.Errorf("stats = %d inodes, %d roots, %d errors", inodes, roots, errs)
	}

	id := web["etc/shadow"]
	if p, ok := tr.WatchedPath(id.dev, id.inode); !ok || p != "/etc/shadow" {
		t.Errorf("WatchedPath = %q, %v", p, ok)
	}

	// The container goes; the host's entries stay.
	tr.GC(func(owner string) bool { return owner != "web" })
	if _, ok := sink[web["etc/shadow"]]; ok || len(sink) != 2 {
		t.Errorf("after GC: %v", sink)
	}
	// A new container reusing the pid is resolved again.
	tr.Observe(200, "web2")
	if _, ok := sink[web["etc/shadow"]]; !ok {
		t.Error("root not resolved again after GC")
	}

	tr.SetWatches(nil)
	if len(sink) != 0 {
		t.Errorf("entries left after the watches were cleared: %v", sink)
	}
}

// A symlink inside a container must be resolved inside it, never against
// the agent's own root.
func TestSymlinkStaysInRoot(t *testing.T) {
	proc := t.TempDir()
	ids := root(t, proc, "7", "real/shadow")
	if err := os.MkdirAll(filepath.Join(proc, "7", "root", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Absolute targets: one that exists inside the root, one that exists
	// only outside it.
	if err := os.Symlink("/real/shadow", filepath.Join(proc, "7", "root", "etc", "shadow")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(proc, "7", "root", "etc", "escape")); err != nil {
		t.Fatal(err)
	}

	sink := fakeSink{}
	tr := New(proc, sink)
	tr.SetWatches(map[string]uint32{"/etc/shadow": 1, "/etc/escape": 1})
	tr.Observe(7, "c")
	if len(sink) != 1 || sink[ids["real/shadow"]] != 1 {
		t.Errorf("sink = %v, want only %v", sink, ids["real/shadow"])
	}
}
