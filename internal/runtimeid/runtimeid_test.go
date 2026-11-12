// SPDX-License-Identifier: Apache-2.0

package runtimeid

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetRecognisesByIdentity(t *testing.T) {
	// A fake /proc whose pid 1 has a root holding one "runtime".
	proc := t.TempDir()
	root := filepath.Join(proc, "1", "root")
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	runc := filepath.Join(root, "usr/bin/runc")
	if err := os.WriteFile(runc, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink that points out of the root must not be followed there.
	outside := filepath.Join(proc, "outside")
	if err := os.WriteFile(outside, []byte("y"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/../../outside", filepath.Join(root, "usr/bin/crun")); err != nil {
		t.Fatal(err)
	}

	s := New(proc, []string{"/usr/bin/runc", "/usr/bin/crun", "/usr/bin/missing", "/usr/bin"})
	if n := s.Refresh(); n != 1 {
		t.Fatalf("Refresh() = %d identities, want 1", n)
	}

	id := func(path string) (uint32, uint64) {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			t.Fatal(err)
		}
		return unix.Major(st.Dev)<<20 | unix.Minor(st.Dev), st.Ino
	}
	if dev, ino := id(runc); !s.Has(dev, ino) {
		t.Error("the runtime binary is not recognised")
	}
	if dev, ino := id(outside); s.Has(dev, ino) {
		t.Error("a file outside the node's root is recognised")
	}

	// A copy under the same name is another file.
	copyPath := filepath.Join(t.TempDir(), "runc")
	if err := os.WriteFile(copyPath, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if dev, ino := id(copyPath); s.Has(dev, ino) {
		t.Error("a copy of the binary is recognised")
	}
	if s.Has(0, 0) {
		t.Error("the zero identity is recognised")
	}

	// A replaced binary is added; the old identity stays.
	oldDev, oldIno := id(runc)
	if err := os.Rename(copyPath, runc); err != nil {
		t.Skip("cannot rename across filesystems here")
	}
	if n := s.Refresh(); n != 2 {
		t.Fatalf("after an upgrade Refresh() = %d identities, want 2", n)
	}
	if !s.Has(oldDev, oldIno) {
		t.Error("the identity of the replaced binary was forgotten")
	}
}
