// SPDX-License-Identifier: Apache-2.0

package credwatch

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/k8s"
)

type sink struct{ m map[fileID]uint32 }

func (s *sink) PutInode(dev uint32, inode uint64, bits uint32) error {
	s.m[fileID{dev, inode}] = bits
	return nil
}

func (s *sink) DeleteInode(dev uint32, inode uint64) error {
	delete(s.m, fileID{dev, inode})
	return nil
}

// A container root under a fake /proc, with a token volume laid out as the
// kubelet does: the file in a ..<time> directory, linked from the top.
func setup(t *testing.T, mount, rel string) (procRoot string) {
	t.Helper()
	procRoot = t.TempDir()
	root := filepath.Join(t.TempDir(), "rootfs")
	vol := filepath.Join(root, mount)
	data := filepath.Join(vol, "..2026_11_22_10_00_00.1")
	if err := os.MkdirAll(filepath.Join(data, filepath.Dir(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, rel), []byte("eyJ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..2026_11_22_10_00_00.1", filepath.Join(vol, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", rel), filepath.Join(vol, filepath.Base(rel))); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(procRoot, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(procRoot, "42", "root")); err != nil {
		t.Fatal(err)
	}
	return procRoot
}

func devOf(t *testing.T, p string) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return unix.Major(st.Dev)<<20 | unix.Minor(st.Dev)
}

// A token volume that is a tmpfs of its own is watched as a whole device,
// and any path to the token, under any name the spec gave it, is the token;
// the volume's other files are not.
func TestWholeVolume(t *testing.T) {
	procRoot := setup(t, "opt/svc", "creds")
	s := &sink{m: map[fileID]uint32{}}
	w := New(procRoot, s, 1)
	w.ownFS = func(int, *unix.Stat_t, *unix.Stat_t) bool { return true }
	tok := k8s.TokenMount{ContainerID: "c1", Namespace: "shop", Pod: "web", Path: "/opt/svc/creds", Rel: "creds"}
	w.Resolve(42, []k8s.TokenMount{tok})

	dev := devOf(t, procRoot)
	if bits, ok := s.m[fileID{dev: dev}]; !ok || bits != 1 {
		t.Fatalf("device watch %v %v; map %v", bits, ok, s.m)
	}
	for p, want := range map[string]bool{
		"/opt/svc/creds":                         true,
		"/opt/svc/..2026_11_22_10_00_00.1/creds": true,
		"/proc/77/root/opt/svc/creds":            true,
		"/hostkubelet/pods/u/volumes/kubernetes.io~projected/svc/..2026_11_22_10_00_00.1/creds": true,
		"/opt/svc/ca.crt":    false,
		"/opt/svc/namespace": false,
		"/opt/svc/xcreds":    false,
	} {
		c, ok := w.Lookup(dev, 999, p)
		if ok != want || ok && (c.Kind != KindSAToken || c.Pod != "web" || c.Namespace != "shop") {
			t.Errorf("%s: %+v %v, want %v", p, c, ok, want)
		}
	}
	// Resolving again does nothing new; the container gone, the watch goes.
	w.Resolve(42, []k8s.TokenMount{tok})
	if n, _ := w.Stats(); n != 1 {
		t.Errorf("%d watches after a second resolve", n)
	}
	w.GC(func(string) bool { return false })
	if len(s.m) != 0 {
		t.Errorf("left after GC: %v", s.m)
	}
}

// A volume on the container's own filesystem is watched by the token's
// inode, and a rotation, which writes a new file, moves the watch.
func TestByInodeFollowsRotation(t *testing.T) {
	procRoot := setup(t, "var/run/app", "token")
	s := &sink{m: map[fileID]uint32{}}
	w := New(procRoot, s, 1)
	w.ownFS = func(int, *unix.Stat_t, *unix.Stat_t) bool { return false }
	tok := k8s.TokenMount{ContainerID: "c1", Namespace: "shop", Pod: "web", Path: "/var/run/app/token", Rel: "token"}
	w.Resolve(42, []k8s.TokenMount{tok})
	if len(s.m) != 1 {
		t.Fatalf("watches %v", s.m)
	}
	var old fileID
	for id := range s.m {
		old = id
	}
	if old.inode == 0 {
		t.Fatal("watched as a whole device")
	}
	if _, ok := w.Lookup(old.dev, old.inode, "/anything"); !ok {
		t.Error("the token's inode is not the token")
	}

	// Rotation: a new directory, ..data pointed at it.
	vol := filepath.Join(procRoot, "42", "root", "var/run/app")
	next := filepath.Join(vol, "..2026_11_22_11_00_00.2")
	if err := os.Mkdir(next, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(next, "token"), []byte("eyK"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(vol, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..2026_11_22_11_00_00.2", filepath.Join(vol, "..data")); err != nil {
		t.Fatal(err)
	}
	w.Resolve(42, []k8s.TokenMount{tok})
	if _, ok := s.m[old]; ok || len(s.m) != 1 {
		t.Errorf("after rotation: %v (old %v)", s.m, old)
	}
}
