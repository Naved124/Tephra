// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/filter"
)

// A watched name changed without being opened: removed, renamed, linked,
// truncated by path.
func TestFileChange(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// A second directory two mounts down from the root (/dev, then
	// /dev/shm), for the walk across mount points.
	shm, err := os.MkdirTemp("/dev/shm", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shm) })
	for _, d := range []string{"home", "cron", "other"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var (
		history   = filepath.Join(dir, "home", ".bash_history")
		preload   = filepath.Join(dir, "preload")
		staged    = filepath.Join(dir, "other", "staged")
		moved     = filepath.Join(dir, "other", "moved")
		cronLink  = filepath.Join(dir, "cron", "job")
		cronSym   = filepath.Join(dir, "cron", "sym")
		unwatched = filepath.Join(dir, "other", "nothing")
		onShm     = filepath.Join(shm, "file")
	)
	for _, p := range []string{history, staged, unwatched, onShm} {
		touch(t, p)
	}

	s := loadForTest(t, Options{Filters: filter.Set{Watches: []filter.Watch{
		{Kind: filter.Name, Path: ".bash_history", Bits: filter.Write},
		{Kind: filter.Exact, Path: preload, Bits: filter.Write},
		{Kind: filter.Prefix, Path: filepath.Join(dir, "cron") + "/", Bits: filter.Write},
		{Kind: filter.Prefix, Path: shm + "/", Bits: filter.Write},
		// A watch that reports reads only is not a reason to report a
		// change.
		{Kind: filter.Exact, Path: unwatched, Bits: filter.Read},
	}}})
	if !s.Available(events.TypeFileChange) {
		t.Skip("this kernel has no path hooks (CONFIG_SECURITY_PATH)")
	}

	expect := func(path, op string, by uint32, do func() error) *events.FileChange {
		t.Helper()
		if err := do(); err != nil {
			t.Fatalf("%s %s: %v", op, path, err)
		}
		e := next(t, s, wait, func(f *events.FileChange) bool { return f.PID == self() && f.Path == path && f.Op == op })
		if e == nil {
			t.Errorf("no file_change event for %s of %s", op, path)
			return nil
		}
		if got := e.Flags & (events.FileByInode | events.FileByName | events.FileByPath | events.FileNoPath); got != by {
			t.Errorf("%s %s: flags %#x, want %#x", op, path, got, by)
		}
		return e
	}

	expect(history, "truncate", events.FileByName, func() error { return unix.Truncate(history, 0) })
	if e := expect(history, "unlink", events.FileByName, func() error { return os.Remove(history) }); e != nil && e.Inode == 0 {
		t.Error("unlink of an existing file carries no inode")
	}
	// Written elsewhere and renamed into place: the watched name is
	// created without ever being opened.
	if e := expect(preload, "rename_to", events.FileByPath, func() error { return os.Rename(staged, preload) }); e != nil && e.Inode != 0 {
		t.Errorf("rename onto a name that did not exist carries inode %d", e.Inode)
	}
	expect(preload, "rename_from", events.FileByPath, func() error { return os.Rename(preload, moved) })
	expect(cronLink, "link", events.FileByPath, func() error { return os.Link(moved, cronLink) })
	expect(cronSym, "symlink", events.FileByPath, func() error { return os.Symlink("/dev/null", cronSym) })
	expect(history, "symlink", events.FileByName, func() error { return os.Symlink("/dev/null", history) })
	expect(onShm, "unlink", events.FileByPath, func() error { return os.Remove(onShm) })

	before, _ := s.ReadStats(events.TypeFileChange)
	if err := os.Remove(unwatched); err != nil {
		t.Fatal(err)
	}
	if e := next(t, s, 500*time.Millisecond, func(f *events.FileChange) bool { return f.PID == self() && f.Path == unwatched }); e != nil {
		t.Errorf("unexpected event %+v", e)
	}
	after, _ := s.ReadStats(events.TypeFileChange)
	if after.Filtered <= before.Filtered {
		t.Errorf("filtered did not grow (%d -> %d)", before.Filtered, after.Filtered)
	}
	if after.Dropped != 0 {
		t.Errorf("%d file_change events dropped", after.Dropped)
	}
}

// A path longer than the kernel buffer is reported as cut, not as a wrong
// shorter path.
func TestFileChangeLongPath(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	deep := dir
	for i := 0; i < 8; i++ {
		deep = filepath.Join(deep, "a-directory-name-of-forty-characters-xxx")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(deep, ".bash_history")
	touch(t, target)

	s := loadForTest(t, Options{Filters: filter.Set{Watches: []filter.Watch{
		{Kind: filter.Name, Path: ".bash_history", Bits: filter.Write},
	}}})
	if !s.Available(events.TypeFileChange) {
		t.Skip("this kernel has no path hooks (CONFIG_SECURITY_PATH)")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	e := next(t, s, wait, func(f *events.FileChange) bool { return f.PID == self() && f.Op == "unlink" })
	if e == nil {
		t.Fatal("no event for a name watch under a long path")
	}
	if e.Flags&events.FileNoPath == 0 {
		t.Errorf("path of %d bytes not marked as cut: %q", len(target), e.Path)
	}
	if got := filepath.Base(e.Path); got != ".bash_history" {
		t.Errorf("cut path %q does not end in the file name", e.Path)
	}
}

// An open the kernel refuses is reported with the name as passed and, for a
// relative name, the working directory.
func TestOpenDenied(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "td")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := loadForTest(t, Options{})
	// The test runs as root, which no permission bit stops.
	asNobody := func(cwd string, argv ...string) {
		t.Helper()
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = cwd
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		if err := cmd.Run(); err == nil {
			t.Fatalf("%v succeeded as nobody", argv)
		}
	}

	asNobody("/", "/bin/cat", secret)
	e := next(t, s, wait, func(d *events.FileDenied) bool { return d.Comm == "cat" && d.Name == secret })
	if e == nil {
		t.Fatal("no file_denied event for an absolute name")
	}
	if e.Errno != uint32(unix.EACCES) || e.Write() || e.Cwd != "" || e.UID != 65534 {
		t.Errorf("event %+v", e)
	}

	asNobody(dir, "/bin/cat", "./secret")
	e = next(t, s, wait, func(d *events.FileDenied) bool { return d.Comm == "cat" && d.Name == "./secret" })
	if e == nil {
		t.Fatal("no file_denied event for a relative name")
	}
	if e.Cwd != dir {
		t.Errorf("cwd %q, want %q", e.Cwd, dir)
	}

	asNobody("/", "/bin/sh", "-c", "echo x >> "+secret)
	e = next(t, s, wait, func(d *events.FileDenied) bool { return d.Name == secret && d.Write() })
	if e == nil {
		t.Fatal("no file_denied event for a refused write")
	}

	// A successful open and a missing file are not refusals.
	before, _ := s.ReadStats(events.TypeFileDenied)
	openFlags(t, secret, os.O_RDONLY)
	_, _ = os.Open(filepath.Join(dir, "missing"))
	if e := next(t, s, 300*time.Millisecond, func(d *events.FileDenied) bool { return d.PID == self() }); e != nil {
		t.Errorf("unexpected event %+v", e)
	}
	after, _ := s.ReadStats(events.TypeFileDenied)
	if after.Seen != before.Seen && after.Dropped != 0 {
		t.Errorf("stats %+v -> %+v", before, after)
	}
}
