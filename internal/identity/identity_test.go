// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeProc lays out procRoot/<pid>/root as a container root filesystem and
// returns procRoot.
func fakeProc(t *testing.T, pid string, files map[string][]byte, links map[string]string) string {
	t.Helper()
	proc := t.TempDir()
	root := filepath.Join(proc, pid, "root")
	for name, data := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	return proc
}

// exeOf describes the file at path under pid's root as an exec event would.
func exeOf(t *testing.T, proc, pid, path string, argv ...string) Exe {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(proc, pid, "root", path), &st); err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(pid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return Exe{PID: uint32(n), Path: path, Dev: kdev(st.Dev), Inode: st.Ino, Ctime: uint64(st.Ctim.Nano()), Argv: argv}
}

func content(seed byte, size int) []byte {
	b := bytes.Repeat([]byte{seed}, size)
	b[0] = 0x7f // not that it matters: identity is the bytes, not ELF
	return b
}

func TestCopiedShellKeepsItsIdentity(t *testing.T) {
	dash := content('d', 4096)
	proc := fakeProc(t, "100", map[string][]byte{
		"/usr/bin/dash":    dash,
		"/usr/bin/python3": content('p', 8192),
		"/usr/bin/curl":    content('c', 2048),
		"/tmp/kworker":     dash, // E01: the shell copied to another name
		"/tmp/fetch":       content('c', 2048),
		"/tmp/other":       content('o', 4096),
	}, map[string]string{"/bin": "usr/bin", "/usr/bin/sh": "dash"})
	c := New(proc)
	c.ObserveRoot(100)

	for _, tc := range []struct {
		path string
		want Role
	}{
		{"/tmp/kworker", Shell},
		{"/bin/sh", Shell},
		{"/usr/bin/python3", Interpreter},
		{"/tmp/fetch", DownloadTool},
		{"/tmp/other", Unknown},
	} {
		if got := c.Identify(exeOf(t, proc, "100", tc.path, tc.path)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestBusyboxAppletDecides(t *testing.T) {
	bb := content('b', 4096)
	proc := fakeProc(t, "200", map[string][]byte{
		"/bin/busybox":        bb,
		"/tmp/.cache/busybox": bb, // E09
	}, map[string]string{"/bin/sh": "/bin/busybox", "/bin/wget": "/bin/busybox"})
	c := New(proc)
	c.ObserveRoot(200)

	for _, tc := range []struct {
		argv []string
		want Role
	}{
		{[]string{"/tmp/.cache/busybox", "sh"}, Shell},
		{[]string{"/tmp/.cache/busybox", "sh", "/tmp/.cache/update"}, Shell},
		{[]string{"/bin/sh"}, Shell},
		{[]string{"wget", "-q", "http://x/"}, DownloadTool},
		{[]string{"/tmp/.cache/busybox", "cat", "/etc/hostname"}, Unknown},
		{nil, Unknown},
	} {
		if got := c.Identify(exeOf(t, proc, "200", "/tmp/.cache/busybox", tc.argv...)); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.argv, got, tc.want)
		}
	}
	// Alpine's /bin/sh is a symlink to busybox; it must not turn busybox
	// into "shell" for every applet.
	if got := c.Identify(exeOf(t, proc, "200", "/bin/busybox", "cat")); got != Unknown {
		t.Errorf("busybox as cat: %q", got)
	}
}

func TestIdentityIsTheFirstMiB(t *testing.T) {
	bash := content('B', prefix+512)
	padded := append(append([]byte{}, bash...), []byte("appended")...)
	edited := append([]byte{}, bash...)
	edited[100] ^= 0xff
	proc := fakeProc(t, "300", map[string][]byte{
		"/bin/bash":   bash,
		"/tmp/padded": padded,
		"/tmp/edited": edited,
	}, nil)
	c := New(proc)
	c.ObserveRoot(300)
	if got := c.Identify(exeOf(t, proc, "300", "/tmp/padded", "x")); got != Shell {
		t.Errorf("bytes appended after the first MiB: %q, want shell", got)
	}
	if got := c.Identify(exeOf(t, proc, "300", "/tmp/edited", "x")); got != Unknown {
		t.Errorf("first MiB edited: %q, want unknown", got)
	}
}

func TestIdentifyChecksTheFileIsTheOneExecuted(t *testing.T) {
	proc := fakeProc(t, "400", map[string][]byte{
		"/bin/sh":  content('s', 1024),
		"/tmp/new": content('s', 1024),
	}, nil)
	c := New(proc)
	c.ObserveRoot(400)
	x := exeOf(t, proc, "400", "/tmp/new", "x")
	x.Inode++ // the path now names another file than the one executed
	if got := c.Identify(x); got != Unknown {
		t.Errorf("mismatched inode: %q, want unknown", got)
	}
	if _, _, errs := c.Stats(); errs != 1 {
		t.Errorf("errs %d, want 1", errs)
	}
}

func TestShellFromAnotherContainer(t *testing.T) {
	zsh := content('z', 2048)
	proc := fakeProc(t, "500", map[string][]byte{"/bin/zsh": zsh}, nil)
	other := filepath.Join(proc, "600", "root", "tmp")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "z"), zsh, 0o755); err != nil {
		t.Fatal(err)
	}
	c := New(proc)
	c.ObserveRoot(500)
	c.ObserveRoot(600)
	if got := c.Identify(exeOf(t, proc, "600", "/tmp/z", "z")); got != Shell {
		t.Errorf("shell brought from another container: %q, want shell", got)
	}
}
