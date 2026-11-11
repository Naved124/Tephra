// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/filter"
)

// loadForTest loads the sensor and lifts the ignore on the test's own
// cgroup, so that what the test does is visible.
func loadForTest(t *testing.T, opts Options) *Sensor {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	if opts.RingBufSize == 0 {
		opts.RingBufSize = 1 << 20
	}
	s, err := Load(opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, sk := range s.Skipped() {
		t.Logf("skipped %s (%s): %s", sk.Program, sk.Hook, sk.Reason)
	}
	if err := s.coll.Maps["cgroup_ignore"].Delete(s.Self().CgroupID); err != nil {
		t.Fatal(err)
	}
	return s
}

// next returns the first event for which match is true, or nil when none
// arrives in time.
func next[T events.Event](t *testing.T, s *Sensor, wait time.Duration, match func(T) bool) T {
	t.Helper()
	var zero T
	deadline := time.Now().Add(wait)
	for {
		s.Events().SetDeadline(deadline)
		rec, err := s.Events().Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return zero
			}
			t.Fatalf("read ring buffer: %v", err)
		}
		ev, err := events.Decode(rec.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if e, ok := ev.(T); ok && match(e) {
			return e
		}
	}
}

func self() uint32 { return uint32(os.Getpid()) }

func TestConnectAndAccept(t *testing.T) {
	s := loadForTest(t, Options{})

	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("listen %s: %v", addr, err)
		}
		server := netip.MustParseAddrPort(ln.Addr().String())
		accepted := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			accepted <- c
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial %s: %v", ln.Addr(), err)
		}
		client := netip.MustParseAddrPort(conn.LocalAddr().String())
		srv := <-accepted

		var sawConnect, sawAccept bool
		for !sawConnect || !sawAccept {
			e := next(t, s, 5*time.Second, func(n *events.Net) bool { return n.PID == self() })
			if e == nil {
				t.Fatalf("%s: connect seen %v, accept seen %v", addr, sawConnect, sawAccept)
			}
			switch e.Type {
			case events.TypeConnect:
				if e.Remote != server {
					continue
				}
				sawConnect = true
				if e.Proto != unix.IPPROTO_TCP {
					t.Errorf("connect proto = %d, want TCP", e.Proto)
				}
			case events.TypeAccept:
				if e.Local != server {
					continue
				}
				sawAccept = true
				if e.Remote != client {
					t.Errorf("accept peer = %s, want %s", e.Remote, client)
				}
				if e.Proto != unix.IPPROTO_TCP {
					t.Errorf("accept proto = %d, want TCP", e.Proto)
				}
			}
		}
		_ = conn.Close()
		_ = srv.Close()
		_ = ln.Close()
	}
}

// An IPv4 destination reached through an IPv6 socket is one address to the
// ignore list and to the reader.
func TestNetIgnoreAndMapped(t *testing.T) {
	s := loadForTest(t, Options{Filters: filter.Set{NetIgnore: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
	}}})
	if !s.NetIgnored(netip.MustParseAddr("127.9.9.9")) || s.NetIgnored(netip.MustParseAddr("::1")) {
		t.Fatal("ignore list not as written")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	before, _ := s.ReadStats(events.TypeConnect)
	// Plain IPv4, then the same address as ::ffff:127.0.0.1.
	for _, target := range []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("[::ffff:127.0.0.1]:%d", port)} {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		ap := netip.MustParseAddrPort(target)
		_ = unix.Connect(fd, &unix.SockaddrInet6{Port: int(ap.Port()), Addr: netip.AddrFrom16(ap.Addr().As16()).As16()})
		_ = unix.Close(fd)
	}
	if e := next(t, s, time.Second, func(n *events.Net) bool {
		return n.PID == self() && n.Type == events.TypeConnect && int(n.Remote.Port()) == port
	}); e != nil {
		t.Errorf("ignored destination was emitted: %s", e.Remote)
	}
	after, _ := s.ReadStats(events.TypeConnect)
	if after.Filtered-before.Filtered < 2 {
		t.Errorf("connect filtered grew by %d, want at least 2", after.Filtered-before.Filtered)
	}

	// Removing the entry takes effect without a reload.
	if err := s.SetFilters(filter.Set{}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if e := next(t, s, 5*time.Second, func(n *events.Net) bool {
		return n.PID == self() && n.Type == events.TypeConnect && int(n.Remote.Port()) == port
	}); e == nil {
		t.Error("no connect event after the ignore entry was removed")
	}
}

func TestUnixConnect(t *testing.T) {
	s := loadForTest(t, Options{})
	path := filepath.Join(t.TempDir(), "s.sock")
	for _, name := range []string{path, "@tephra-test-abstract"} {
		ln, err := net.Listen("unix", name)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.Dial("unix", name)
		if err != nil {
			t.Fatal(err)
		}
		e := next(t, s, 5*time.Second, func(u *events.UnixConnect) bool { return u.PID == self() && u.Path == name })
		if e == nil {
			t.Errorf("no unix_connect event for %s", name)
		}
		_ = conn.Close()
		_ = ln.Close()
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func openFlags(t *testing.T, path string, flags int) {
	t.Helper()
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	_ = f.Close()
}

func TestFileOpenWatches(t *testing.T) {
	// The watched paths must fit the kernel's 128-byte key, which
	// t.TempDir() does not promise.
	dir, err := os.MkdirTemp("/tmp", "tw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for _, d := range []string{"prefix", "other"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var (
		inPrefix  = filepath.Join(dir, "prefix", "a")
		exact     = filepath.Join(dir, "exact")
		exactLong = filepath.Join(dir, "exact-not")
		byName    = filepath.Join(dir, "other", "authorized_keys")
		writeOnly = filepath.Join(dir, "wo")
		identity  = filepath.Join(dir, "identity")
		hardLink  = filepath.Join(dir, "other", "innocent")
		unwatched = filepath.Join(dir, "other", "nothing")
	)
	for _, p := range []string{inPrefix, exact, exactLong, byName, writeOnly, identity, unwatched} {
		touch(t, p)
	}
	if err := os.Link(identity, hardLink); err != nil {
		t.Fatal(err)
	}

	s := loadForTest(t, Options{Filters: filter.Set{Watches: []filter.Watch{
		{Kind: filter.Prefix, Path: filepath.Join(dir, "prefix") + "/", Bits: filter.Read | filter.Write},
		{Kind: filter.Exact, Path: exact, Bits: filter.Read | filter.Write},
		{Kind: filter.Name, Path: "authorized_keys", Bits: filter.Read | filter.Write},
		{Kind: filter.Exact, Path: writeOnly, Bits: filter.Write},
	}}})
	var st unix.Stat_t
	if err := unix.Stat(identity, &st); err != nil {
		t.Fatal(err)
	}
	if err := s.PutInode(KernelDev(unix.Major(st.Dev), unix.Minor(st.Dev)), st.Ino, filter.Read|filter.Write); err != nil {
		t.Fatal(err)
	}

	mine := func(path string) func(*events.FileOpen) bool {
		return func(f *events.FileOpen) bool { return f.PID == self() && f.Path == path }
	}
	expect := func(path string, flags int, by uint32) *events.FileOpen {
		t.Helper()
		openFlags(t, path, flags)
		e := next(t, s, 5*time.Second, mine(path))
		if e == nil {
			t.Errorf("no file_open event for %s", path)
			return nil
		}
		if got := e.Flags & (events.FileByInode | events.FileByName | events.FileByPath); got != by {
			t.Errorf("%s: matched by %#x, want %#x", path, got, by)
		}
		if e.Inode == 0 || e.Dev == 0 {
			t.Errorf("%s: inode %d dev %d", path, e.Inode, e.Dev)
		}
		return e
	}
	expectNone := func(path string, flags int) {
		t.Helper()
		before, _ := s.ReadStats(events.TypeFileOpen)
		openFlags(t, path, flags)
		if e := next(t, s, 500*time.Millisecond, mine(path)); e != nil {
			t.Errorf("%s: unexpected event %+v", path, e)
		}
		after, _ := s.ReadStats(events.TypeFileOpen)
		if after.Filtered <= before.Filtered {
			t.Errorf("%s: filtered did not grow (%d -> %d)", path, before.Filtered, after.Filtered)
		}
	}

	expect(inPrefix, os.O_RDONLY, events.FileByPath)
	if e := expect(exact, os.O_RDONLY, events.FileByPath); e != nil && e.Write() {
		t.Error("read-only open reported as a write")
	}
	// An exact watch does not cover longer names.
	expectNone(exactLong, os.O_RDONLY)
	expect(byName, os.O_RDONLY, events.FileByName)
	// The hard link is under no watched path and has no watched name.
	expect(hardLink, os.O_RDONLY, events.FileByInode)
	expect(identity, os.O_RDONLY, events.FileByInode)
	expectNone(unwatched, os.O_RDONLY)

	// A write-only watch drops reads in the kernel, and the truncation
	// flag is still visible at the hook.
	expectNone(writeOnly, os.O_RDONLY)
	if e := expect(writeOnly, os.O_WRONLY|os.O_TRUNC, events.FileByPath); e != nil {
		if !e.Write() || e.OpenFlags&events.OTrunc == 0 {
			t.Errorf("open flags %#o, want write and O_TRUNC", e.OpenFlags)
		}
	}

	// Disabling the type stops the events and the counting.
	if err := s.SetEnabled([]events.Type{events.TypeConnect}); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ReadStats(events.TypeFileOpen)
	openFlags(t, inPrefix, os.O_RDONLY)
	after, _ := s.ReadStats(events.TypeFileOpen)
	if after.Seen != before.Seen || s.Enabled(events.TypeFileOpen) || !s.Enabled(events.TypeExec) {
		t.Errorf("file_open still counted after being disabled (%d -> %d)", before.Seen, after.Seen)
	}
}

// Only the allowlisted variables leave the kernel, and an environment too
// long to scan is flagged.
func TestExecEnvAllowlist(t *testing.T) {
	s := loadForTest(t, Options{})

	// Not os/exec: it removes duplicate variables, and one case below
	// needs them.
	run := func(env []string) *events.Exec {
		t.Helper()
		pid, err := syscall.ForkExec("/bin/true", []string{"/bin/true"}, &syscall.ProcAttr{Env: env})
		if err != nil {
			t.Fatal(err)
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
			t.Fatal(err)
		}
		e := next(t, s, 5*time.Second, func(x *events.Exec) bool { return x.PID == uint32(pid) })
		if e == nil {
			t.Fatal("exec event not seen")
		}
		return e
	}

	env := []string{"SECRET_TOKEN=do-not-capture", "LD_LIBRARY_PATH=/opt/lib"}
	for i := 0; i < 60; i++ {
		env = append(env, fmt.Sprintf("FILLER_%d=%s", i, strings.Repeat("v", i)))
	}
	env = append(env, "LD_AUDIT=/nonexistent/audit.so", "LD_PRELOADX=no", "XLD_PRELOAD=no", "PATH=/usr/bin", "LD_AUDIT=second-is-ignored")
	e := run(env)
	// In slot order, not in the order they were set.
	if want := []string{"LD_AUDIT=/nonexistent/audit.so", "LD_LIBRARY_PATH=/opt/lib"}; !reflect.DeepEqual(e.Env, want) {
		t.Errorf("env = %q, want %q", e.Env, want)
	}
	if e.Flags&events.ExecEnvTrunc != 0 {
		t.Error("env flagged as truncated")
	}
	if !reflect.DeepEqual(e.Argv, []string{"/bin/true"}) {
		t.Errorf("argv = %q", e.Argv)
	}

	if e := run([]string{"PATH=/usr/bin"}); e.Env != nil || e.Flags&events.ExecEnvTrunc != 0 {
		t.Errorf("plain environment: env %q flags %#x", e.Env, e.Flags)
	}

	// More variables than the kernel scans, with the interesting one last.
	env = nil
	for i := 0; i < 700; i++ {
		env = append(env, fmt.Sprintf("PAD_%d=x", i))
	}
	env = append(env, "LD_LIBRARY_PATH=/hidden")
	if e := run(env); e.Flags&events.ExecEnvTrunc == 0 {
		t.Errorf("an environment of %d variables was not flagged; env %q", len(env), e.Env)
	}
}

// A server already blocked in accept() when the sensor attaches must still
// have its next connection reported.
func TestAcceptBlockedBeforeAttach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	sa, _ := unix.Getsockname(fd)
	port := sa.(*unix.SockaddrInet4).Port

	// A blocking accept on a raw descriptor, as a simple server does it.
	accepted := make(chan int, 1)
	go func() {
		nfd, _, _ := unix.Accept(fd)
		accepted <- nfd
	}()
	time.Sleep(300 * time.Millisecond) // let it block in the kernel

	s := loadForTest(t, Options{})
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if nfd := <-accepted; nfd >= 0 {
		defer func() { _ = unix.Close(nfd) }()
	}
	e := next(t, s, 5*time.Second, func(n *events.Net) bool {
		return n.PID == self() && n.Type == events.TypeAccept && int(n.Local.Port()) == port
	})
	if e == nil {
		for _, a := range s.Attachments() {
			t.Logf("attached: %s (%s)", a.Program, a.Hook)
		}
		t.Fatal("no accept event for a server that was blocked in accept() before the sensor attached")
	}
}
