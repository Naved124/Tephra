// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/filter"
)

// The tests below refuse real actions. They run as root in the lab VM only
// (make test-root), in a cgroup of their own; nothing outside that cgroup is
// ever refused, and every test switches enforcement off and unpins before
// it ends.

// Exit codes of the child.
const (
	childWentAhead   = 0
	childRefused     = 13
	childFailed      = 3
	childUnsupported = 4
)

var errUnsupported = errors.New("not supported by this kernel")

const childEnv = "TEPHRA_ENFORCE_CHILD"

// TestEnforceChild is not a test: it is the process that tries an action,
// started by the tests below with the action in the environment.
func TestEnforceChild(t *testing.T) {
	action := os.Getenv(childEnv)
	if action == "" {
		t.Skip("helper process")
	}
	err := tryAction(action, os.Getenv(childEnv+"_ARG"))
	switch {
	case err == nil:
		os.Exit(childWentAhead)
	case errors.Is(err, unix.EPERM):
		os.Exit(childRefused)
	case errors.Is(err, errUnsupported):
		os.Exit(childUnsupported)
	default:
		fmt.Fprintln(os.Stderr, action+":", err)
		os.Exit(childFailed)
	}
}

func tryAction(action, arg string) error {
	switch action {
	case "write":
		f, err := os.OpenFile(arg, os.O_WRONLY, 0)
		if err == nil {
			_ = f.Close()
		}
		return err
	case "read":
		f, err := os.Open(arg)
		if err == nil {
			_ = f.Close()
		}
		return err
	case "ptrace":
		target := exec.Command("sleep", "5")
		if err := target.Start(); err != nil {
			return err
		}
		defer func() { _ = target.Process.Kill(); _ = target.Wait() }()
		if err := unix.PtraceAttach(target.Process.Pid); err != nil {
			return err
		}
		var ws unix.WaitStatus
		_, _ = unix.Wait4(target.Process.Pid, &ws, unix.WALL, nil)
		return unix.PtraceDetach(target.Process.Pid)
	case "mount":
		if err := unix.Mount("none", arg, "tmpfs", 0, ""); err != nil {
			return err
		}
		return unix.Unmount(arg, 0)
	case "memfd":
		fd, err := unix.MemfdCreate("payload", 0)
		if err != nil {
			return err
		}
		src, err := os.Open("/bin/true")
		if err != nil {
			return err
		}
		mem := os.NewFile(uintptr(fd), "memfd")
		if _, err := io.Copy(mem, src); err != nil {
			return err
		}
		// Replaces this process with /bin/true, which exits 0.
		return unix.Exec("/proc/self/fd/"+strconv.Itoa(fd), []string{"true"}, nil)
	case "module":
		// Not a module: the kernel reads it and rejects it, unless the
		// read itself is refused first.
		f, err := os.Open("/bin/true")
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		err = unix.FinitModule(int(f.Fd()), "", 0)
		if err != nil && !errors.Is(err, unix.EPERM) {
			return nil
		}
		return err
	case "module-compressed":
		// The same, as a compressed module: the kernel reads it under
		// another ID, and decompresses it itself (6.4 and later).
		f, err := os.Open("/bin/true")
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		const moduleInitCompressedFile = 4
		err = unix.FinitModule(int(f.Fd()), "", moduleInitCompressedFile)
		switch {
		case errors.Is(err, unix.EINVAL):
			return errUnsupported
		case err != nil && !errors.Is(err, unix.EPERM):
			return nil
		}
		return err
	}
	return fmt.Errorf("unknown action %q", action)
}

// enforceLab is a cgroup for the children, a watched file and a mount
// point.
type enforceLab struct {
	cgroupDir string
	cgroupFD  int
	cgroupID  uint64
	file      string
	mountDir  string
}

func newEnforceLab(t *testing.T) *enforceLab {
	t.Helper()
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("needs cgroup v2")
	}
	l := &enforceLab{cgroupDir: fmt.Sprintf("/sys/fs/cgroup/tephra-enforce-test-%d", os.Getpid())}
	if err := os.Mkdir(l.cgroupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Empty once the children have exited.
		for i := 0; i < 50; i++ {
			if os.Remove(l.cgroupDir) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Errorf("cgroup %s left behind", l.cgroupDir)
	})
	var st syscall.Stat_t
	if err := syscall.Stat(l.cgroupDir, &st); err != nil {
		t.Fatal(err)
	}
	l.cgroupID = st.Ino
	fd, err := unix.Open(l.cgroupDir, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	l.cgroupFD = fd
	t.Cleanup(func() { _ = unix.Close(fd) })

	dir := t.TempDir()
	l.file = filepath.Join(dir, "blocked")
	if err := os.WriteFile(l.file, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l.mountDir = filepath.Join(dir, "mnt")
	if err := os.Mkdir(l.mountDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *enforceLab) filters() filter.Set {
	return filter.Set{Watches: []filter.Watch{{Kind: filter.Exact, Path: l.file, Bits: filter.Write | filter.Block}}}
}

// run starts the child for one action, in the lab cgroup or (inCgroup
// false) in the test's own, and returns its exit code.
func (l *enforceLab) run(t *testing.T, action string, inCgroup bool) int {
	t.Helper()
	arg := ""
	switch action {
	case "write", "read":
		arg = l.file
	case "mount":
		arg = l.mountDir
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestEnforceChild$")
	cmd.Env = append(os.Environ(), childEnv+"="+action, childEnv+"_ARG="+arg)
	cmd.Stderr = os.Stderr
	if inCgroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: l.cgroupFD}
	}
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	}
	t.Fatalf("%s: %v", action, err)
	return -1
}

var blockable = []struct {
	action string
	id     uint32
}{
	{"write", ActionFileWrite},
	{"ptrace", ActionPtrace},
	{"mount", ActionMount},
	{"memfd", ActionExecUnlinked},
	{"module", ActionModule},
	{"module-compressed", ActionModule},
}

func allActions() []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, b := range blockable {
		if !seen[b.id] {
			seen[b.id] = true
			out = append(out, b.id)
		}
	}
	return out
}

func requireEnforcement(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	if ok, why := LSMActive(); !ok {
		t.Skip(why)
	}
}

// enforceEvents drains the ring buffer and returns the enforce events of a
// cgroup by action name.
func enforceEvents(t *testing.T, s *Sensor, cgroup uint64) map[string][]*events.Enforce {
	t.Helper()
	out := map[string][]*events.Enforce{}
	for {
		s.Events().SetDeadline(time.Now().Add(300 * time.Millisecond))
		rec, err := s.Events().Read()
		if err != nil {
			return out
		}
		ev, err := events.Decode(rec.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if e, ok := ev.(*events.Enforce); ok && e.CgroupID == cgroup {
			out[e.Action] = append(out[e.Action], e)
		}
	}
}

func loadEnforcing(t *testing.T, l *enforceLab, opts Options) *Sensor {
	t.Helper()
	opts.RingBufSize = 1 << 20
	opts.Enforce = true
	opts.Filters = l.filters()
	s, err := Load(opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ok, why := s.EnforcementAvailable(); !ok {
		_ = s.Close()
		t.Fatalf("enforcement not available: %s; attached %+v, skipped %+v", why, s.Attachments(), s.Skipped())
	}
	t.Cleanup(func() {
		_, _ = s.SetEnforcement(EnforceOff, nil)
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := s.SetProtectCgroups(nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnforceCgroups([]uint64{l.cgroupID}); err != nil {
		t.Fatal(err)
	}
	return s
}

// The six programs pass the verifier and attach, and every action of the
// first blockable set can be enforced.
func TestEnforceAttach(t *testing.T) {
	requireEnforcement(t)
	l := newEnforceLab(t)
	s := loadEnforcing(t, l, Options{})
	n := 0
	for _, a := range s.Attachments() {
		if _, ok := lsmActions[a.Program]; ok {
			n++
		}
	}
	if n != len(lsmActions) {
		t.Errorf("%d enforcement programs attached, want %d: %+v, skipped %+v", n, len(lsmActions), s.Attachments(), s.Skipped())
	}
	in, err := s.SetEnforcement(EnforceDryRun, allActions())
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != len(allActions()) {
		t.Errorf("actions in force %v, want all of %v", in, allActions())
	}
	if !s.Available(events.TypeEnforce) {
		t.Error("enforce event type not available")
	}
}

// Off, dry-run and on, inside and outside the enforced cgroup.
func TestEnforceModes(t *testing.T) {
	requireEnforcement(t)
	l := newEnforceLab(t)
	s := loadEnforcing(t, l, Options{})

	for _, tc := range []struct {
		mode     uint32
		name     string
		want     int
		inCgroup bool
		// whether an enforce event is expected, and its denied flag
		event, denied bool
	}{
		{EnforceOff, "off", childWentAhead, true, false, false},
		{EnforceDryRun, "dry-run", childWentAhead, true, true, false},
		{EnforceOn, "on", childRefused, true, true, true},
		{EnforceOn, "on, outside the enforced cgroup", childWentAhead, false, false, false},
	} {
		if _, err := s.SetEnforcement(tc.mode, allActions()); err != nil {
			t.Fatal(err)
		}
		enforceEvents(t, s, l.cgroupID) // drain
		unsupported := map[string]bool{}
		for _, b := range blockable {
			got := l.run(t, b.action, tc.inCgroup)
			if got == childUnsupported {
				unsupported[b.action] = true
				continue
			}
			if got != tc.want {
				t.Errorf("%s: %s exited %d, want %d", tc.name, b.action, got, tc.want)
			}
		}
		// Reading the watched file is never refused.
		if got := l.run(t, "read", tc.inCgroup); got != childWentAhead {
			t.Errorf("%s: read exited %d, want %d", tc.name, got, childWentAhead)
		}
		evs := enforceEvents(t, s, l.cgroupID)
		for _, b := range blockable {
			if b.action == "module-compressed" {
				// Same action name as module; counted there.
				continue
			}
			name := events.EnforceActions[b.id]
			got := evs[name]
			switch {
			case !tc.event && len(got) > 0:
				t.Errorf("%s: %s: unexpected enforce event %+v", tc.name, b.action, got[0])
			case tc.event && len(got) == 0:
				t.Errorf("%s: %s: no enforce event", tc.name, b.action)
			case tc.event && got[0].Denied() != tc.denied:
				t.Errorf("%s: %s: denied %v, want %v", tc.name, b.action, got[0].Denied(), tc.denied)
			}
			if b.action == "write" && tc.event && len(got) > 0 && got[0].Path != l.file {
				t.Errorf("%s: write event path %q, want %q", tc.name, got[0].Path, l.file)
			}
		}
	}
}

// Pinned, refusal outlives the agent; a new agent adopts it; the kill
// switch ends it without an agent.
func TestEnforcePinned(t *testing.T) {
	requireEnforcement(t)
	l := newEnforceLab(t)
	dir := fmt.Sprintf("/sys/fs/bpf/tephra-test-%d", os.Getpid())
	t.Cleanup(func() { unpinAll(dir) })

	first, err := Load(Options{RingBufSize: 1 << 20, Enforce: true, Filters: l.filters(), PinDir: dir, Pin: true})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := first.SetProtectCgroups(nil); err != nil {
		t.Fatal(err)
	}
	if err := first.SetEnforceCgroups([]uint64{l.cgroupID}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.SetEnforcement(EnforceOn, []uint32{ActionMount}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, "mount", true); got != childRefused {
		t.Errorf("after the agent closed: mount exited %d, want %d (refused by the pinned programs)", got, childRefused)
	}
	mode, actions, pinned, err := PinnedEnforcement(dir)
	if err != nil || !pinned || mode != EnforceOn || actions != 1<<ActionMount {
		t.Errorf("pinned state: mode %d actions %#x pinned %v err %v", mode, actions, pinned, err)
	}

	second, err := Load(Options{RingBufSize: 1 << 20, Enforce: true, Filters: l.filters(), PinDir: dir, Pin: true})
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if mode, actions := second.Enforcement(); mode != EnforceOn || actions != 1<<ActionMount {
		t.Errorf("second agent adopted mode %d actions %#x", mode, actions)
	}
	if got := l.run(t, "mount", true); got != childRefused {
		t.Errorf("with the second agent: mount exited %d, want %d", got, childRefused)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	ok, err := KillSwitch(dir)
	if !ok || err != nil {
		t.Fatalf("KillSwitch: %v %v", ok, err)
	}
	if got := l.run(t, "mount", true); got != childWentAhead {
		t.Errorf("after the kill switch: mount exited %d, want %d", got, childWentAhead)
	}
}

// forkMount is a Python program that forks, mounts a tmpfs in the child
// without executing anything, and exits with the child's status: 0 if the
// mount went ahead, 13 if it was refused.
const forkMount = `
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
pid = os.fork()
if pid == 0:
    if libc.mount(b"none", sys.argv[1].encode(), b"tmpfs", 0, None) != 0:
        os._exit(13 if ctypes.get_errno() == 1 else 3)
    libc.umount(sys.argv[1].encode())
    os._exit(0)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
`

// The container runtime sets a container up in processes it forks after
// executing its own copy, and those must be let through: runc's init forks
// the stage that mounts the root filesystem. Here /usr/bin/env stands in for
// the runtime: it executes Python, which forks a child that mounts.
func TestEnforceRuntimeFork(t *testing.T) {
	requireEnforcement(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3")
	}
	l := newEnforceLab(t)
	s := loadEnforcing(t, l, Options{})
	var st unix.Stat_t
	if err := unix.Stat("/usr/bin/env", &st); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRuntimeFiles([]FileID{{Dev: KernelDev(unix.Major(st.Dev), unix.Minor(st.Dev)), Inode: st.Ino}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetEnforcement(EnforceOn, []uint32{ActionMount}); err != nil {
		t.Fatal(err)
	}
	run := func(argv ...string) int {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: l.cgroupFD}
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	}
	if got := run("/usr/bin/env", python, "-c", forkMount, l.mountDir); got != childWentAhead {
		t.Errorf("fork of the runtime's child: mount exited %d, want %d", got, childWentAhead)
	}
	if got := run(python, "-c", forkMount, l.mountDir); got != childRefused {
		t.Errorf("fork of an ordinary process: mount exited %d, want %d", got, childRefused)
	}
	// What the runtime's child executes next is the container's program,
	// and is on its own again.
	if got := run("/usr/bin/env", "/bin/sh", "-c", "exec "+python+" -c '"+strings.ReplaceAll(forkMount, "'", `'"'"'`)+"' "+l.mountDir); got != childRefused {
		t.Errorf("after the runtime's child executed a program: mount exited %d, want %d", got, childRefused)
	}
}
