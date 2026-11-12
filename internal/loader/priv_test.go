// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/events"
)

const wait = 5 * time.Second

func TestPtraceAttach(t *testing.T) {
	s := loadForTest(t, Options{})
	target := exec.Command("/bin/sleep", "30")
	if err := target.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Process.Kill(); _, _ = target.Process.Wait() })
	pid := target.Process.Pid

	// ptrace requests must come from one thread.
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := syscall.PtraceAttach(pid); err != nil {
			done <- err
			return
		}
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, 0, nil)
		done <- syscall.PtraceDetach(pid)
	}()
	if err := <-done; err != nil {
		t.Fatalf("ptrace: %v", err)
	}
	e := next(t, s, wait, func(p *events.Ptrace) bool { return p.PID == self() && p.TargetPID == uint32(pid) })
	if e == nil {
		t.Fatal("no ptrace event for an attach")
	}
	if e.Mode&2 == 0 || e.TargetStartNS == 0 {
		t.Errorf("ptrace event %+v", e)
	}
}

func TestMemfdCreate(t *testing.T) {
	s := loadForTest(t, Options{})
	fd, err := unix.MemfdCreate("tephra-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	e := next(t, s, wait, func(m *events.Memfd) bool { return m.PID == self() })
	if e == nil {
		t.Fatal("no memfd event")
	}
	if e.MemfdFlags != unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING {
		t.Errorf("flags %#x", e.MemfdFlags)
	}
}

func TestBPFLoad(t *testing.T) {
	s := loadForTest(t, Options{})
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "tephra_probe",
		Type:         ebpf.SocketFilter,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = prog.Close()
	e := next(t, s, wait, func(b *events.BPFLoad) bool { return b.PID == self() && b.Name == "tephra_probe" })
	if e == nil {
		t.Fatal("no bpf_load event for a program loaded by another tool")
	}
	if e.ProgType != uint32(ebpf.SocketFilter) || e.Cmd != 5 {
		t.Errorf("bpf_load event %+v", e)
	}
}

func TestCredChange(t *testing.T) {
	s := loadForTest(t, Options{})
	// The child drops to an unprivileged user before it execs.
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 54321, Gid: 54322}}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	e := next(t, s, wait, func(c *events.CredChange) bool { return c.NewUID == 54321 })
	if e == nil {
		t.Fatal("no cred_change event for setuid")
	}
	if e.OldUID != 0 || e.NewEUID != 54321 || e.Flags&events.CredInExec != 0 || e.PPID != self() {
		t.Errorf("cred_change event %+v", e)
	}

	// A setuid binary changes credentials as part of exec.
	su, err := exec.LookPath("su")
	if err != nil {
		t.Skip("no su binary for the setuid case")
	}
	cmd = exec.Command(su, "-c", "true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	_ = cmd.Run() // fails to authenticate; the exec is what matters
	e = next(t, s, wait, func(c *events.CredChange) bool {
		return c.OldEUID == 65534 && c.NewEUID == 0 && c.Flags&events.CredInExec != 0
	})
	if e == nil {
		t.Error("no cred_change event flagged as part of an exec for a setuid binary")
	}
}

func TestMount(t *testing.T) {
	s := loadForTest(t, Options{})
	dir, err := os.MkdirTemp("/tmp", "tephra-mnt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	if err := unix.Mount("tephra", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=64k"); err != nil {
		t.Fatal(err)
	}
	_ = unix.Unmount(dir, 0)
	e := next(t, s, wait, func(m *events.Mount) bool { return m.PID == self() && m.FSType == "tmpfs" })
	if e == nil {
		t.Fatal("no mount event")
	}
	if !strings.HasSuffix(e.Target, "/"+filepath.Base(dir)) || e.MntFlags&unix.MS_NOSUID == 0 {
		t.Errorf("mount event %+v, want a target ending in %s", e, filepath.Base(dir))
	}
}

func TestNamespaceSwitch(t *testing.T) {
	s := loadForTest(t, Options{})
	var host unix.Stat_t
	if err := unix.Stat("/proc/self/ns/uts", &host); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		// The thread ends up in namespaces of its own and is thrown
		// away: it is never unlocked.
		runtime.LockOSThread()
		back, err := unix.Open("/proc/self/ns/uts", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = unix.Close(back) }()
		if err := unix.Unshare(unix.CLONE_NEWUTS); err != nil {
			done <- err
			return
		}
		done <- unix.Setns(back, unix.CLONE_NEWUTS)
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	left := next(t, s, wait, func(n *events.Setns) bool { return n.PID == self() })
	if left == nil {
		t.Fatal("no setns event for unshare")
	}
	if len(left.Changed) != 1 || left.Changed[0] != "uts" || left.Inum["uts"] == uint32(host.Ino) {
		t.Errorf("unshare event: changed %v, uts %d (host %d)", left.Changed, left.Inum["uts"], host.Ino)
	}
	entered := next(t, s, wait, func(n *events.Setns) bool { return n.PID == self() })
	if entered == nil {
		t.Fatal("no setns event for entering the host namespace")
	}
	if len(entered.Changed) != 1 || entered.Inum["uts"] != uint32(host.Ino) || entered.Inum["mnt"] == 0 {
		t.Errorf("setns event: changed %v, inums %v, want uts %d", entered.Changed, entered.Inum, host.Ino)
	}
}

func TestModuleLoad(t *testing.T) {
	s := loadForTest(t, Options{})
	if out, err := exec.Command("modprobe", "dummy").CombinedOutput(); err != nil {
		t.Skipf("cannot load the dummy module here: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("modprobe", "-r", "dummy").Run() })
	e := next(t, s, wait, func(m *events.ModuleLoad) bool { return m.Name == "dummy" })
	if e == nil {
		// Already loaded before the test: nothing was loaded now.
		t.Skip("the dummy module was already loaded")
	}
	if e.Comm != "modprobe" {
		t.Errorf("module loaded by %q", e.Comm)
	}
}

// A hook the kernel cannot take costs only its own event type.
func TestBrokenHookDisablesOnlyItself(t *testing.T) {
	brokenHook = "tephra_cred"
	t.Cleanup(func() { brokenHook = "" })
	s := loadForTest(t, Options{})

	if s.Available(events.TypeCredChange) || s.Enabled(events.TypeCredChange) {
		t.Error("cred_change is available without its hook")
	}
	found := false
	for _, sk := range s.Skipped() {
		found = found || sk.Program == "tephra_cred"
	}
	if !found {
		t.Errorf("tephra_cred not reported as skipped: %+v", s.Skipped())
	}
	for _, typ := range events.Types {
		if typ != events.TypeCredChange && (!s.Available(typ) || !s.Enabled(typ)) {
			t.Errorf("%s lost with the broken hook", typ)
		}
	}
	// And the rest still works.
	fd, err := unix.MemfdCreate("tephra-test", 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	if e := next(t, s, wait, func(m *events.Memfd) bool { return m.PID == self() }); e == nil {
		t.Error("no memfd event with another hook broken")
	}
}
