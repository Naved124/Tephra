// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/filter"
)

// loadBlind loads the sensor as the agent with blind mode and no
// enforcement, the lab cgroup standing in for the node's pod root.
func loadBlind(t *testing.T, l *enforceLab, mode uint32) *Sensor {
	t.Helper()
	s, err := Load(Options{
		RingBufSize: 1 << 20,
		Blind:       true,
		Filters:     filter.Set{Watches: []filter.Watch{{Kind: filter.Exact, Path: l.file, Bits: filter.BlindRead | filter.BlindWrite}}},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ok, why := s.BlindAvailable(); !ok {
		_ = s.Close()
		t.Fatalf("blind mode not available: %s", why)
	}
	if ok, _ := s.EnforcementAvailable(); ok {
		t.Error("enforcement available without being enabled")
	}
	t.Cleanup(func() {
		_, _ = s.SetBlind(BlindOff, nil, 0)
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := s.SetBlindCgroups([]uint64{l.cgroupID}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlindProtect(nil); err != nil {
		t.Fatal(err)
	}
	actions := []uint32{ActionExecUnlinked, ActionFileRead, ActionFileWrite, ActionPtrace, ActionMount}
	in, err := s.SetBlind(mode, actions, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != len(actions) {
		t.Fatalf("blind actions in force %v, want %v", in, actions)
	}
	return s
}

// boot is the kernel's boot clock, which the heartbeat is written in.
func boot(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

// The sensor is blind when its heartbeat is stale: the kernel then refuses
// the blind-mode actions to processes in pods, whatever the enforcement
// mode, records each refusal in the tamper buffer, and stops when a newer
// heartbeat arrives. Processes outside pods, and protected pods, are never
// refused.
func TestBlindMode(t *testing.T) {
	requireEnforcement(t)
	l := newEnforceLab(t)
	s := loadBlind(t, l, BlindOn)
	now := func() uint64 { return boot(t) }

	if err := s.Heartbeat(now()); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"read", "write"} {
		if got := l.run(t, a, true); got != childWentAhead {
			t.Errorf("%s with a fresh heartbeat: exit %d, want it to go ahead", a, got)
		}
	}

	// Stale: the agent has not been heard from for longer than 3 s.
	if err := s.Heartbeat(now() - uint64(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"read", "write", "mount", "ptrace", "memfd"} {
		if got := l.run(t, a, true); got != childRefused {
			t.Errorf("%s while blind: exit %d, want refused", a, got)
		}
	}
	got := nextTamper(t, s, 5*time.Second, func(e *events.Enforce) bool { return e.Action == "file_read" })
	if got == nil {
		t.Fatal("no record of the refused read in the tamper buffer")
	}
	if !got.Blind() || !got.Denied() || got.Path != l.file || got.CgroupID != l.cgroupID {
		t.Errorf("refusal record %+v: want blind, denied, %s, cgroup %d", got, l.file, l.cgroupID)
	}
	// Nothing went to the main buffer, which a flood could fill.
	if e := next(t, s, time.Second, func(*events.Enforce) bool { return true }); e != nil {
		t.Errorf("blind refusal sent to the main ring buffer: %+v", e)
	}

	// The node's own processes are never refused.
	if got := l.run(t, "read", false); got != childWentAhead {
		t.Errorf("read outside a pod while blind: exit %d, want it to go ahead", got)
	}
	// Nor are protected pods.
	if err := s.SetBlindProtect([]uint64{l.cgroupID}); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, "read", true); got != childWentAhead {
		t.Errorf("read in a protected pod while blind: exit %d, want it to go ahead", got)
	}
	if err := s.SetBlindProtect(nil); err != nil {
		t.Fatal(err)
	}

	// A heartbeat ends it.
	if err := s.Heartbeat(now()); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, "read", true); got != childWentAhead {
		t.Errorf("read after a fresh heartbeat: exit %d, want it to go ahead", got)
	}

	// Off: nothing is refused, however stale.
	if _, err := s.SetBlind(BlindOff, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat(now() - uint64(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, "read", true); got != childWentAhead {
		t.Errorf("read with blind mode off: exit %d, want it to go ahead", got)
	}
}

// Dry-run reports what blind mode would refuse and refuses nothing.
func TestBlindDryRun(t *testing.T) {
	requireEnforcement(t)
	l := newEnforceLab(t)
	s := loadBlind(t, l, BlindDryRun)
	if err := s.Heartbeat(1); err != nil { // long stale
		t.Fatal(err)
	}
	if got := l.run(t, "read", true); got != childWentAhead {
		t.Errorf("read in blind dry-run: exit %d, want it to go ahead", got)
	}
	got := nextTamper(t, s, 5*time.Second, func(e *events.Enforce) bool { return e.Action == "file_read" })
	if got == nil || !got.Blind() || got.Denied() {
		t.Fatalf("dry-run record %+v: want blind, not denied", got)
	}
}

// A stop signal to the agent blinds the sensor at once, before the signal
// is delivered and without waiting for the heartbeat to go stale; a newer
// heartbeat ends it. The test process is the agent, so it ignores SIGTTOU,
// which still passes the kernel's check that the hook sits on.
func TestBlindOnStopSignal(t *testing.T) {
	requireEnforcement(t)
	l := newEnforceLab(t)
	s := loadBlind(t, l, BlindOn)
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	if err := s.Heartbeat(boot(t)); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, "read", true); got != childWentAhead {
		t.Fatalf("read before the signal: exit %d, want it to go ahead", got)
	}
	if out, err := exec.Command("/bin/kill", "-TTOU", fmt.Sprint(os.Getpid())).CombinedOutput(); err != nil {
		t.Fatalf("kill -TTOU: %v %s", err, out)
	}
	hb, down, err := s.BlindTimes()
	if err != nil {
		t.Fatal(err)
	}
	if down <= hb {
		t.Fatalf("down %d not after heartbeat %d: the stop signal did not blind the sensor", down, hb)
	}
	if got := l.run(t, "read", true); got != childRefused {
		t.Errorf("read after a stop signal to the agent: exit %d, want refused", got)
	}
	if err := s.Heartbeat(boot(t)); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, "read", true); got != childWentAhead {
		t.Errorf("read after the next heartbeat: exit %d, want it to go ahead", got)
	}
}

// While blind, the runtime still starts containers: runc's init forks the
// stage that mounts the container's root, and that child must keep the
// runtime's mark. On the lab it did not, every pod sandbox on the node failed
// with "mount dst=/ ... operation not permitted", and the next agent could
// not start to end the blindness. An ordinary process's fork is refused.
func TestBlindRuntimeFork(t *testing.T) {
	requireEnforcement(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3")
	}
	l := newEnforceLab(t)
	s := loadBlind(t, l, BlindOn)
	var st unix.Stat_t
	if err := unix.Stat("/usr/bin/env", &st); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRuntimeFiles([]FileID{{Dev: KernelDev(unix.Major(st.Dev), unix.Minor(st.Dev)), Inode: st.Ino}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat(boot(t) - uint64(10*time.Second)); err != nil {
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
		t.Errorf("while blind, the runtime's forked child: mount exited %d, want it to go ahead", got)
	}
	if got := run(python, "-c", forkMount, l.mountDir); got != childRefused {
		t.Errorf("while blind, an ordinary process's fork: mount exited %d, want refused", got)
	}
}

// The kill switch ends blind mode as well as enforcement, from the pins and
// with no agent: the way out for a node where no agent can run.
func TestBlindKillSwitch(t *testing.T) {
	requireEnforcement(t)
	l := newEnforceLab(t)
	dir := fmt.Sprintf("/sys/fs/bpf/tephra-blind-test-%d", os.Getpid())
	t.Cleanup(func() { unpinAll(dir) })
	s, err := Load(Options{RingBufSize: 1 << 20, Blind: true, PinDir: dir,
		Filters: filter.Set{Watches: []filter.Watch{{Kind: filter.Exact, Path: l.file, Bits: filter.BlindRead}}}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.SetBlindCgroups([]uint64{l.cgroupID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetBlind(BlindOn, []uint32{ActionFileRead}, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat(1); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, "read", true); got != childRefused {
		t.Fatalf("read while blind: exit %d, want refused", got)
	}
	if ok, err := KillSwitch(dir); !ok || err != nil {
		t.Fatalf("KillSwitch: %v %v", ok, err)
	}
	if got := l.run(t, "read", true); got != childWentAhead {
		t.Errorf("read after the kill switch: exit %d, want it to go ahead", got)
	}
}
