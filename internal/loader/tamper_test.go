// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/events"
)

// loadAsAgent loads the sensor with the test binary as the agent: its own
// events are not reported, anyone else's are.
func loadAsAgent(t *testing.T, opts Options) *Sensor {
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
	return s
}

// Signals sent to the agent by another process are reported, with the
// sender as the subject; the agent's own signals, which Go sends to its
// threads all the time, are not.
func TestSignalToAgent(t *testing.T) {
	s := loadAsAgent(t, Options{})
	if !s.Available(events.TypeSignal) {
		t.Skip("security_task_kill cannot be hooked on this kernel")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/kill", "-CONT", fmt.Sprint(os.Getpid()))
	if err := cmd.Run(); err != nil {
		t.Fatalf("kill -CONT: %v", err)
	}
	sender := uint32(cmd.Process.Pid)

	got := next(t, s, 5*time.Second, func(e *events.Signal) bool { return e.TargetPID == self() })
	if got == nil {
		t.Fatal("no signal event")
	}
	if got.PID != sender || got.Signal != uint32(syscall.SIGCONT) || got.TargetStartNS != s.Self().StartNS {
		t.Errorf("signal event %+v, want SIGCONT from %d", got, sender)
	}
	if e := next(t, s, time.Second, func(e *events.Signal) bool { return e.PID == self() }); e != nil {
		t.Errorf("the agent's signal to itself was reported: %+v", e)
	}
}

// Only the agent's own process is ignored, not its cgroup: a child in the
// same cgroup, as a process moved there would be (E15), is reported, and the
// agent's own connect is not.
func TestAgentIgnoredByProcessNotCgroup(t *testing.T) {
	s := loadAsAgent(t, Options{})

	cmd := exec.Command("/bin/true", "tephra-e15")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	child := uint32(cmd.Process.Pid)
	if e := next(t, s, 5*time.Second, func(e *events.Exec) bool { return e.PID == child }); e == nil {
		t.Error("exec of a process in the agent's cgroup was not reported")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if e := next(t, s, time.Second, func(e *events.Net) bool { return e.PID == self() }); e != nil {
		t.Errorf("the agent's own connect was reported: %+v", e)
	}
}

// An agent that ends without unpinning, as a killed one does, leaves the
// detection programs recording into the pinned ring buffer. The next agent
// adopts it, reads what happened in between, and replaces the links. A
// planned stop unpins everything.
func TestDetectionSurvivesAgent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	dir := fmt.Sprintf("/sys/fs/bpf/tephra-detect-test-%d", os.Getpid())
	t.Cleanup(func() { unpinAll(dir) })
	opts := Options{RingBufSize: 1 << 20, KeepRecording: true, DetectPinDir: dir}

	first, err := Load(opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !first.KeepsRecording() || first.Backlog() {
		t.Fatalf("first agent: keeps recording %v, backlog %v", first.KeepsRecording(), first.Backlog())
	}
	// A killed agent's descriptors are closed by the kernel; Close does
	// the same and unpins nothing.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"events", "stats", "link_tephra_exec", "link_tephra_signal"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not pinned after the agent ended: %v", name, err)
		}
	}

	// Happens while no agent runs.
	cmd := exec.Command("/bin/true", "tephra-while-down")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	child := uint32(cmd.Process.Pid)

	second := loadAsAgent(t, opts)
	if !second.Backlog() {
		t.Fatalf("second agent did not adopt the ring buffer (fresh start: %q)", second.FreshStart())
	}
	e := next(t, second, 5*time.Second, func(e *events.Exec) bool { return e.PID == child })
	if e == nil {
		t.Fatal("the exec done while no agent ran was not read by the next one")
	}
	if len(e.Argv) < 2 || e.Argv[1] != "tephra-while-down" {
		t.Errorf("argv %q", e.Argv)
	}

	// A planned stop: nothing is left behind.
	second.UnpinDetection()
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(dir)
		t.Errorf("pins left after a planned stop: %v", entries)
	}
}

// Without KeepRecording, whatever an earlier agent left pinned is removed.
func TestDetectionNotKept(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	dir := fmt.Sprintf("/sys/fs/bpf/tephra-detect-test-%d-off", os.Getpid())
	t.Cleanup(func() { unpinAll(dir) })
	first, err := Load(Options{RingBufSize: 1 << 20, KeepRecording: true, DetectPinDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	second := loadAsAgent(t, Options{DetectPinDir: dir})
	if second.KeepsRecording() || second.Backlog() {
		t.Errorf("keeps recording %v, backlog %v", second.KeepsRecording(), second.Backlog())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("pins of the earlier agent left: %v", err)
	}
	if ok, err := DetectionOff(dir); ok || err != nil {
		t.Errorf("DetectionOff on nothing: %v %v", ok, err)
	}
}
