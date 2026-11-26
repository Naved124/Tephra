// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/tephrasec/tephra/internal/events"
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

	got := nextTamper(t, s, 5*time.Second, func(e *events.Signal) bool { return e.TargetPID == self() })
	if got == nil {
		t.Fatal("no signal event")
	}
	if got.PID != sender || got.Signal != uint32(syscall.SIGCONT) || got.TargetStartNS != s.Self().StartNS {
		t.Errorf("signal event %+v, want SIGCONT from %d", got, sender)
	}
	if e := nextTamper(t, s, time.Second, func(e *events.Signal) bool { return e.PID == self() }); e != nil {
		t.Errorf("the agent's signal to itself was reported: %+v", e)
	}
}

// E19 and E23 flood the agent before killing it. A signal to the agent goes
// to the tamper buffer, which the flood cannot fill: with the main ring
// buffer full and dropping, the record of the signal still arrives.
func TestSignalSurvivesFullRing(t *testing.T) {
	s := loadAsAgent(t, Options{RingBufSize: 4096})
	if !s.Available(events.TypeSignal) {
		t.Skip("security_task_kill cannot be hooked on this kernel")
	}
	// Nothing reads the main buffer: a few hundred process starts fill
	// its single page.
	for i := 0; i < 300; i++ {
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.ReadStats(events.TypeExec)
	if err != nil {
		t.Fatal(err)
	}
	if st.Dropped == 0 {
		t.Fatalf("the main ring buffer did not fill: %+v", st)
	}
	cmd := exec.Command("/bin/kill", "-CONT", fmt.Sprint(os.Getpid()))
	if err := cmd.Run(); err != nil {
		t.Fatalf("kill -CONT: %v", err)
	}
	got := nextTamper(t, s, 5*time.Second, func(e *events.Signal) bool { return e.TargetPID == self() })
	if got == nil {
		t.Fatalf("the signal was lost with the main buffer full (%d exec records dropped)", st.Dropped)
	}
	if got.PID != uint32(cmd.Process.Pid) {
		t.Errorf("signal from %d, want the kill process %d", got.PID, cmd.Process.Pid)
	}
}

// A record taken from the tamper buffer by an agent killed before it handled
// it is gone from the buffer (E19). The kernel also keeps it in a table until
// an agent marks it done, so the next agent can still handle it.
func TestTamperRecordKept(t *testing.T) {
	s := loadAsAgent(t, Options{})
	if !s.Available(events.TypeSignal) {
		t.Skip("security_task_kill cannot be hooked on this kernel")
	}
	cmd := exec.Command("/bin/kill", "-CONT", fmt.Sprint(os.Getpid()))
	if err := cmd.Run(); err != nil {
		t.Fatalf("kill -CONT: %v", err)
	}
	got := nextTamper(t, s, 5*time.Second, func(e *events.Signal) bool { return e.PID == uint32(cmd.Process.Pid) })
	if got == nil || got.TamperSeq == 0 {
		t.Fatalf("signal record %+v without a tamper sequence number", got)
	}
	// Read from the buffer, not yet done: still kept, byte for byte.
	pending, err := s.TamperPending()
	if err != nil {
		t.Fatal(err)
	}
	var kept *events.Signal
	for _, p := range pending {
		if p.Seq != got.TamperSeq {
			continue
		}
		ev, err := events.Decode(p.Raw)
		if err != nil {
			t.Fatal(err)
		}
		kept, _ = ev.(*events.Signal)
	}
	if kept == nil || kept.PID != got.PID || kept.Signal != got.Signal || kept.TamperSeq != got.TamperSeq {
		t.Fatalf("seq %d not kept as it was read: kept %+v, %d pending", got.TamperSeq, kept, len(pending))
	}
	if done, err := s.TamperDone(got.TamperSeq); err != nil || done {
		t.Fatalf("done %v before marking (err %v)", done, err)
	}
	if err := s.SetTamperDone(got.TamperSeq); err != nil {
		t.Fatal(err)
	}
	if done, err := s.TamperDone(got.TamperSeq); err != nil || !done {
		t.Fatalf("not done after marking (err %v)", err)
	}
	pending, err = s.TamperPending()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pending {
		if p.Seq == got.TamperSeq {
			t.Errorf("seq %d still pending after it was marked done", p.Seq)
		}
	}
}

// Even the tamper buffer can be filled, by signalling the agent thousands of
// times. Each signal that finds it full is counted in the kernel, so the
// agent still raises R030 for it; the count of what was reported is kept
// beside it.
func TestTamperLostCounted(t *testing.T) {
	s := loadAsAgent(t, Options{})
	if !s.Available(events.TypeSignal) {
		t.Skip("security_task_kill cannot be hooked on this kernel")
	}
	lost0, reported0, err := s.TamperLost(TamperSignal)
	if err != nil {
		t.Fatal(err)
	}
	// One shell sends them all; nothing reads the tamper buffer meanwhile.
	sh := exec.Command("/bin/sh", "-c", fmt.Sprintf("i=0; while [ $i -lt 8000 ]; do kill -CONT %d; i=$((i+1)); done", os.Getpid()))
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("signal loop: %v: %s", err, out)
	}
	lost, reported, err := s.TamperLost(TamperSignal)
	if err != nil {
		t.Fatal(err)
	}
	if lost <= lost0 {
		t.Fatalf("8000 signals into a 256 KiB tamper buffer lost none (lost %d)", lost)
	}
	st, err := s.ReadStats(events.TypeSignal)
	if err != nil {
		t.Fatal(err)
	}
	if st.Dropped < lost-lost0 {
		t.Errorf("signal stats dropped %d, fewer than the %d counted lost", st.Dropped, lost-lost0)
	}
	if err := s.SetTamperReported(TamperSignal, lost); err != nil {
		t.Fatal(err)
	}
	if _, r, err := s.TamperLost(TamperSignal); err != nil || r != lost {
		t.Errorf("reported count %d after setting %d (err %v; was %d)", r, lost, err, reported)
	}
	_ = reported0
	// The buffer still holds the first signals, with their sender.
	if e := nextTamper(t, s, time.Second, func(e *events.Signal) bool { return e.TargetPID == self() }); e == nil {
		t.Error("no signal record kept in the full tamper buffer")
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

// A ring buffer written in another record layout is not read: its backlog
// would decode as garbage. The next agent starts afresh and says why.
func TestDetectionOtherLayoutNotAdopted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	dir := fmt.Sprintf("/sys/fs/bpf/tephra-layout-test-%d", os.Getpid())
	t.Cleanup(func() { unpinAll(dir) })
	opts := Options{RingBufSize: 1 << 20, KeepRecording: true, DetectPinDir: dir}

	first, err := Load(opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v, ok := pinnedLayout(dir); !ok || v != events.LayoutVersion {
		t.Fatalf("layout pinned %d %v, want %d", v, ok, events.LayoutVersion)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	// As an agent of an earlier layout would have left it.
	m, err := ebpf.LoadPinnedMap(filepath.Join(dir, layoutPin), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Put(uint32(0), uint32(events.LayoutVersion-1)); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()

	second := loadAsAgent(t, opts)
	if second.Backlog() || !strings.Contains(second.FreshStart(), "record layout") {
		t.Errorf("backlog %v, fresh start %q", second.Backlog(), second.FreshStart())
	}
	if v, ok := pinnedLayout(dir); !ok || v != events.LayoutVersion {
		t.Errorf("layout after the fresh start %d %v", v, ok)
	}
}
