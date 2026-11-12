// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/Naved124/tephra/internal/events"
)

// Runs unprivileged: it only inspects the embedded object.
func TestEmbeddedSpec(t *testing.T) {
	spec, err := loadTephra()
	if err != nil {
		t.Fatalf("load embedded spec: %v", err)
	}

	prog, ok := spec.Programs["tephra_exec"]
	if !ok {
		t.Fatalf("program tephra_exec not in spec; have %v", spec.Programs)
	}
	if prog.Type != ebpf.Tracing {
		t.Errorf("program type = %v, want Tracing", prog.Type)
	}
	if prog.AttachType != ebpf.AttachTraceRawTp {
		t.Errorf("attach type = %v, want TraceRawTp", prog.AttachType)
	}
	if prog.AttachTo != "sched_process_exec" {
		t.Errorf("attach target = %q, want sched_process_exec", prog.AttachTo)
	}
	// Most helpers need a GPL-compatible program licence.
	if prog.License != "GPL" {
		t.Errorf("licence = %q, want GPL", prog.License)
	}

	stats, ok := spec.Maps["stats"]
	if !ok {
		t.Fatal("map stats not in spec")
	}
	if stats.Type != ebpf.PerCPUArray {
		t.Errorf("stats map type = %v, want PerCPUArray", stats.Type)
	}
	for _, name := range []string{"tephra_fork", "tephra_exit", "tephra_self", "tephra_connect", "tephra_accept", "tephra_accept_v1", "tephra_accept_v2", "tephra_file_open"} {
		if _, ok := spec.Programs[name]; !ok {
			t.Errorf("program %s not in spec", name)
		}
	}
	if stats.ValueSize != 32 {
		t.Errorf("stats value size = %d, want 32 (4 x u64)", stats.ValueSize)
	}
}

// Needs root (or CAP_BPF and CAP_PERFMON): loads and attaches for real, runs a
// process, and expects its exec, with fork before it and exit after it, on the
// ring buffer.
func TestLoadAndObserve(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}

	s, err := Load(Options{RingBufSize: 1 << 20})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	// Three lifecycle hooks, connect, accept, file_open, the five
	// file_change hooks, refused opens and the seven privilege and tamper
	// hooks.
	if got := len(s.Attachments()); got != 19 {
		t.Fatalf("attachments = %d, want 19: %+v, skipped %+v", got, s.Attachments(), s.Skipped())
	}
	for _, typ := range events.Types {
		if !s.Available(typ) || !s.Enabled(typ) {
			t.Errorf("%s: available %v, enabled %v", typ, s.Available(typ), s.Enabled(typ))
		}
	}
	if s.Self().CgroupID == 0 || s.Self().PidNSInum == 0 {
		t.Errorf("self not resolved: %+v", s.Self())
	}

	// The test binary shares the agent's cgroup, which is ignored. Lift
	// that so the child below is visible.
	if err := s.coll.Maps["cgroup_ignore"].Delete(s.Self().CgroupID); err != nil {
		t.Fatalf("clear cgroup_ignore: %v", err)
	}

	cmd := exec.Command("/bin/true", "tephra-marker", "second arg")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run /bin/true: %v", err)
	}
	child := uint32(cmd.Process.Pid)

	var sawFork, sawExec, sawExit bool
	var key uint64
	deadline := time.Now().Add(5 * time.Second)
	for !sawExit {
		s.Events().SetDeadline(deadline)
		rec, err := s.Events().Read()
		if err != nil {
			t.Fatalf("read ring buffer (fork %v, exec %v, exit %v): %v", sawFork, sawExec, sawExit, err)
		}
		ev, err := events.Decode(rec.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		switch e := ev.(type) {
		case *events.Fork:
			if e.ChildPID != child {
				continue
			}
			sawFork = true
			key = e.ChildStartNS
			if e.PID != uint32(os.Getpid()) || e.ParentPID != uint32(os.Getpid()) {
				t.Errorf("fork: forker %d parent %d, want both %d", e.PID, e.ParentPID, os.Getpid())
			}
		case *events.Exec:
			if e.PID != child {
				continue
			}
			sawExec = true
			if !sawFork {
				t.Error("exec arrived before fork")
			}
			if e.Path != "/bin/true" {
				t.Errorf("exec path = %q, want /bin/true", e.Path)
			}
			if want := []string{"/bin/true", "tephra-marker", "second arg"}; !reflect.DeepEqual(e.Argv, want) {
				t.Errorf("exec argv = %q, want %q", e.Argv, want)
			}
			if e.StartTimeNS != key {
				t.Errorf("exec start time %d differs from fork's %d", e.StartTimeNS, key)
			}
			if e.PPID != uint32(os.Getpid()) || e.UID != 0 || e.Inode == 0 || e.CgroupID != s.Self().CgroupID {
				t.Errorf("exec header/payload wrong: %+v", e)
			}
			if e.Flags&(events.ExecUnlinked|events.ExecArgvTrunc) != 0 {
				t.Errorf("exec flags = %#x, want neither unlinked nor truncated", e.Flags)
			}
		case *events.Exit:
			if e.PID != child {
				continue
			}
			sawExit = true
			if !sawExec {
				t.Error("exit arrived before exec")
			}
			if e.StartTimeNS != key || e.Code() != 0 {
				t.Errorf("exit: start %d (want %d), code %d (want 0)", e.StartTimeNS, key, e.Code())
			}
		}
	}

	// Each seen event ends in exactly one of the three outcomes. Nothing
	// else on the machine is stopped, so allow a few reads for a
	// consistent snapshot.
	for _, typ := range events.Types {
		var st Stats
		ok := false
		for i := 0; i < 20 && !ok; i++ {
			if st, err = s.ReadStats(typ); err != nil {
				t.Fatal(err)
			}
			ok = st.Seen == st.Filtered+st.Emitted+st.Dropped
		}
		lifecycle := typ == events.TypeExec || typ == events.TypeFork || typ == events.TypeExit
		if !ok || (lifecycle && st.Seen == 0) {
			t.Errorf("%s stats inconsistent: %+v", typ, st)
		}
	}
}

// A "#!" script must be reported as its interpreter, so that rules matching
// on shells cannot be sidestepped by wrapping the shell in a script.
func TestScriptExecReportsInterpreter(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	s, err := Load(Options{RingBufSize: 1 << 20})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.coll.Maps["cgroup_ignore"].Delete(s.Self().CgroupID); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(t.TempDir(), "innocent-name")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script, "arg")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.Events().SetDeadline(deadline)
		rec, err := s.Events().Read()
		if err != nil {
			t.Fatalf("exec event not seen: %v", err)
		}
		ev, err := events.Decode(rec.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		e, ok := ev.(*events.Exec)
		if !ok || e.PID != uint32(cmd.Process.Pid) {
			continue
		}
		if e.Path != "/bin/sh" {
			t.Errorf("path = %q, want the interpreter /bin/sh", e.Path)
		}
		if want := []string{"/bin/sh", script, "arg"}; !reflect.DeepEqual(e.Argv, want) {
			t.Errorf("argv = %q, want %q", e.Argv, want)
		}
		return
	}
}

// An argv longer than the capture limit is cut and flagged.
func TestArgvTruncation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	s, err := Load(Options{RingBufSize: 1 << 20})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.coll.Maps["cgroup_ignore"].Delete(s.Self().CgroupID); err != nil {
		t.Fatal(err)
	}

	long := strings.Repeat("x", 3000)
	cmd := exec.Command("/bin/true", long, "tail")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.Events().SetDeadline(deadline)
		rec, err := s.Events().Read()
		if err != nil {
			t.Fatalf("exec event not seen: %v", err)
		}
		ev, err := events.Decode(rec.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		e, ok := ev.(*events.Exec)
		if !ok || e.PID != uint32(cmd.Process.Pid) {
			continue
		}
		if e.Flags&events.ExecArgvTrunc == 0 {
			t.Error("truncation flag not set")
		}
		total := 0
		for _, a := range e.Argv {
			total += len(a) + 1
		}
		// 1024 bytes captured; the cut argument has no terminator.
		if total != 1025 || len(e.Argv) != 2 || e.Argv[0] != "/bin/true" {
			t.Errorf("captured %d args, %d bytes; want 2 args, 1024 bytes", len(e.Argv), total-1)
		}
		return
	}
}
