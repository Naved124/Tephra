// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// Runs unprivileged: it only inspects the embedded object.
func TestEmbeddedSpec(t *testing.T) {
	spec, err := loadExec()
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
	if stats.ValueSize != 32 {
		t.Errorf("stats value size = %d, want 32 (4 x u64)", stats.ValueSize)
	}
}

// Needs root (or CAP_BPF and CAP_PERFMON): loads and attaches for real, then
// checks that an exec is counted.
func TestLoadAndCount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}

	s, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	if got := len(s.Attachments()); got != 1 {
		t.Fatalf("attachments = %d, want 1", got)
	}

	before, err := s.ReadStats(EventExec)
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.StartProcess("/bin/true", []string{"true"}, &os.ProcAttr{})
	if err != nil {
		t.Fatalf("start /bin/true: %v", err)
	}
	if _, err := p.Wait(); err != nil {
		t.Fatal(err)
	}
	after, err := s.ReadStats(EventExec)
	if err != nil {
		t.Fatal(err)
	}
	if after.Seen <= before.Seen {
		t.Errorf("exec seen counter did not increase: before %d, after %d", before.Seen, after.Seen)
	}
}
