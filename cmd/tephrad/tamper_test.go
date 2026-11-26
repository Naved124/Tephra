// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/tephrasec/tephra/internal/config"
	"github.com/tephrasec/tephra/internal/enrich"
	"github.com/tephrasec/tephra/internal/events"
	"github.com/tephrasec/tephra/internal/export"
	"github.com/tephrasec/tephra/internal/k8s"
	"github.com/tephrasec/tephra/internal/loader"
	"github.com/tephrasec/tephra/internal/proctree"
	"github.com/tephrasec/tephra/internal/rules"
)

// fakeTamper stands in for the kernel's counts of lost tamper records and
// its table of the last ones.
type fakeTamper struct {
	lost     map[loader.TamperKind]uint64
	reported map[loader.TamperKind]uint64
	failSet  bool
	kept     []loader.TamperRecord
	done     map[uint64]bool
}

func (f *fakeTamper) TamperPending() ([]loader.TamperRecord, error) {
	var out []loader.TamperRecord
	for _, k := range f.kept {
		if !f.done[k.Seq] {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeTamper) TamperDone(seq uint64) (bool, error) { return f.done[seq], nil }

func (f *fakeTamper) SetTamperDone(seq uint64) error {
	if f.done == nil {
		f.done = map[uint64]bool{}
	}
	f.done[seq] = true
	return nil
}

func (f *fakeTamper) TamperLost(k loader.TamperKind) (uint64, uint64, error) {
	return f.lost[k], f.reported[k], nil
}

func (f *fakeTamper) SetTamperReported(k loader.TamperKind, n uint64) error {
	if f.failSet {
		return errors.New("map write failed")
	}
	f.reported[k] = n
	return nil
}

func tamperAgent(t *testing.T, f *fakeTamper) (*agent, *bytes.Buffer) {
	t.Helper()
	set, err := rules.Load("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	return &agent{
		c:        &counters{},
		cur:      &settings{cfg: config.Default(), rules: set},
		enricher: enrich.New("node-1", proctree.New(0, 0), proctree.ProcFS{Root: t.TempDir()}, k8s.NewCgroupResolver(t.TempDir()), nil),
		stdout:   export.NewJSONLines(out),
		tamper:   f,
		// Started long ago, on a node up for 100 s.
		tamperStart: time.Now().Add(-time.Hour),
		bootNS:      func() uint64 { return 100e9 },
	}, out
}

// tamperRaw builds a tamper record as the kernel writes it.
func tamperRaw(typ events.Type, seq, tsBoot uint64, pid, targetPID, sig uint32) []byte {
	l := events.Layout["signal_event"]
	if typ == events.TypePtrace {
		l = events.Layout["ptrace_event"]
	}
	h := events.Layout["event_hdr"].Fields
	raw := make([]byte, l.Size)
	le := binary.LittleEndian
	le.PutUint64(raw[h["ts_boot_ns"].Off:], tsBoot)
	le.PutUint32(raw[h["type"].Off:], uint32(typ))
	le.PutUint32(raw[h["size"].Off:], uint32(l.Size))
	le.PutUint32(raw[h["pid"].Off:], pid)
	le.PutUint32(raw[h["tid"].Off:], pid)
	copy(raw[h["comm"].Off:], "sh")
	le.PutUint32(raw[l.Fields["target_pid"].Off:], targetPID)
	if typ == events.TypeSignal {
		le.PutUint32(raw[l.Fields["sig"].Off:], sig)
	} else {
		le.PutUint32(raw[l.Fields["mode"].Off:], 0x2)
	}
	le.PutUint64(raw[l.Fields["tamper_seq"].Off:], seq)
	return raw
}

// E19: the agent's reader took the SIGKILL's record from the tamper buffer
// and the kill landed before the agent handled it, so no agent ever saw it.
// The kernel keeps the last tamper records in a table until an agent marks
// them done; the next agent replays what nobody handled, sender and all.
func TestTamperRecordReplayed(t *testing.T) {
	kill := tamperRaw(events.TypeSignal, 1<<12|3, 90e9, 555, 4242, uint32(syscall.SIGKILL))
	f := &fakeTamper{
		reported: map[loader.TamperKind]uint64{},
		kept: []loader.TamperRecord{
			{Seq: 1<<12 | 3, Raw: kill},
			// An attach to the old agent, also unhandled.
			{Seq: 2<<12 | 3, Raw: tamperRaw(events.TypePtrace, 2<<12|3, 91e9, 556, 4242, 0)},
			// Too young: it may still be on its way through the buffer.
			{Seq: 1<<12 | 5, Raw: tamperRaw(events.TypeSignal, 1<<12|5, 99.5e9, 557, 4242, uint32(syscall.SIGTERM))},
		},
	}
	a, out := tamperAgent(t, f)
	now := time.Now()

	// Not in the first seconds: the buffer's backlog comes first.
	a.tamperStart = now
	a.tamperTick(now)
	if got := alerts(t, a, out); len(got) != 0 {
		t.Fatalf("replayed before the backlog was read: %v", got)
	}
	a.tamperStart = now.Add(-time.Hour)

	a.tamperTick(now)
	got := alerts(t, a, out)
	sig := got["R030"]
	if sig == nil || sig.Signal == nil || sig.Signal.Name != "SIGKILL" || sig.Process.PID != 555 || sig.Signal.Lost != 0 {
		t.Fatalf("no R030 naming the SIGKILL's sender from the table: %v", got)
	}
	if got["R033"] == nil {
		t.Errorf("no R033 for the attach to the earlier agent: %v", got)
	}
	if n := a.c.tamperReplayed.Load(); n != 2 {
		t.Errorf("replayed %d, want 2 (the young one waits)", n)
	}

	// The same record through the buffer, late, is a duplicate.
	ev, err := events.Decode(kill)
	if err != nil {
		t.Fatal(err)
	}
	a.handle(ev)
	a.tamperTick(now.Add(time.Second))
	if got := alerts(t, a, out); got["R030"] != nil {
		t.Errorf("the SIGKILL raised twice in one agent: %v", got)
	}
	if a.c.tamperDuplicates.Load() != 1 {
		t.Errorf("duplicates %d, want 1", a.c.tamperDuplicates.Load())
	}
	if f.done[1<<12|3] {
		t.Error("marked done before its alert had time to leave")
	}

	// Marked done once its alert has had time to leave; the next agent
	// does not raise it again.
	a.tamperTick(now.Add(tamperDoneAfter + time.Second))
	if !f.done[1<<12|3] || !f.done[2<<12|3] {
		t.Fatalf("handled records not marked done: %v", f.done)
	}
	_ = alerts(t, a, out)
	b, outB := tamperAgent(t, f)
	b.bootNS = func() uint64 { return 90e9 }
	b.tamperTick(now)
	if got := alerts(t, b, outB); got["R030"] != nil || got["R033"] != nil {
		t.Errorf("the next agent raised what was done: %v", got)
	}
	if ev, _ := events.Decode(kill); true {
		b.handle(ev)
		if got := alerts(t, b, outB); got["R030"] != nil {
			t.Errorf("a done record from the buffer raised again: %v", got)
		}
	}
}

// alerts returns the rule IDs of the alerts written, and the records they
// were raised on.
func alerts(t *testing.T, a *agent, out *bytes.Buffer) map[string]*export.Record {
	t.Helper()
	if err := a.stdout.Flush(); err != nil {
		t.Fatal(err)
	}
	got := map[string]*export.Record{}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		var r export.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if r.Rule != nil {
			got[r.Rule.ID] = &r
		}
	}
	out.Reset()
	return got
}

// E19 and E23 flood the agent before killing it. The kill's record went
// into the one ring buffer the flood had filled, and R030 was silent in one
// run in four. Records of attacks on the agent now have a buffer of their
// own; if even that one is full, the kernel counts the loss and the agent
// still raises R030 (or R033), without the sender.
func TestLostTamperRecordsStillAlert(t *testing.T) {
	f := &fakeTamper{
		lost:     map[loader.TamperKind]uint64{loader.TamperSignal: 3, loader.TamperPtrace: 1},
		reported: map[loader.TamperKind]uint64{},
	}
	a, out := tamperAgent(t, f)
	a.checkTamperLost(time.Now())
	got := alerts(t, a, out)
	sig, ok := got["R030"]
	if !ok {
		t.Fatalf("no R030 for 3 lost signal records; alerts: %v", got)
	}
	if sig.Signal == nil || sig.Signal.Lost != 3 || sig.Node != "node-1" || sig.Process.PID != 0 || sig.Process.Image != "" {
		t.Errorf("R030 record: %+v signal %+v; want 3 lost on node-1 with no sender", sig, sig.Signal)
	}
	pt, ok := got["R033"]
	if !ok {
		t.Fatalf("no R033 for a lost attach record; alerts: %v", got)
	}
	if pt.Ptrace == nil || pt.Ptrace.Lost != 1 || !pt.Ptrace.TargetIsAgent {
		t.Errorf("R033 record: ptrace %+v; want 1 lost, target the agent", pt.Ptrace)
	}
	if a.c.tamperLost.Load() != 4 {
		t.Errorf("tamper_lost counter %d, want 4", a.c.tamperLost.Load())
	}

	// Reported once: the next tick, and the next agent, which reads the
	// same pinned counts, stay quiet until more are lost.
	a.checkTamperLost(time.Now())
	if got := alerts(t, a, out); len(got) != 0 {
		t.Errorf("the same losses reported again: %v", got)
	}
	next, out2 := tamperAgent(t, f)
	next.checkTamperLost(time.Now())
	if got := alerts(t, next, out2); len(got) != 0 {
		t.Errorf("the next agent reported losses already reported: %v", got)
	}
	f.lost[loader.TamperSignal] = 5
	next.checkTamperLost(time.Now())
	if got := alerts(t, next, out2); got["R030"] == nil || got["R030"].Signal.Lost != 2 {
		t.Errorf("2 new losses: alerts %v", got)
	}

	// A count that cannot be written is reported again rather than lost.
	g := &fakeTamper{lost: map[loader.TamperKind]uint64{loader.TamperSignal: 1}, reported: map[loader.TamperKind]uint64{}, failSet: true}
	b, out3 := tamperAgent(t, g)
	b.checkTamperLost(time.Now())
	b.checkTamperLost(time.Now())
	if n := b.c.alertsFor("R030"); n != 2 {
		t.Errorf("unwritable count: R030 raised %d times, want 2 (again rather than never)", n)
	}
	_ = out3

	// Nothing lost, nothing raised.
	h := &fakeTamper{lost: map[loader.TamperKind]uint64{}, reported: map[loader.TamperKind]uint64{}}
	c, out4 := tamperAgent(t, h)
	c.checkTamperLost(time.Now())
	if got := alerts(t, c, out4); len(got) != 0 {
		t.Errorf("alerts with nothing lost: %v", got)
	}
}

// alertsFor counts the alerts raised for one rule, at any level.
func (c *counters) alertsFor(id string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n uint64
	for k, v := range c.alerts {
		if k.rule == id {
			n += v
		}
	}
	return n
}

// fakeMain stands in for the main reader: Flush is read through after a
// delay, or never.
type fakeMain struct {
	flushed chan struct{}
	after   time.Duration
	never   bool
	calls   int
}

func (f *fakeMain) Flush() error {
	f.calls++
	if !f.never {
		go func() {
			time.Sleep(f.after)
			f.flushed <- struct{}{}
		}()
	}
	return nil
}

// A planned rollout: runc starts, then sends the agent SIGTERM. The start
// is in the main buffer, read in batches; the signal in the tamper buffer,
// read at once. Handled in that order, runc is unknown and the stop looks
// unplanned (R030 and R031 on every node). The tamper record now waits for
// the main buffer to be read up to it, but not for long.
func TestTamperWaitsForMainBuffer(t *testing.T) {
	c := &counters{}
	flushed := make(chan struct{}, 1)
	m := &fakeMain{flushed: flushed, after: 50 * time.Millisecond}
	start := time.Now()
	mainFirst(m, flushed, time.Second, c)()
	if el := time.Since(start); m.calls != 1 || el < 50*time.Millisecond || el > 900*time.Millisecond {
		t.Errorf("flushes %d, waited %v; want 1 flush and a wait for it", m.calls, el)
	}
	if c.tamperUnordered.Load() != 0 {
		t.Error("counted as unordered though the flush was read through")
	}

	// A notice left from an earlier flush does not end the wait.
	flushed <- struct{}{}
	start = time.Now()
	mainFirst(m, flushed, time.Second, c)()
	if el := time.Since(start); el < 50*time.Millisecond {
		t.Errorf("a stale notice ended the wait after %v", el)
	}

	// A main reader that does not catch up holds the record back only
	// for the wait.
	stuck := &fakeMain{flushed: flushed, never: true}
	start = time.Now()
	mainFirst(stuck, flushed, 100*time.Millisecond, c)()
	if el := time.Since(start); el < 100*time.Millisecond || el > time.Second {
		t.Errorf("waited %v for a main reader that never catches up, want 100ms", el)
	}
	if c.tamperUnordered.Load() != 1 {
		t.Errorf("unordered %d, want 1", c.tamperUnordered.Load())
	}
}
