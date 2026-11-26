// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/config"
	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/filter"
	"github.com/Naved124/tephra/internal/loader"
)

// The default blind configuration asks the kernel for every Tier 1 action,
// file reads and writes included.
func TestBlindActions(t *testing.T) {
	got := blindActions(config.Default().Blind)
	want := []uint32{loader.ActionExecUnlinked, loader.ActionFileWrite, loader.ActionPtrace, loader.ActionModule, loader.ActionMount, loader.ActionFileRead}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("blind actions %v, want %v", got, want)
	}
	if blindMode(config.BlindOn) != loader.BlindOn || blindMode(config.BlindDryRun) != loader.BlindDryRun || blindMode(config.BlindOff) != loader.BlindOff {
		t.Error("blind mode names map to the wrong kernel values")
	}
}

// A refusal made while the sensor was blind raises R038, and with it any
// blocking rule that names the same file. It is counted as a blind refusal,
// not as an enforcement one.
func TestBlindRefusalRaisesR038(t *testing.T) {
	a, out := tamperAgent(t, &fakeTamper{reported: map[loader.TamperKind]uint64{}})
	rec := &export.Record{
		TS: "2026-11-26T12:00:00.000000Z", Type: "enforce", Node: "node-1",
		Process: export.Process{PID: 5130, Image: "/bin/dd"},
		K8s:     export.K8s{Namespace: "shop", Pod: "web"},
		File:    &export.File{Path: "/etc/shadow", MatchedBy: "block"},
		Enforce: &export.Enforce{Action: "file_read", Denied: true, Blind: true},
	}
	a.handleEnforce(rec)
	got := alerts(t, a, out)
	if got["R038"] == nil {
		t.Fatalf("no R038 for a refusal while blind; alerts %v", got)
	}
	if a.c.blindRefused.Load() != 1 || a.c.enforceDenied.Load() != 0 {
		t.Errorf("counted blind %d, enforce %d; want 1 and 0", a.c.blindRefused.Load(), a.c.enforceDenied.Load())
	}

	// A write to ld.so.preload refused while blind: R038 and R007, which
	// blocks that write.
	w := *rec
	w.File = &export.File{Path: "/etc/ld.so.preload", Write: true, MatchedBy: "block"}
	w.Enforce = &export.Enforce{Action: "file_write", Denied: true, Blind: true}
	a.handleEnforce(&w)
	got = alerts(t, a, out)
	if got["R038"] == nil || got["R007"] == nil {
		t.Errorf("blind refusal of a write to ld.so.preload: alerts %v, want R038 and R007", got)
	}

	// An ordinary refusal does not raise R038.
	o := w
	o.Enforce = &export.Enforce{Action: "file_write", Denied: true}
	a.handleEnforce(&o)
	if got := alerts(t, a, out); got["R038"] != nil {
		t.Errorf("an ordinary refusal raised R038: %v", got)
	}
}

// records returns every record written, by type, and the alerts by rule.
func records(t *testing.T, a *agent, out *bytes.Buffer) (byType map[string][]*export.Record, byRule map[string]*export.Record) {
	t.Helper()
	if err := a.stdout.Flush(); err != nil {
		t.Fatal(err)
	}
	byType, byRule = map[string][]*export.Record{}, map[string]*export.Record{}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r export.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if r.Rule != nil {
			byRule[r.Rule.ID] = &r
		} else {
			byType[r.Type] = append(byType[r.Type], &r)
		}
	}
	out.Reset()
	return byType, byRule
}

// A file summary whose opens all failed to reach the agent is the only
// trace of them: it goes through the rules as a file_open carrying the
// count. One whose first open got through is a count, judged already.
func TestFileSummaryReport(t *testing.T) {
	a, out := tamperAgent(t, &fakeTamper{reported: map[loader.TamperKind]uint64{}})
	first := func() *events.FileOpen {
		return &events.FileOpen{
			Header: events.Header{TSBootNS: 90e9, StartTimeNS: 80e9, Type: events.TypeFileOpen, PID: 5130, TID: 5130,
				Flags: events.FileKernelCreds | 1, Comm: "dd"},
			Inode: 1851171, Dev: 345, Path: "/etc/shadow",
		}
	}

	a.reportFileSummary(loader.FileSummary{Count: 37, WindowNS: 90e9, LastNS: 95e9, First: first()}, time.Now())
	byType, byRule := records(t, a, out)
	if byRule["R005"] == nil {
		t.Fatalf("an undelivered summary of /etc/shadow reads raised no R005; alerts %v", byRule)
	}
	if f := byRule["R005"].File; f == nil || f.Count != 37 || f.FirstSeen == "" || f.LastSeen == "" {
		t.Errorf("R005 from a summary: file %+v, want count 37 and its times", f)
	}
	if len(byType["file_open"]) != 1 || len(byType[export.TypeFileSummary]) != 0 {
		t.Errorf("undelivered summary records %v, want one file_open", byType)
	}
	if a.c.fileSumUndelivered.Load() != 1 {
		t.Errorf("undelivered counter %d", a.c.fileSumUndelivered.Load())
	}

	a.reportFileSummary(loader.FileSummary{Count: 12, WindowNS: 90e9, LastNS: 95e9, Delivered: true, First: first()}, time.Now())
	byType, byRule = records(t, a, out)
	if len(byRule) != 0 {
		t.Errorf("a delivered summary raised alerts again: %v", byRule)
	}
	if s := byType[export.TypeFileSummary]; len(s) != 1 || s[0].File.Count != 12 || s[0].File.Path != "/etc/shadow" {
		t.Errorf("delivered summary records %v, want one file_summary of 12 opens of /etc/shadow", byType)
	}
}

// The agent's default file watches, the rules' and blind mode's together,
// are all ones the loader accepts. The blind-only watches were refused
// once, on the lab, as "reporting nothing".
func TestDefaultWatchesAct(t *testing.T) {
	a, _ := tamperAgent(t, &fakeTamper{reported: map[loader.TamperKind]uint64{}})
	f := a.cur.filters()
	blind := 0
	for _, w := range f.Watches {
		if !w.Acts() {
			t.Errorf("watch %s (bits %b) does nothing and would be refused", w.Path, w.Bits)
		}
		if w.Bits&(filter.BlindRead|filter.BlindWrite) != 0 {
			blind++
		}
	}
	if blind < len(config.Default().Blind.Files) {
		t.Errorf("%d watches carry blind bits, want the %d Tier 1 files", blind, len(config.Default().Blind.Files))
	}
}
