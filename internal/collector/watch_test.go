// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

func beat(start uint64, extra ...string) map[string]uint64 {
	h := map[string]uint64{"agent_start_unix": start, "rules_loaded": 31}
	for _, k := range extra {
		h[k] = 1
	}
	return h
}

// An agent that keeps sending health raises nothing.
func TestSteadyAgentIsQuiet(t *testing.T) {
	w := newWatch(defaultSilence)
	for s := 0; s <= 300; s += 15 {
		if a := w.health("n1", beat(1000), at(s)); a != nil {
			t.Fatalf("alert at %ds: %+v", s, a.Rule)
		}
		if got := w.check(at(s + 5)); len(got) != 0 {
			t.Fatalf("silence reported at %ds", s+5)
		}
	}
}

// A silent agent is reported once, high, however long the silence lasts.
func TestSilenceReportedOnce(t *testing.T) {
	w := newWatch(defaultSilence)
	w.health("n1", beat(1000), at(0))
	if got := w.check(at(30)); len(got) != 0 {
		t.Fatal("reported before the limit")
	}
	got := w.check(at(60))
	if len(got) != 1 || got[0].Rule.ID != "R031" || got[0].Rule.Level != "high" || got[0].Node != "n1" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Health["silent_seconds"] != 60 {
		t.Errorf("silent_seconds %d", got[0].Health["silent_seconds"])
	}
	for s := 75; s < 600; s += 15 {
		if again := w.check(at(s)); len(again) != 0 {
			t.Fatalf("reported again at %ds", s)
		}
	}
}

// An agent killed and replaced: the silence is reported, then the restart,
// medium, with what was recorded while no agent read.
func TestUnplannedRestart(t *testing.T) {
	w := newWatch(defaultSilence)
	w.health("n1", beat(1000), at(0))
	if got := w.check(at(60)); len(got) != 1 {
		t.Fatalf("silence: %+v", got)
	}
	h := beat(1080, "keeps_recording")
	h["recorded_while_down"] = 42
	a := w.health("n1", h, at(90))
	if a == nil || a.Rule.ID != "R031" || a.Rule.Level != "medium" || a.Rule.Title != restartTitle {
		t.Fatalf("restart: %+v", a)
	}
	if a.Health["recorded_while_down"] != 42 || a.Health["gap_seconds"] != 90 || a.Health["keeps_recording"] != 1 {
		t.Errorf("facts %v", a.Health)
	}
	// Back to normal: nothing more.
	if a := w.health("n1", beat(1080), at(105)); a != nil {
		t.Fatalf("second restart alert: %+v", a.Rule)
	}
	if got := w.check(at(110)); len(got) != 0 {
		t.Fatal("silence reported after recovery")
	}
}

// A crash quickly restarted by Kubernetes, within the silence limit, is
// still reported as a restart.
func TestQuickCrashIsReported(t *testing.T) {
	w := newWatch(defaultSilence)
	w.health("n1", beat(1000), at(0))
	if a := w.health("n1", beat(1010), at(20)); a == nil || a.Rule.Level != "medium" {
		t.Fatalf("got %+v", a)
	}
}

// A planned stop announces itself: neither the silence nor the restart
// that follows raises anything.
func TestPlannedStopIsQuiet(t *testing.T) {
	w := newWatch(defaultSilence)
	w.health("n1", beat(1000), at(0))
	w.health("n1", beat(1000, "stopping"), at(10))
	for s := 15; s < 600; s += 15 {
		if got := w.check(at(s)); len(got) != 0 {
			t.Fatalf("silence reported at %ds after a planned stop", s)
		}
	}
	if a := w.health("n1", beat(1600), at(600)); a != nil {
		t.Fatalf("planned restart reported: %+v", a.Rule)
	}
	// The new agent is watched again.
	if got := w.check(at(660)); len(got) != 1 {
		t.Fatalf("silence after the planned restart: %+v", got)
	}
}

// A node gone for a day is forgotten, so the map does not grow forever.
func TestSilentNodeForgotten(t *testing.T) {
	w := newWatch(defaultSilence)
	w.health("n1", beat(1000), at(0))
	w.check(at(60))
	w.check(at(int((forgetSilentNode + time.Minute).Seconds())))
	if len(w.nodes) != 0 {
		t.Fatalf("nodes %v", w.nodes)
	}
}

// Each node is watched on its own.
func TestNodesAreSeparate(t *testing.T) {
	w := newWatch(defaultSilence)
	w.health("n1", beat(1000), at(0))
	w.health("n2", beat(2000), at(0))
	w.health("n2", beat(2000), at(50))
	got := w.check(at(60))
	if len(got) != 1 || got[0].Node != "n1" {
		t.Fatalf("got %+v", got)
	}
}
