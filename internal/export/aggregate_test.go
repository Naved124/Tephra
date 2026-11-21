// SPDX-License-Identifier: Apache-2.0

package export

import (
	"fmt"
	"testing"
	"time"
)

func alertOf(rule, level, pod, image, path string) *Record {
	return &Record{
		TS: "t", Type: "file_open", Node: "n",
		Rule:      &Rule{ID: rule, Level: level},
		Process:   Process{Image: image, CommandLine: image + " " + path},
		Container: &Container{ID: "c-" + pod},
		K8s:       K8s{Namespace: "ns", Pod: pod},
		File:      &File{Path: path},
	}
}

// Repeats are folded into one summary; another program, file or pod is
// never folded into them.
func TestGrouperFoldsRepeatsOnly(t *testing.T) {
	g := NewGrouper()
	now := time.Unix(1000, 0)
	if g.Add(alertOf("R005", "high", "flooder", "/bin/cat", "/etc/shadow"), now) == nil {
		t.Fatal("the first alert of a kind was held back")
	}
	for i := 0; i < 1000; i++ {
		if g.Add(alertOf("R005", "high", "flooder", "/bin/cat", "/etc/shadow"), now) != nil {
			t.Fatal("a repeat was sent on its own")
		}
	}
	for _, r := range []*Record{
		alertOf("R005", "high", "flooder", "/bin/dd", "/etc/shadow"),      // another program
		alertOf("R005", "high", "flooder", "/bin/cat", "/etc/gshadow"),    // another file
		alertOf("R005", "high", "victim", "/bin/cat", "/etc/shadow"),      // another pod
		alertOf("R030", "critical", "flooder", "/bin/cat", "/etc/shadow"), // another rule
	} {
		if g.Add(r, now) == nil {
			t.Errorf("%s %s %s %s folded into the flood", r.Rule.ID, r.K8s.Pod, r.Process.Image, r.File.Path)
		}
	}
	if s := g.Flush(now.Add(GroupWindow / 2)); len(s) != 0 {
		t.Errorf("%d summaries before the window ended", len(s))
	}
	s := g.Flush(now.Add(GroupWindow))
	if len(s) != 1 || s[0].Repeats == nil || s[0].Repeats.Count != 1000 || s[0].Process.Image != "/bin/cat" {
		t.Fatalf("summaries %+v, want one of 1000 repeats of cat", s)
	}
	if g.Len() != 0 {
		t.Errorf("%d groups left after the window", g.Len())
	}
	// A new window starts a new group, sent at once again.
	if g.Add(alertOf("R005", "high", "flooder", "/bin/cat", "/etc/shadow"), now.Add(GroupWindow)) == nil {
		t.Error("the first alert of a new window was held back")
	}
}

// A pod that varies its programs to escape grouping (E23) has the rest of
// its alerts grouped by rule; other pods are untouched.
func TestGrouperPodBudget(t *testing.T) {
	g := NewGrouper()
	now := time.Unix(1000, 0)
	sent := 0
	for i := 0; i < 200; i++ {
		for j := 0; j < 10; j++ {
			if g.Add(alertOf("R005", "high", "flooder", fmt.Sprintf("/tmp/reader%d", i), "/etc/shadow"), now) != nil {
				sent++
			}
		}
	}
	if sent != podBudget+1 {
		t.Errorf("%d alerts sent from 200 programs, want %d", sent, podBudget+1)
	}
	if g.Add(alertOf("R005", "high", "victim", "/bin/dd", "/etc/shadow"), now) == nil {
		t.Error("another pod's alert folded under the flooder's budget")
	}
	var folded *Repeats
	for _, s := range g.Flush(now.Add(GroupWindow)) {
		if s.Repeats.Folded {
			folded = s.Repeats
		}
	}
	if folded == nil || folded.Count != 200*10-podBudget*10-1 || len(folded.Samples) != maxSamples {
		t.Errorf("folded summary %+v", folded)
	}
}

// When the queue holds only alerts, the lowest level goes first and a
// critical alert is never dropped for a lower one.
func TestQueueDropsLowestLevelFirst(t *testing.T) {
	g, err := NewGRPC("127.0.0.1:1", 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"medium", "high", "medium"} {
		g.Offer(&Record{Rule: &Rule{ID: "R", Level: l}})
	}
	if !g.Offer(&Record{Rule: &Rule{ID: "R030", Level: "critical"}}) {
		t.Fatal("a critical alert was refused while medium ones were queued")
	}
	if g.Offer(&Record{Rule: &Rule{ID: "R", Level: "medium"}}) {
		t.Error("a medium alert displaced one no lower")
	}
	var levels []string
	g.mu.Lock()
	for _, a := range g.alerts {
		levels = append(levels, a.Rule.Level)
	}
	g.mu.Unlock()
	if fmt.Sprint(levels) != "[high medium critical]" {
		t.Errorf("queue holds %v, want the oldest medium gone", levels)
	}
	st := g.Stats()
	if st.DroppedAlerts != 2 || st.DroppedByLevel["medium"] != 2 || st.DroppedByLevel["critical"] != 0 {
		t.Errorf("stats %+v", st)
	}
}

// Phase 4 run 1, E07, as a replay: tens of thousands of alerts recovered from
// the pinned buffer, then the read that matters and the kill of the agent.
// Both come out, through a queue far smaller than the flood.
func TestFloodThenTheAlertThatMatters(t *testing.T) {
	g := NewGrouper()
	q, err := NewGRPC("127.0.0.1:1", 8192)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	offer := func(r *Record) {
		if out := g.Add(r, now); out != nil {
			q.Offer(out)
		}
	}
	for i := 0; i < 50000; i++ {
		offer(alertOf("R005", "high", "e06", "/usr/local/bin/python3", "/etc/shadow"))
	}
	kill := alertOf("R030", "critical", "victim", "/bin/busybox", "")
	kill.File, kill.Signal = nil, &Signal{Number: 9, TargetPID: 4242}
	offer(kill)
	offer(alertOf("R005", "high", "victim", "/bin/dd", "/etc/shadow"))
	for _, s := range g.Flush(now.Add(GroupWindow)) {
		q.Offer(s)
	}
	var got []string
	q.mu.Lock()
	for _, a := range q.alerts {
		x := a.Rule.ID + " " + a.K8s.Pod
		if a.Repeats != nil {
			x += fmt.Sprintf(" x%d", a.Repeats.Count)
		}
		got = append(got, x)
	}
	q.mu.Unlock()
	if want := "[R005 e06 R030 victim R005 victim R005 e06 x49999]"; fmt.Sprint(got) != want {
		t.Errorf("queued %v, want %s", got, want)
	}
	if q.Stats().DroppedAlerts != 0 {
		t.Errorf("%d alerts dropped", q.Stats().DroppedAlerts)
	}
}

// A program started again with other arguments is a new kind, sent at once
// (CI: R004 on a wget with a new URL was held for the summary).
func TestGrouperProgramStartsByCommandLine(t *testing.T) {
	g := NewGrouper()
	now := time.Unix(1000, 0)
	run := func(cl string) *Record {
		return &Record{Type: "exec", Rule: &Rule{ID: "R004", Level: "low"}, Process: Process{Image: "/usr/bin/wget", CommandLine: cl},
			K8s: K8s{Namespace: "ns", Pod: "probe"}}
	}
	if g.Add(run("wget http://grafana/"), now) == nil || g.Add(run("wget http://loki/"), now) == nil {
		t.Fatal("a first download held back")
	}
	if g.Add(run("wget http://loki/"), now) != nil {
		t.Error("the same command again was sent on its own")
	}
	if g.Add(run("wget http://127.0.0.1:9/m5-nonce"), now) == nil {
		t.Error("a new command was held for the summary")
	}
}
