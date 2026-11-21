// SPDX-License-Identifier: Apache-2.0

package export

import (
	"fmt"
	"sync"
	"time"
)

// Grouping of repeated alerts. A flood of alerts is a way to hide the one
// that matters: the export queue fills, and what comes after the flood is
// dropped (Phase 4 run 1, E07). Grouping keeps the flood to a few records
// without delaying or folding away anything new.
const (
	// GroupWindow is how long repeats of an alert are counted before one
	// summary of them is sent.
	GroupWindow = 10 * time.Second
	// podBudget is how many groups one pod may open in a window. More
	// than that is a pod varying what it does to defeat grouping (E23):
	// the rest of its alerts are grouped by rule alone.
	podBudget = 50
	// maxSamples is how many command lines a summary keeps.
	maxSamples = 5
	// maxGroups bounds memory; beyond it alerts are grouped by rule and
	// pod alone.
	maxGroups = 20000
)

// Repeats is set on the summary of a group of alerts: how many more alerts
// of the same kind there were after the first one, which was sent on its own.
type Repeats struct {
	Count uint64 `json:"count"`
	// First and Last are the times of the first and last repeat.
	First string `json:"first"`
	Last  string `json:"last"`
	// Folded: the pod opened more groups in the window than it may, and
	// these repeats were grouped by rule alone, whatever program or
	// target they had.
	Folded bool `json:"folded,omitempty"`
	// Samples are distinct command lines among the repeats.
	Samples []string `json:"samples,omitempty"`
}

type groupKey struct {
	rule, namespace, pod, container, image, target string
	folded                                         bool
}

type group struct {
	opened  time.Time
	first   *Record // the alert that opened the group, sent at once
	repeats uint64
	firstTS string
	lastTS  string
	samples []string
}

type podKey struct{ namespace, pod, node string }

// Grouper groups repeated alerts. The first alert of a kind is passed on at
// once; repeats within GroupWindow are counted and sent as one summary when
// the window ends. A kind is the rule, the pod and container, the program
// and the target (the file or remote address), so another program, another
// file or another pod is never folded into a flood.
//
// It is safe for concurrent use.
type Grouper struct {
	mu     sync.Mutex
	groups map[groupKey]*group
	// opened counts the groups each pod opened in its current window.
	opened map[podKey]int
	since  map[podKey]time.Time
}

// NewGrouper returns an empty grouper.
func NewGrouper() *Grouper {
	return &Grouper{groups: map[groupKey]*group{}, opened: map[podKey]int{}, since: map[podKey]time.Time{}}
}

// Add takes an alert. It returns the alert when it is to be sent now, or nil
// when it was counted as a repeat. Records that are not alerts pass through.
func (g *Grouper) Add(r *Record, now time.Time) *Record {
	if !r.IsAlert() {
		return r
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	k := g.key(r, now)
	if gr, ok := g.groups[k]; ok {
		gr.repeats++
		if gr.firstTS == "" {
			gr.firstTS = r.TS
		}
		gr.lastTS = r.TS
		if cl := r.Process.CommandLine; cl != "" && len(gr.samples) < maxSamples && !contains(gr.samples, cl) {
			gr.samples = append(gr.samples, cl)
		}
		return nil
	}
	g.groups[k] = &group{opened: now, first: r}
	return r
}

func (g *Grouper) key(r *Record, now time.Time) groupKey {
	k := groupKey{
		rule:      r.Rule.ID,
		namespace: r.K8s.Namespace,
		pod:       r.K8s.Pod,
		image:     r.Process.Image,
		target:    target(r),
	}
	if r.Container != nil {
		k.container = r.Container.ID
	}
	if _, ok := g.groups[k]; ok {
		return k
	}
	pk := podKey{r.K8s.Namespace, r.K8s.Pod, r.Node}
	if t, ok := g.since[pk]; !ok || now.Sub(t) >= GroupWindow {
		g.since[pk] = now
		g.opened[pk] = 0
	}
	if g.opened[pk] >= podBudget || len(g.groups) >= maxGroups {
		return groupKey{rule: k.rule, namespace: k.namespace, pod: k.pod, folded: true}
	}
	g.opened[pk]++
	return k
}

// Flush returns the summaries of the groups whose window has ended, and
// forgets those groups. A group with no repeats ends without a summary.
func (g *Grouper) Flush(now time.Time) []*Record {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []*Record
	for k, gr := range g.groups {
		if now.Sub(gr.opened) < GroupWindow {
			continue
		}
		delete(g.groups, k)
		if gr.repeats == 0 {
			continue
		}
		s := *gr.first
		s.TS = gr.lastTS
		s.Repeats = &Repeats{Count: gr.repeats, First: gr.firstTS, Last: gr.lastTS, Folded: k.folded, Samples: gr.samples}
		out = append(out, &s)
	}
	for pk, t := range g.since {
		if now.Sub(t) >= GroupWindow {
			delete(g.since, pk)
			delete(g.opened, pk)
		}
	}
	return out
}

// Len is the number of open groups.
func (g *Grouper) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.groups)
}

// target is what an alert is about: the file, the remote address, the
// process a signal or trace was aimed at, the module, the mount point. For
// anything else, a program start among them, it is the command line: the
// same program run with other arguments is doing something new, which must
// be sent at once and not held for a summary.
func target(r *Record) string {
	switch {
	case r.File != nil:
		if r.File.Target != "" {
			return r.File.Target
		}
		return r.File.Path
	case r.Network != nil:
		if r.Network.UnixPath != "" {
			return r.Network.UnixPath
		}
		return fmt.Sprintf("%s:%d", r.Network.DestinationIP, r.Network.DestinationPort)
	case r.Signal != nil:
		return fmt.Sprintf("signal %d to %d", r.Signal.Number, r.Signal.TargetPID)
	case r.Ptrace != nil:
		return fmt.Sprintf("ptrace %d", r.Ptrace.TargetPID)
	case r.Module != nil:
		return "module " + r.Module.Name
	case r.Mount != nil:
		return "mount " + r.Mount.Target
	}
	return r.Process.CommandLine
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
