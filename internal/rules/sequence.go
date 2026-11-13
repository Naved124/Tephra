// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/Naved124/tephra/internal/export"
)

// A sequence rule fires when its steps match in order on events that belong
// together. Each step is a single-event rule of its own:
//
//	sequence:
//	  by: process_tree          # or: pod
//	  window: 60s
//	  steps:
//	    - event: exec
//	      detection: {...}
//	    - event: exec
//	      exe_changed: true     # optional, exec steps after the first
//	      detection: {...}
//
// "process_tree" groups the events of one tree of processes inside a
// container: everything started from one entry into it, which is the
// container's first process or one exec into the container. "pod" groups
// everything in a pod.
//
// The window runs from the latest match of the first step. exe_changed asks
// that the executable's inode changed after the sequence began (with one
// second of slack for clock conversion), which is what tells "ran the file it
// just fetched" from "ran something".
const (
	ByProcessTree = "process_tree"
	ByPod         = "pod"

	minSteps  = 2
	maxSteps  = 4
	minWindow = time.Second
	maxWindow = 10 * time.Minute

	// DefaultSequenceCap bounds the partial sequences a rule set keeps.
	// The oldest is dropped when a new one does not fit.
	DefaultSequenceCap = 4096

	changeSlack = time.Second
	tsLayout    = "2006-01-02T15:04:05.000000Z"
)

func (r *Rule) parseSequence(file string, n *yaml.Node) error {
	fail := func(at *yaml.Node, format string, args ...any) error {
		return &Error{file, at.Line, fmt.Sprintf("rule %s: ", r.ID) + fmt.Sprintf(format, args...)}
	}
	if n.Kind != yaml.MappingNode {
		return fail(n, "sequence must be a mapping with by, window and steps")
	}
	var steps *yaml.Node
	var window string
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		var err error
		switch k.Value {
		case "by":
			r.By, err = scalarString(v)
		case "window":
			window, err = scalarString(v)
		case "steps":
			steps = v
		default:
			return fail(k, "unknown key %q in sequence", k.Value)
		}
		if err != nil {
			return fail(v, "%s: %v", k.Value, err)
		}
	}
	if r.By != ByProcessTree && r.By != ByPod {
		return fail(n, "sequence by %q is not process_tree or pod", r.By)
	}
	w, err := time.ParseDuration(window)
	if err != nil || w < minWindow || w > maxWindow {
		return fail(n, "sequence window %q is not a duration from %s to %s", window, minWindow, maxWindow)
	}
	r.Window = w
	if steps == nil || steps.Kind != yaml.SequenceNode || len(steps.Content) < minSteps || len(steps.Content) > maxSteps {
		return fail(n, "sequence needs a list of %d to %d steps", minSteps, maxSteps)
	}
	for i, sn := range steps.Content {
		step, err := r.parseStep(file, i, sn)
		if err != nil {
			return err
		}
		r.Steps = append(r.Steps, step)
	}
	return nil
}

func (r *Rule) parseStep(file string, index int, n *yaml.Node) (*Rule, error) {
	fail := func(at *yaml.Node, format string, args ...any) error {
		return &Error{file, at.Line, fmt.Sprintf("rule %s step %d: ", r.ID, index+1) + fmt.Sprintf(format, args...)}
	}
	if n.Kind != yaml.MappingNode {
		return nil, fail(n, "a step must be a mapping with event and detection")
	}
	step := &Rule{ID: r.ID, File: file, Line: n.Line}
	var detection *yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "event":
			var err error
			if step.Event, err = scalarString(v); err != nil {
				return nil, fail(v, "event: %v", err)
			}
		case "detection":
			detection = v
		case "exe_changed":
			if v.Kind != yaml.ScalarNode || v.Tag != "!!bool" {
				return nil, fail(v, "exe_changed: want true or false")
			}
			_ = v.Decode(&step.ExeChanged)
		default:
			return nil, fail(k, "unknown key %q in a step", k.Value)
		}
	}
	switch {
	case ruleEvents[step.Event] == nil:
		return nil, fail(n, "event %q is not a known event type", step.Event)
	case detection == nil:
		return nil, fail(n, "detection is missing")
	case step.ExeChanged && (step.Event != "exec" || index == 0):
		return nil, fail(n, "exe_changed applies to an exec step after the first")
	}
	if err := step.parseDetection(file, detection); err != nil {
		return nil, err
	}
	if err := step.compileWatches(); err != nil {
		return nil, fail(detection, "%v", err)
	}
	return step, nil
}

// progress is one partial sequence.
type progress struct {
	id string
	// next is the index of the step waited for.
	next int
	// since is when the sequence began, for exe_changed; last is the
	// latest match of the first step, which the window runs from.
	since, last time.Time
	elem        *list.Element
}

// sequencer holds the partial sequences of a rule set, oldest first.
type sequencer struct {
	mu      sync.Mutex
	cap     int
	states  map[string]*progress
	order   *list.List
	evicted uint64
}

func newSequencer(limit int) *sequencer {
	return &sequencer{cap: limit, states: map[string]*progress{}, order: list.New()}
}

// seqKey names what a record belongs to; empty if it cannot be grouped.
func seqKey(by string, rec *export.Record) string {
	switch by {
	case ByProcessTree:
		return rec.Process.Tree
	case ByPod:
		if rec.K8s.Pod == "" {
			return ""
		}
		return rec.K8s.Namespace + "/" + rec.K8s.Pod
	}
	return ""
}

func (q *sequencer) drop(p *progress) {
	q.order.Remove(p.elem)
	delete(q.states, p.id)
}

// match advances the sequences of the given rules with one record and
// returns the rules that completed.
func (q *sequencer) match(rules []*Rule, rec *export.Record) []*Rule {
	ts, err := time.Parse(tsLayout, rec.TS)
	if err != nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	var fired []*Rule
	for _, r := range rules {
		key := seqKey(r.By, rec)
		if key == "" {
			continue
		}
		id := r.ID + "\x00" + key
		p := q.states[id]
		if p != nil && ts.Sub(p.last) > r.Window {
			q.drop(p)
			p = nil
		}
		if p != nil {
			step := r.Steps[p.next]
			if step.Event == rec.Type && (!step.ExeChanged || changedSince(rec, p.since)) && step.Matches(rec) {
				p.next++
				if p.next == len(r.Steps) {
					q.drop(p)
					fired = append(fired, r)
				}
				continue
			}
		}
		first := r.Steps[0]
		if first.Event != rec.Type || !first.Matches(rec) {
			continue
		}
		if p != nil {
			// The first step again: the window restarts, and the
			// beginning moves up so that it is never more than one
			// window behind.
			p.last = ts
			if floor := ts.Add(-r.Window); p.since.Before(floor) {
				p.since = floor
			}
			q.order.MoveToBack(p.elem)
			continue
		}
		for q.order.Len() >= q.cap {
			q.drop(q.order.Front().Value.(*progress))
			q.evicted++
		}
		p = &progress{id: id, next: 1, since: ts, last: ts}
		p.elem = q.order.PushBack(p)
		q.states[id] = p
	}
	return fired
}

func changedSince(rec *export.Record, since time.Time) bool {
	x := rec.Process.Exec
	if x == nil || x.ExeCtimeNS == 0 {
		return false
	}
	return !time.Unix(0, int64(x.ExeCtimeNS)).Before(since.Add(-changeSlack))
}

// SequenceStats reports how many partial sequences are held and how many
// were dropped to make room.
func (s *Set) SequenceStats() (held int, evicted uint64) {
	s.seq.mu.Lock()
	defer s.seq.mu.Unlock()
	return s.seq.order.Len(), s.seq.evicted
}

// SetSequenceCap changes the bound on partial sequences.
func (s *Set) SetSequenceCap(n int) {
	if n < 1 {
		n = 1
	}
	s.seq.mu.Lock()
	defer s.seq.mu.Unlock()
	s.seq.cap = n
}
