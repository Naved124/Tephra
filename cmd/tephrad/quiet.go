// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/loader"
)

// quiet keeps the agent's side of the quiet marks: which processes are
// marked, with what, and in which container, so that a mark can be taken
// back when what it was judged on changes.
type quiet struct {
	on bool
	// loopbackOnly: raw events are exported, so only loopback
	// connections, which are not, may be skipped.
	loopbackOnly bool
	marks        map[uint32]quietEntry
	byContainer  map[string]map[uint32]bool
}

type quietEntry struct {
	mark      loader.QuietMark
	container string
}

// maxQuiet matches the kernel map; past it the LRU forgets old marks.
const maxQuiet = 16384

// applyQuiet follows the configuration and the rule set: the destinations
// always reported, and no mark left from the previous rule set.
func (a *agent) applyQuiet(s *settings) error {
	cfg := s.cfg
	on := cfg.QuietConnections && (!cfg.Export.RawEvents || !cfg.Export.LoopbackEvents)
	if err := a.sensor.ClearAllQuiet(); err != nil {
		return err
	}
	a.quiet = quiet{on: on, loopbackOnly: cfg.Export.RawEvents,
		marks: map[uint32]quietEntry{}, byContainer: map[string]map[uint32]bool{}}
	if !on {
		return a.sensor.SetAlwaysReport(nil, nil)
	}
	return a.sensor.SetAlwaysReport(s.rules.AlwaysReportPorts(), s.apiServers())
}

// judgeQuiet marks the process a connect or accept came from, if no loaded
// rule can fire on its connections the kernel would skip.
func (a *agent) judgeQuiet(ev *events.Net, rec *export.Record) {
	q := &a.quiet
	if !q.on || rec.Container == nil && rec.K8s.Namespace != "host" {
		// A process whose container is unresolved is judged again once
		// it is.
		return
	}
	out, in := a.cur.rules.Quiet(rec)
	var dirs uint32
	if out {
		dirs |= loader.QuietOut
	}
	if in {
		dirs |= loader.QuietIn
	}
	if dirs == 0 {
		return
	}
	if q.loopbackOnly {
		dirs |= loader.QuietLoopback
	}
	m := loader.MarkOf(ev, dirs)
	if e, ok := q.marks[ev.PID]; ok && e.mark == m {
		return
	}
	if len(q.marks) >= maxQuiet {
		return
	}
	if err := a.sensor.SetQuiet(ev.PID, m); err != nil {
		a.c.quietErrors.Add(1)
		return
	}
	container := ""
	if rec.Container != nil {
		container = rec.Container.ID
	}
	a.forgetQuiet(ev.PID, false)
	q.marks[ev.PID] = quietEntry{mark: m, container: container}
	if q.byContainer[container] == nil {
		q.byContainer[container] = map[uint32]bool{}
	}
	q.byContainer[container][ev.PID] = true
	a.c.quietMarked.Add(1)
}

// forgetQuiet drops the agent's record of a mark, and with kernel set the
// kernel's mark too.
func (a *agent) forgetQuiet(pid uint32, kernel bool) {
	q := &a.quiet
	e, ok := q.marks[pid]
	if !ok {
		return
	}
	delete(q.marks, pid)
	if m := q.byContainer[e.container]; m != nil {
		delete(m, pid)
		if len(m) == 0 {
			delete(q.byContainer, e.container)
		}
	}
	if kernel {
		if err := a.sensor.ClearQuiet(pid); err != nil {
			a.c.quietErrors.Add(1)
		}
	}
}

// mainChanged takes back every mark in a container whose main binary
// changed: is_main_binary may have changed for processes that ran no exec.
func (a *agent) mainChanged(containerID string) {
	for pid := range a.quiet.byContainer[containerID] {
		a.forgetQuiet(pid, true)
	}
}

// quietExit drops the mark of a process that exited.
func (a *agent) quietExit(ev *events.Exit) {
	if e, ok := a.quiet.marks[ev.PID]; ok && e.mark.StartNS == ev.StartTimeNS {
		a.forgetQuiet(ev.PID, true)
	}
}
