// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/netip"
	"time"

	"github.com/tephrasec/tephra/internal/events"
	"github.com/tephrasec/tephra/internal/export"
	"github.com/tephrasec/tephra/internal/loader"
)

// quiet keeps the agent's side of the quiet marks: which processes are
// marked, with what, and in which container, so that a mark can be taken
// back when what it was judged on changes.
type quiet struct {
	on bool
	// summarise: raw events are exported, so the kernel counts the
	// connections it skips, and they leave the agent as summaries.
	summarise   bool
	marks       map[uint32]quietEntry
	byContainer map[string]map[uint32]bool
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
	on := cfg.QuietConnections
	if err := a.sensor.ClearAllQuiet(); err != nil {
		return err
	}
	a.quiet = quiet{on: on, summarise: cfg.Export.RawEvents,
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
	if q.summarise {
		dirs |= loader.QuietSummary
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

// quietExit drops the mark of a process that exited, and has its counted
// connections read soon, while its pod is still known.
func (a *agent) quietExit(ev *events.Exit) {
	if e, ok := a.quiet.marks[ev.PID]; ok && e.mark.StartNS == ev.StartTimeNS {
		a.forgetQuiet(ev.PID, true)
		a.drainSoon = true
	}
}

// summaryEvery is how often the counted connections are read.
const summaryEvery = 10 * time.Second

// drainSummaries turns the kernel's counts into connection_summary records:
// one per process and destination with what was counted since the previous
// report. What was reported is kept in a pinned map, so that an agent that
// adopts the counts of one that died goes on from there instead of
// reporting the same connections twice. A destination with nothing new over
// a whole period is taken out of the map, with whatever arrived in between,
// so the map holds what is active. Counts are read even when they are not
// exported, to free the map.
func (a *agent) drainSummaries(now time.Time) {
	a.drainSoon = false
	if a.sums == nil {
		sent, err := a.sensor.SentSummaries()
		if err != nil {
			a.c.quietErrors.Add(1)
			return
		}
		a.sums = sent
	}
	sums, err := a.sensor.Summaries()
	if err != nil {
		a.c.quietErrors.Add(1)
		return
	}
	out, take, next := planSummaries(a.sums, sums)
	for _, o := range out {
		a.emitSummary(o.sum, o.n, now)
		if err := a.sensor.SetSent(o.sum.Key, next[o.sum.Key]); err != nil {
			a.c.quietErrors.Add(1)
		}
	}
	for _, x := range take {
		got, ok, err := a.sensor.TakeSummary(x.Key)
		if err != nil {
			// Read again next time.
			a.c.quietErrors.Add(1)
			next[x.Key] = a.sums[x.Key]
			continue
		}
		if ok && got.Count > x.Count {
			a.emitSummary(got, got.Count-x.Count, now)
		}
	}
	// What was reported for counts no longer in the map is forgotten.
	for k := range a.sums {
		if _, ok := next[k]; !ok {
			if err := a.sensor.ForgetSent(k); err != nil {
				a.c.quietErrors.Add(1)
			}
		}
	}
	a.sums = next
}

type sumOut struct {
	sum loader.Summary
	n   uint64
}

// planSummaries decides, from what was reported and this read, what to
// report (the growth of each count) and what to take out of the map (the
// destinations that did not grow over a whole period).
func planSummaries(prev map[loader.SummaryKey]loader.SummarySent, sums []loader.Summary) (out []sumOut, take []loader.Summary, next map[loader.SummaryKey]loader.SummarySent) {
	next = make(map[loader.SummaryKey]loader.SummarySent, len(sums))
	for _, x := range sums {
		p, known := prev[x.Key]
		if x.Count < p.Count {
			// Taken and counted anew.
			p, known = loader.SummarySent{}, false
		}
		switch {
		case x.Count > p.Count:
			out = append(out, sumOut{x, x.Count - p.Count})
			next[x.Key] = loader.SummarySent{Count: x.Count, LastNS: x.LastNS}
		case known:
			take = append(take, x)
		}
	}
	return out, take, next
}

// emitSummary exports n connections of one counted destination, attributed
// as an event of the process would be. Rules are not run: the process was
// marked quiet because none of them can fire on these connections.
func (a *agent) emitSummary(x loader.Summary, n uint64, now time.Time) {
	ev := &events.Net{
		Header: events.Header{
			TSBootNS: x.LastNS, StartTimeNS: x.StartNS, CgroupID: x.CgroupID,
			Type: events.Type(x.Type), PID: x.PID, TID: x.PID, PPID: x.PPID,
			UID: x.UID, GID: x.GID, PidNS: x.PidNS, MntNS: x.MntNS, NetNS: x.NetNS,
			Comm: x.Comm,
		},
		Family: x.Family, Proto: uint16(x.Proto), ExecID: x.ExecID,
	}
	if ev.Type == events.TypeAccept {
		listen := netip.IPv4Unspecified()
		if x.Family == events.AFInet6 {
			listen = netip.IPv6Unspecified()
		}
		ev.Remote = netip.AddrPortFrom(x.Remote, 0)
		ev.Local = netip.AddrPortFrom(listen, x.Port)
	} else {
		ev.Remote = netip.AddrPortFrom(x.Remote, x.Port)
	}
	cfg := a.cur.cfg
	if !cfg.Export.RawEvents {
		return
	}
	rec := a.enricher.Handle(ev, now)
	if rec == nil || rec.Network == nil {
		return
	}
	if !cfg.Export.LoopbackEvents && rec.Network.Loopback() {
		a.c.loopbackHeld.Add(1)
		return
	}
	rec.Type = export.TypeConnSummary
	if ev.Type == events.TypeAccept {
		// The listening address is not kept, only its port.
		rec.Network.DestinationIP = ""
	}
	rec.Network.Count = n
	rec.Network.Total = x.Count
	rec.Network.FirstSeen = a.enricher.Wall(x.FirstNS)
	rec.Network.LastSeen = a.enricher.Wall(x.LastNS)
	a.c.connSummaries.Add(1)
	a.emit(rec)
}
