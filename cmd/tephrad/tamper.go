// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/loader"
)

// tamperStore is the kernel's side of tamper records: how many were lost,
// and the last ones kept with what was done with them. The sensor in
// production, a fake in tests.
type tamperStore interface {
	TamperLost(k loader.TamperKind) (lost, reported uint64, err error)
	SetTamperReported(k loader.TamperKind, n uint64) error
	TamperPending() ([]loader.TamperRecord, error)
	TamperDone(seq uint64) (bool, error)
	SetTamperDone(seq uint64) error
}

const (
	// tamperDoneAfter is how long after handling a tamper record it is
	// marked done: long enough for its alert to leave the agent. An agent
	// killed sooner leaves it to the next one, which raises it again.
	tamperDoneAfter = 5 * time.Second
	// tamperReplayAge is how old a kept record must be before it is
	// replayed: one that young may still be on its way from the buffer.
	tamperReplayAge = 2 * time.Second
	// tamperReplayStart lets a new agent read the tamper buffer's backlog
	// before it replays anything.
	tamperReplayStart = 3 * time.Second
)

// tamperOrderWait is how long a tamper record waits for the main buffer to
// be read up to it. A flood can keep the main reader from catching up; the
// record does not wait longer for it, and if the agent dies meanwhile the
// kernel's table keeps it for the next one.
const tamperOrderWait = 500 * time.Millisecond

// flusher is the main ring buffer reader, as mainFirst needs it.
type flusher interface{ Flush() error }

// mainFirst returns what runs before a tamper record is queued: it asks the
// main reader to read everything recorded so far, and waits until that is
// queued or wait has passed.
func mainFirst(main flusher, flushed <-chan struct{}, wait time.Duration, c *counters) func() {
	return func() {
		// A notice left from an earlier flush is not about this one.
		select {
		case <-flushed:
		default:
		}
		if err := main.Flush(); err != nil {
			c.tamperErrors.Add(1)
			return
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-flushed:
		case <-t.C:
			c.tamperUnordered.Add(1)
		}
	}
}

// tamperSeqOf returns the sequence number of a tamper record, 0 for any
// other event.
func tamperSeqOf(ev events.Event) uint64 {
	switch e := ev.(type) {
	case *events.Signal:
		return e.TamperSeq
	case *events.Ptrace:
		return e.TamperSeq
	}
	return 0
}

// tamperFirst says whether the tamper record seq is new: neither handled by
// this agent, nor marked done by it or an earlier one. A record can arrive
// twice: from the buffer and replayed from the table.
func (a *agent) tamperFirst(seq uint64, now time.Time) bool {
	if _, ok := a.tamperSeen[seq]; ok {
		return false
	}
	if a.tamper != nil {
		done, err := a.tamper.TamperDone(seq)
		if err != nil {
			// Unknown: handling it again is better than not at all.
			a.c.tamperErrors.Add(1)
		} else if done {
			return false
		}
	}
	if a.tamperSeen == nil {
		a.tamperSeen = map[uint64]time.Time{}
	}
	a.tamperSeen[seq] = now
	return true
}

// tamperTick runs every second: it reports lost tamper records, marks the
// handled ones done, and handles kept ones that never arrived.
func (a *agent) tamperTick(now time.Time) {
	a.checkTamperLost(now)
	if a.tamper == nil {
		return
	}
	for seq, at := range a.tamperSeen {
		if now.Sub(at) < tamperDoneAfter {
			continue
		}
		if err := a.tamper.SetTamperDone(seq); err != nil {
			a.c.tamperErrors.Add(1)
			continue
		}
		delete(a.tamperSeen, seq)
	}
	a.replayTamper(now)
}

// replayTamper handles the tamper records kept in the kernel that no agent
// handled: one read by an agent that was killed before it got to it, as the
// record of the SIGKILL itself can be, or one the tamper buffer had no room
// for. Their alerts name the sender as if they had come through the buffer.
func (a *agent) replayTamper(now time.Time) {
	if now.Sub(a.tamperStart) < tamperReplayStart {
		return
	}
	pending, err := a.tamper.TamperPending()
	if err != nil {
		a.c.tamperErrors.Add(1)
		return
	}
	boot := a.bootNS()
	for _, p := range pending {
		if _, ok := a.tamperSeen[p.Seq]; ok {
			continue
		}
		ev, err := events.Decode(p.Raw)
		if err != nil || tamperSeqOf(ev) != p.Seq {
			a.c.tamperErrors.Add(1)
			continue
		}
		if ts := ev.Hdr().TSBootNS; boot < ts || boot-ts < uint64(tamperReplayAge) {
			continue
		}
		a.c.tamperReplayed.Add(1)
		a.handle(ev)
	}
}

// tamperKinds pairs each kind the kernel counts with its record type.
var tamperKinds = []struct {
	kind loader.TamperKind
	typ  events.Type
}{
	{loader.TamperSignal, events.TypeSignal},
	{loader.TamperPtrace, events.TypePtrace},
}

// checkTamperLost raises an alert for tamper records the kernel counted but
// could not store, because the tamper buffer was full: a signal sent to the
// agent (R030) or an attach to it (R033) is then still reported, without
// its sender. The count of what was reported is kept in the kernel, so the
// agent after this one does not report the same records again.
func (a *agent) checkTamperLost(now time.Time) {
	if a.tamper == nil {
		return
	}
	for _, k := range tamperKinds {
		lost, reported, err := a.tamper.TamperLost(k.kind)
		if err != nil {
			a.c.tamperErrors.Add(1)
			continue
		}
		if lost <= reported {
			continue
		}
		n := lost - reported
		a.c.tamperLost.Add(n)
		rec := a.enricher.Lost(k.typ, n, now)
		if a.cur.cfg.Export.RawEvents {
			a.emit(rec)
		}
		for _, r := range a.cur.rules.Match(rec) {
			a.c.alert(r)
			a.emit(r.Alert(rec))
		}
		// Recorded after the alert: if the count cannot be written, the
		// same loss is reported again on the next tick, which is better
		// than not at all.
		if err := a.tamper.SetTamperReported(k.kind, lost); err != nil {
			a.c.tamperErrors.Add(1)
		}
	}
}
