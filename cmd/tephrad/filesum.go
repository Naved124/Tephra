// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/tephrasec/tephra/internal/events"
	"github.com/tephrasec/tephra/internal/export"
	"github.com/tephrasec/tephra/internal/loader"
)

// drainFileSummaries takes every file summary the kernel holds and reports
// it. It runs once a window: the kernel then starts a new entry with each
// key's next open and sends that open, so a flood that goes on leaves one
// record and one count per key and window.
func (a *agent) drainFileSummaries(now time.Time) {
	keys, err := a.sensor.FileSummaryKeys()
	if err != nil {
		a.c.fileSumErrors.Add(1)
		return
	}
	for _, k := range keys {
		sum, ok, err := a.sensor.TakeFileSummary(k)
		if err != nil {
			a.c.fileSumErrors.Add(1)
			continue
		}
		if ok && sum.Count > 0 {
			a.reportFileSummary(sum, now)
		}
	}
}

// reportFileSummary sends one summary. When a record of the key reached the
// agent, the count is a file_summary record, and the rules have judged that
// record already. When none did, the summary is all there is of these opens,
// and it is handled as the first of them would have been, rules included.
func (a *agent) reportFileSummary(sum loader.FileSummary, now time.Time) {
	// The second event of an overlayfs open is dropped as a duplicate of
	// the first; a summary has no duplicate, whichever of the two it
	// kept.
	sum.First.Flags &^= events.FileKernelCreds
	rec := a.enricher.Handle(sum.First, now)
	if rec == nil || rec.File == nil {
		a.c.fileSumUnattributed.Add(1)
		return
	}
	rec.File.Count = sum.Count
	rec.File.FirstSeen = a.enricher.Wall(sum.First.TSBootNS)
	rec.File.LastSeen = a.enricher.Wall(sum.LastNS)
	if sum.Delivered {
		a.c.fileSummaries.Add(1)
		if a.cur.cfg.Export.RawEvents {
			rec.Type = export.TypeFileSummary
			a.emit(rec)
		}
		return
	}
	a.c.fileSumUndelivered.Add(1)
	if a.cur.cfg.Export.RawEvents {
		a.emit(rec)
	}
	for _, r := range a.cur.rules.Match(rec) {
		if a.judgedByKernel(r, rec) {
			continue
		}
		a.c.alert(r)
		a.emit(r.Alert(rec))
	}
}
