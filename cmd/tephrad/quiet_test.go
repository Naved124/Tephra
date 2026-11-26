// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/tephrasec/tephra/internal/loader"
)

func sumKey(pid uint32) loader.SummaryKey { return loader.SummaryKey{Pid: pid} }

func TestPlanSummaries(t *testing.T) {
	a, b, c := sumKey(1), sumKey(2), sumKey(3)
	sums := func(counts map[loader.SummaryKey]uint64) []loader.Summary {
		var out []loader.Summary
		for k, n := range counts {
			out = append(out, loader.Summary{Key: k, Count: n, LastNS: n})
		}
		return out
	}

	// First read: everything counted is new.
	out, take, next := planSummaries(nil, sums(map[loader.SummaryKey]uint64{a: 5, b: 2}))
	if len(out) != 2 || len(take) != 0 {
		t.Fatalf("first read: out %v take %v", out, take)
	}
	got := map[loader.SummaryKey]uint64{}
	for _, o := range out {
		got[o.sum.Key] = o.n
	}
	if got[a] != 5 || got[b] != 2 {
		t.Fatalf("first read reported %v", got)
	}

	// Second read: a grew by 3, b did not grow and is taken, c is new.
	out, take, next = planSummaries(next, sums(map[loader.SummaryKey]uint64{a: 8, b: 2, c: 1}))
	got = map[loader.SummaryKey]uint64{}
	for _, o := range out {
		got[o.sum.Key] = o.n
	}
	if got[a] != 3 || got[c] != 1 || len(got) != 2 {
		t.Errorf("second read reported %v, want a:3 c:1", got)
	}
	if len(take) != 1 || take[0].Key != b {
		t.Errorf("second read takes %v, want only b", take)
	}
	if _, kept := next[b]; kept {
		t.Error("a taken destination is still remembered")
	}

	// A destination taken and counted anew starts from zero, so nothing
	// counted is lost or reported twice.
	out, _, _ = planSummaries(next, sums(map[loader.SummaryKey]uint64{a: 2}))
	if len(out) != 1 || out[0].n != 2 {
		t.Errorf("recounted destination reported %v, want 2", out)
	}

	// An agent that adopts the counts of one that died starts from what
	// that one reported, and reports only the growth.
	adopted := map[loader.SummaryKey]loader.SummarySent{a: {Count: 5}}
	out, take, _ = planSummaries(adopted, sums(map[loader.SummaryKey]uint64{a: 9}))
	if len(out) != 1 || out[0].n != 4 || len(take) != 0 {
		t.Errorf("after adoption reported %v take %v, want a:4", out, take)
	}
}
