// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tephrasec/tephra/internal/events"
	"github.com/tephrasec/tephra/internal/filter"
)

// Under ring buffer pressure the opens of one file by one program are sent
// once a window and counted in between. Every open is accounted for: it
// arrives as a record or is counted in a summary, never neither. Taking a
// summary starts a new one. With the window at zero nothing is counted.
func TestFileSummaries(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "tfs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	file := filepath.Join(dir, "secret")
	touch(t, file)
	var st, exe syscall.Stat_t
	if err := syscall.Stat(file, &st); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat("/proc/self/exe", &exe); err != nil {
		t.Fatal(err)
	}

	// A small buffer, not read until the end, comes under pressure fast.
	s := loadForTest(t, Options{RingBufSize: 1 << 14, Filters: filter.Set{Watches: []filter.Watch{
		{Kind: filter.Exact, Path: file, Bits: filter.Read},
	}}})
	if err := s.SetFileSummaryWindow(time.Hour); err != nil {
		t.Fatal(err)
	}
	open := func(n int) {
		for i := 0; i < n; i++ {
			f, err := os.Open(file)
			if err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
		}
	}
	take := func() (FileSummary, bool) {
		t.Helper()
		keys, err := s.FileSummaryKeys()
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if k.FileInode != st.Ino {
				continue
			}
			sum, ok, err := s.TakeFileSummary(k)
			if err != nil {
				t.Fatal(err)
			}
			return sum, ok
		}
		return FileSummary{}, false
	}

	const n1, n2 = 600, 400
	open(n1)
	sum1, ok := take()
	if !ok || sum1.Count == 0 {
		t.Fatalf("no file summary after %d opens into a small unread buffer", n1)
	}
	if sum1.First == nil || sum1.First.Path != file || sum1.First.PID != self() {
		t.Errorf("summary's first open %+v: want %s by pid %d", sum1.First, file, self())
	}
	if sum1.Key.ProgInode != exe.Ino || sum1.Key.CgroupId == 0 || sum1.Key.Write != 0 {
		t.Errorf("summary key %+v: want program inode %d, a cgroup, read", sum1.Key, exe.Ino)
	}
	if _, again := take(); again {
		t.Error("a taken summary is still in the map")
	}
	// The next opens start a new summary.
	open(n2)
	sum2, ok := take()
	if !ok || sum2.Count == 0 {
		t.Fatalf("no new file summary after taking the first and %d more opens", n2)
	}

	// Every open is a record or a count.
	records := 0
	nextFrom(t, s.Events(), 2*time.Second, func(f *events.FileOpen) bool {
		if f.PID == self() && f.Path == file {
			records++
		}
		return false
	})
	if got := uint64(records) + sum1.Count + sum2.Count; got != n1+n2 {
		t.Errorf("%d records + %d + %d counted = %d, want %d opens accounted for", records, sum1.Count, sum2.Count, got, n1+n2)
	}
	if records >= n1+n2 {
		t.Errorf("%d records for %d opens: nothing was counted instead", records, n1+n2)
	}
	counted, _, err := s.FileSummaryCounts()
	if err != nil {
		t.Fatal(err)
	}
	if counted < sum1.Count+sum2.Count {
		t.Errorf("file_sum_count %d below the summaries' %d", counted, sum1.Count+sum2.Count)
	}
	t.Logf("%d opens: %d records, %d and %d counted (first delivered: %v, %v)", n1+n2, records, sum1.Count, sum2.Count, sum1.Delivered, sum2.Delivered)

	// Off: under the same pressure nothing is counted.
	if err := s.SetFileSummaryWindow(0); err != nil {
		t.Fatal(err)
	}
	open(n1)
	open(n1) // the buffer, read above, fills again
	if _, ok := take(); ok {
		t.Error("a file summary was made with the window at zero")
	}
}
