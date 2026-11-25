// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/events"
)

// dialSelf connects to ln and accepts the connection, then returns the
// connect event the kernel reported for it, or nil.
func dialSelf(t *testing.T, s *Sensor, ln net.Listener, target string, wait time.Duration) *events.Net {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	conn, err := net.Dial("tcp", target)
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	if c := <-accepted; c != nil {
		_ = c.Close()
	}
	_ = conn.Close()
	// The connect hook runs before the kernel picks the local port, so the
	// event is told apart by its destination; each dial reads its own event
	// before the next dial starts.
	dst := netip.MustParseAddrPort(target)
	return next(t, s, wait, func(n *events.Net) bool {
		return n.PID == self() && n.Type == events.TypeConnect && n.Remote == dst
	})
}

func TestQuietConnections(t *testing.T) {
	s := loadForTest(t, Options{})
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	loop := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)).String()

	first := dialSelf(t, s, ln, loop, 5*time.Second)
	if first == nil {
		t.Fatal("no connect event before any mark")
	}
	if first.ExecID == 0 {
		t.Error("exec_id is 0")
	}
	mark := MarkOf(first, QuietOut|QuietIn)

	// Marked: neither the connect nor the accept is emitted, and both
	// are counted.
	if err := s.SetQuiet(self(), mark); err != nil {
		t.Fatal(err)
	}
	quietBefore, _ := s.QuietCount()
	filtBefore, _ := s.ReadStats(events.TypeConnect)
	if e := dialSelf(t, s, ln, loop, time.Second); e != nil {
		t.Fatalf("connect emitted from a quiet process: %+v", e)
	}
	quietAfter, _ := s.QuietCount()
	filtAfter, _ := s.ReadStats(events.TypeConnect)
	if quietAfter-quietBefore < 2 {
		t.Errorf("quiet count grew by %d, want at least 2 (connect and accept)", quietAfter-quietBefore)
	}
	if filtAfter.Filtered == filtBefore.Filtered {
		t.Error("a quiet connect was not counted as filtered")
	}

	// A mark judged before another exec does not apply.
	stale := mark
	stale.ExecID++
	if err := s.SetQuiet(self(), stale); err != nil {
		t.Fatal(err)
	}
	if dialSelf(t, s, ln, loop, 5*time.Second) == nil {
		t.Error("a mark with another exec count hid a connect")
	}

	// A destination port a rule names is reported from a quiet process.
	if err := s.SetQuiet(self(), mark); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlwaysReport([]uint16{uint16(port)}, nil); err != nil {
		t.Fatal(err)
	}
	if dialSelf(t, s, ln, loop, 5*time.Second) == nil {
		t.Error("a quiet mark hid a connect to an always-reported port")
	}
	// So is an always-reported destination address.
	if err := s.SetAlwaysReport(nil, []netip.AddrPort{netip.MustParseAddrPort(loop)}); err != nil {
		t.Fatal(err)
	}
	if dialSelf(t, s, ln, loop, 5*time.Second) == nil {
		t.Error("a quiet mark hid a connect to an always-reported address")
	}
	if err := s.SetAlwaysReport(nil, nil); err != nil {
		t.Fatal(err)
	}

	// Counted, not lost: with the summary bit the connections are skipped
	// and each destination is counted once per process.
	if err := s.SetQuiet(self(), MarkOf(first, QuietOut|QuietIn|QuietSummary)); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if e := dialSelf(t, s, ln, loop, 300*time.Millisecond); e != nil {
			t.Fatal("a summarised connect was also emitted")
		}
	}
	sums, err := s.Summaries()
	if err != nil {
		t.Fatal(err)
	}
	var out, in *Summary
	for i := range sums {
		x := &sums[i]
		if x.PID != self() || x.StartNS != first.StartTimeNS || x.Port != uint16(port) {
			continue
		}
		switch x.Type {
		case uint32(events.TypeConnect):
			out = x
		case uint32(events.TypeAccept):
			in = x
		}
	}
	if out == nil || out.Count != 3 || out.Remote != netip.MustParseAddr("127.0.0.1") || out.Family != events.AFInet {
		t.Fatalf("connect summary = %+v, want 3 connections to 127.0.0.1:%d", out, port)
	}
	if out.FirstNS == 0 || out.LastNS < out.FirstNS || out.CgroupID != first.CgroupID || out.MntNS != first.MntNS || out.Comm == "" {
		t.Errorf("connect summary does not carry the process's header: %+v", out)
	}
	// The accepting side is the same test process; the accept is counted
	// under the listening port, without the client's own port.
	if in == nil || in.Count != 3 {
		t.Fatalf("accept summary = %+v, want 3 accepts on port %d", in, port)
	}
	got, ok, err := s.TakeSummary(out.Key)
	if err != nil || !ok || got.Count != 3 {
		t.Fatalf("TakeSummary = %+v, %v, %v", got, ok, err)
	}
	if _, ok, _ := s.TakeSummary(out.Key); ok {
		t.Error("a taken summary was still there")
	}
	// What the agent reported is kept beside the counts.
	if err := s.SetSent(in.Key, SummarySent{Count: 2, LastNS: in.LastNS}); err != nil {
		t.Fatal(err)
	}
	if sent, err := s.SentSummaries(); err != nil || sent[in.Key].Count != 2 {
		t.Errorf("SentSummaries = %v, %v", sent[in.Key], err)
	}
	if err := s.ForgetSent(in.Key); err != nil {
		t.Fatal(err)
	}
	if sent, _ := s.SentSummaries(); len(sent) != 0 {
		t.Errorf("forgotten sent count still there: %v", sent)
	}

	// Taken back: reported again.
	if err := s.ClearQuiet(self()); err != nil {
		t.Fatal(err)
	}
	if dialSelf(t, s, ln, loop, 5*time.Second) == nil {
		t.Error("connect not reported after the mark was removed")
	}
	if err := s.ClearAllQuiet(); err != nil {
		t.Fatal(err)
	}
}

// With batched wake-ups a record still reaches a reader that reads on a
// timer, without the batch filling.
func TestRingWakeupBatch(t *testing.T) {
	s := loadForTest(t, Options{})
	if err := s.SetRingWakeup(1 << 19); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if dialSelf(t, s, ln, ln.Addr().String(), 5*time.Second) == nil {
		t.Error("no connect event with batched wake-ups")
	}
}
