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
	local := netip.MustParseAddrPort(conn.LocalAddr().String())
	if c := <-accepted; c != nil {
		_ = c.Close()
	}
	_ = conn.Close()
	return next(t, s, wait, func(n *events.Net) bool {
		return n.PID == self() && n.Type == events.TypeConnect && n.Local.Port() == local.Port()
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

	// Loopback only: loopback skipped, any other address reported.
	if err := s.SetQuiet(self(), MarkOf(first, QuietOut|QuietIn|QuietLoopback)); err != nil {
		t.Fatal(err)
	}
	if e := dialSelf(t, s, ln, loop, time.Second); e != nil {
		t.Error("a loopback-only mark did not hide a loopback connect")
	}
	if other := nonLoopback(t); other.IsValid() {
		target := netip.AddrPortFrom(other, uint16(port)).String()
		if dialSelf(t, s, ln, target, 5*time.Second) == nil {
			t.Errorf("a loopback-only mark hid a connect to %s", target)
		}
	} else {
		t.Log("no non-loopback IPv4 address; that case is not checked")
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

func nonLoopback(t *testing.T) netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
			return p.Addr()
		}
	}
	return netip.Addr{}
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
