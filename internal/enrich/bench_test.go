// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tephrasec/tephra/internal/events"
	"github.com/tephrasec/tephra/internal/identity"
	"github.com/tephrasec/tephra/internal/proctree"
	"github.com/tephrasec/tephra/internal/rules"
)

// BenchmarkExecChurn replays the event shape of the exec benchmark: a
// process in a pod forks, the child executes /bin/true and exits. Each
// iteration is those three events, through the enricher, the shipped rules
// and the JSON encoding of every record. The children are gone from /proc
// by the time their events are handled, as on a node where the agent runs
// behind. It finds where the agent's time goes; it says nothing about a
// node's absolute numbers.
func BenchmarkExecChurn(b *testing.B) {
	f := newFixture(b)
	fs := proctree.ProcFS{Root: f.proc}
	f.e.alive = func(p proctree.Proc, mnt uint32) bool { return fs.Alive(p.Key, mnt) }
	f.e.SetIdentity(identity.New(f.proc))
	set, err := rules.Load("../../rules")
	if err != nil {
		b.Fatal(err)
	}
	// The node's init, which a real node's tree is seeded with, ends
	// every ancestry walk.
	f.procEntry(1, 0, 1, "/sbin/init", "/sbin/init")
	parent := f.webShell("/bin/sh", "sh", "-c", "while :; do /bin/true; done")
	parent.Type = events.TypeFork

	b.ReportAllocs()
	b.ResetTimer()
	start := uint64(200_000_000_000)
	for i := 0; i < b.N; i++ {
		now := time.Now()
		child := events.Header{PID: 60000 + uint32(i%30000), StartTimeNS: start + uint64(i)*1000, PPID: parent.PID, CgroupID: parent.CgroupID, UID: 33, GID: 33}
		fork := &events.Fork{Header: parent, ChildPID: child.PID, ChildStartNS: child.StartTimeNS, ParentPID: parent.PID, ParentStartNS: parent.StartTimeNS}
		exec := &events.Exec{Header: child, Path: "/bin/true", Argv: []string{"/bin/true"}, Inode: 4242, Dev: 0x800001, CtimeNS: 1}
		exec.Type = events.TypeExec
		exit := &events.Exit{Header: child}
		exit.Type = events.TypeExit
		for _, ev := range []events.Event{fork, exec, exit} {
			rec := f.e.Handle(ev, now)
			if rec == nil {
				continue
			}
			for _, r := range set.Match(rec) {
				if _, err := json.Marshal(r.Alert(rec)); err != nil {
					b.Fatal(err)
				}
			}
			if _, err := json.Marshal(rec); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(3*b.N), "ns/event")
}

// BenchmarkNetChurn replays the network benchmarks' event shape: a client
// in a pod connects and the server, nginx, accepts, a new connection each
// time. Each iteration is the two events through the enricher and the
// shipped rules, as the "alerts only" configuration handles them: judged,
// not exported. Loopback is the sidecar case, both ends in one pod.
func BenchmarkNetChurn(b *testing.B) {
	for _, tc := range []struct {
		name           string
		client, server string
	}{
		{"pod", "10.244.1.7", "10.244.1.9"},
		{"loopback", "127.0.0.1", "127.0.0.1"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			f := newFixture(b)
			f.procEntry(1, 0, 1, "/sbin/init", "/sbin/init")
			fs := proctree.ProcFS{Root: f.proc}
			f.e.alive = func(p proctree.Proc, mnt uint32) bool { return fs.Alive(p.Key, mnt) }
			f.e.SetIdentity(identity.New(f.proc))
			set, err := rules.Load("../../rules")
			if err != nil {
				b.Fatal(err)
			}
			client := f.webShell("/usr/bin/ab", "ab", "-n", "200000", "-c", "32", "http://web/")
			server := events.Header{PID: 48190, StartTimeNS: 2000 * tick, PPID: 100, CgroupID: client.CgroupID, UID: 33, GID: 33}
			alerts := 0
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				port := uint16(32768 + i%28000)
				c := &events.Net{Header: client, Family: unix.AF_INET, Proto: unix.IPPROTO_TCP,
					Local:  netip.AddrPortFrom(netip.MustParseAddr(tc.client), port),
					Remote: netip.AddrPortFrom(netip.MustParseAddr(tc.server), 80)}
				c.Type = events.TypeConnect
				a := &events.Net{Header: server, Family: unix.AF_INET, Proto: unix.IPPROTO_TCP,
					Local:  netip.AddrPortFrom(netip.MustParseAddr(tc.server), 80),
					Remote: netip.AddrPortFrom(netip.MustParseAddr(tc.client), port)}
				a.Type = events.TypeAccept
				for _, ev := range []events.Event{c, a} {
					rec := f.e.Handle(ev, time.Now())
					if rec == nil {
						continue
					}
					for _, r := range set.Match(rec) {
						alerts++
						if _, err := json.Marshal(r.Alert(rec)); err != nil {
							b.Fatal(err)
						}
					}
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(2*b.N), "ns/event")
			b.ReportMetric(float64(alerts)/float64(b.N), "alerts/op")
		})
	}
}
