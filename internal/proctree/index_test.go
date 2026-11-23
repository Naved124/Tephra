// SPDX-License-Identifier: Apache-2.0

package proctree

import (
	"math/rand"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/events"
)

// scanOldest and scanFirstBorn are the full scans the index replaced.
func scanOldest(t *Tree, cid string, pidNS uint32, byNS bool) (Key, bool) {
	var best *Proc
	for _, p := range t.procs {
		if p.ContainerID == cid && (!byNS || p.PidNS == pidNS) && (best == nil || p.Key.StartNS < best.Key.StartNS) {
			best = p
		}
	}
	if best == nil {
		return Key{}, false
	}
	return best.Key, true
}

// The cached answers must equal a full scan after any sequence of changes:
// forks, execs that change pid namespace, exits, reaping, eviction at
// capacity, a container recorded late, and seeded entries replaced by
// events. Start times are unique, so the oldest is unambiguous.
func TestContainerIndexMatchesScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	tr := New(64, time.Second)
	cids := []string{"a", "b", "c"}
	var keys []Key
	start := uint64(1_000_000_000)
	now := time.Unix(1000, 0)
	pick := func() (Key, bool) {
		if len(keys) == 0 {
			return Key{}, false
		}
		return keys[rng.Intn(len(keys))], true
	}
	for step := 0; step < 20000; step++ {
		start += uint64(1 + rng.Intn(3*nsPerTick))
		switch op := rng.Intn(9); op {
		case 0: // a process seeded from /proc
			k := Key{PID: uint32(1 + rng.Intn(500)), StartNS: start}
			tr.Add(Proc{Key: k, ContainerID: cids[rng.Intn(3)], PidNS: uint32(rng.Intn(2))})
			keys = append(keys, k)
		case 1, 2: // fork
			if src, ok := pick(); ok {
				k := Key{PID: uint32(1 + rng.Intn(500)), StartNS: start}
				tr.Fork(&events.Fork{Header: events.Header{PID: src.PID, StartTimeNS: src.StartNS, PidNS: uint32(rng.Intn(2))},
					ChildPID: k.PID, ChildStartNS: k.StartNS, ParentPID: src.PID, ParentStartNS: src.StartNS})
				keys = append(keys, k)
			}
		case 3: // exec, sometimes into another pid namespace; sometimes
			// for a seeded process, replacing its tick-precise entry
			if k, ok := pick(); ok {
				tr.Exec(&events.Exec{Header: events.Header{PID: k.PID, StartTimeNS: k.StartNS, PidNS: uint32(rng.Intn(2))}, Path: "/bin/true"})
			}
		case 4: // exec of a process never seen forking
			k := Key{PID: uint32(1 + rng.Intn(500)), StartNS: start}
			tr.Exec(&events.Exec{Header: events.Header{PID: k.PID, StartTimeNS: k.StartNS, PidNS: uint32(rng.Intn(2))}, Path: "/bin/sh"})
			keys = append(keys, k)
		case 5:
			if k, ok := pick(); ok {
				tr.Exit(&events.Exit{Header: events.Header{PID: k.PID, StartTimeNS: k.StartNS}}, now)
			}
		case 6:
			if k, ok := pick(); ok {
				tr.SetContainerID(k, cids[rng.Intn(3)])
			}
		case 7:
			now = now.Add(time.Duration(rng.Intn(600)) * time.Millisecond)
			tr.Reap(now)
		case 8:
			if k, ok := pick(); ok {
				tr.MarkExited(k, now)
			}
		}
		// Ask in a random order, so that answers are cached at
		// different points of the sequence.
		for _, i := range rng.Perm(len(cids)) {
			cid := cids[i]
			want, wok := scanOldest(tr, cid, 0, false)
			got, gok := tr.OldestInContainer(cid)
			if wok != gok || (gok && got.Key != want) {
				t.Fatalf("step %d: OldestInContainer(%s) = %v %v, scan = %v %v", step, cid, got.Key, gok, want, wok)
			}
			ns := uint32(rng.Intn(2))
			want, wok = scanOldest(tr, cid, ns, true)
			got, gok = tr.FirstBornIn(cid, ns)
			if wok != gok || (gok && got.Key != want) {
				t.Fatalf("step %d: FirstBornIn(%s, %d) = %v %v, scan = %v %v", step, cid, ns, got.Key, gok, want, wok)
			}
		}
		if len(keys) > 400 {
			keys = keys[200:]
		}
	}
	// Nothing left behind for processes gone from the tree.
	n := 0
	for _, m := range tr.members {
		n += len(m)
	}
	inContainers := 0
	for _, p := range tr.procs {
		if p.ContainerID != "" {
			inContainers++
		}
	}
	if n != inContainers {
		t.Errorf("index holds %d processes, tree has %d in containers", n, inContainers)
	}
}
