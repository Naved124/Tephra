// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"syscall"
	"testing"

	"github.com/tephrasec/tephra/internal/events"
	"github.com/tephrasec/tephra/internal/export"
	"github.com/tephrasec/tephra/internal/loader"
)

func sigRec(image string, pid uint32, runtime, inPod bool, sig syscall.Signal) *export.Record {
	r := &export.Record{
		Type:    "signal",
		Process: export.Process{PID: pid, Image: image, Runtime: runtime},
		K8s:     export.K8s{Namespace: "host"},
		Signal:  &export.Signal{Number: uint32(sig), TargetPID: uint32(os.Getpid())},
	}
	if inPod {
		r.Container = &export.Container{ID: "f603c429"}
		r.K8s.Namespace = "shop"
	}
	return r
}

// Who may stop the agent quietly: the runtime, the node's init. Nobody else.
func TestStopJudgement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rec     *export.Record
		seen    bool
		planned bool
	}{
		{"runtime SIGTERM", sigRec("/usr/bin/runc", 6001, true, false, syscall.SIGTERM), true, true},
		{"node init SIGTERM", sigRec("/sbin/init", 1, false, false, syscall.SIGTERM), true, true},
		{"pod shell SIGTERM", sigRec("/bin/busybox", 5120, false, true, syscall.SIGTERM), true, false},
		{"pid 1 of a pod", sigRec("/bin/sh", 1, false, true, syscall.SIGTERM), true, false},
		{"host python SIGINT", sigRec("/usr/bin/python3", 7001, false, false, syscall.SIGINT), true, false},
		{"SIGSTOP is not a stop request", sigRec("/bin/busybox", 5120, false, true, syscall.SIGSTOP), false, false},
	} {
		a := &agent{}
		a.noteSignal(tc.rec)
		if a.stop.seen != tc.seen || a.stop.planned != tc.planned {
			t.Errorf("%s: seen %v planned %v, want %v %v", tc.name, a.stop.seen, a.stop.planned, tc.seen, tc.planned)
		}
	}
	// A signal to another process is not about the agent.
	a := &agent{}
	r := sigRec("/usr/bin/runc", 6001, true, false, syscall.SIGTERM)
	r.Signal.TargetPID = uint32(os.Getpid()) + 1
	a.noteSignal(r)
	if a.stop.seen {
		t.Error("signal to another process taken as the agent's")
	}
}

type countCloser struct{ n int }

func (c *countCloser) Close() error { c.n++; return nil }

// An agent whose recording outlives it stops reading the kernel first, then
// handles what it had already read, so nothing between its stop and the
// next agent is lost. After a planned stop it marks the tamper records it
// handled done, so the next agent does not raise Kubernetes' own SIGTERM as
// an attack; after an unplanned one it leaves them, so the next agent raises
// them again if this one's alerts never got out.
func TestHandOver(t *testing.T) {
	for _, planned := range []bool{true, false} {
		f := &fakeTamper{reported: map[loader.TamperKind]uint64{}}
		a, out := tamperAgent(t, f)
		const seq = 1<<12 | 7
		ev, err := events.Decode(tamperRaw(events.TypeSignal, seq, 90e9, 555, 4242, uint32(syscall.SIGTERM)))
		if err != nil {
			t.Fatal(err)
		}
		queue := make(chan events.Event, 4)
		queue <- ev
		readErr := make(chan error, 2)
		readErr <- nil
		readErr <- nil
		rd1, rd2 := &countCloser{}, &countCloser{}

		if err := a.handOver(planned, queue, readErr, 2, rd1, rd2); err != nil {
			t.Fatal(err)
		}
		if rd1.n != 1 || rd2.n != 1 {
			t.Errorf("planned=%v: readers closed %d and %d times, want once each", planned, rd1.n, rd2.n)
		}
		if len(queue) != 0 {
			t.Errorf("planned=%v: %d events left in the queue, lost with the agent", planned, len(queue))
		}
		if got := alerts(t, a, out); got["R030"] == nil {
			t.Errorf("planned=%v: the queued signal was not handled: %v", planned, got)
		}
		if f.done[seq] != planned {
			t.Errorf("planned=%v: tamper record marked done = %v, want %v", planned, f.done[seq], planned)
		}
	}
}
