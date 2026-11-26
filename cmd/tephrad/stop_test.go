// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"syscall"
	"testing"

	"github.com/tephrasec/tephra/internal/export"
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
