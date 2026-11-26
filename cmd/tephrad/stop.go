// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/tephrasec/tephra/internal/events"
	"github.com/tephrasec/tephra/internal/export"
	"github.com/tephrasec/tephra/internal/loader"
)

// stopWait is how long the agent waits, once asked to stop, for the kernel's
// record of who asked.
const stopWait = 2 * time.Second

// stopSignal is what the kernel saw send the agent its last SIGTERM or SIGINT.
type stopSignal struct {
	seen    bool
	planned bool
	sender  string
}

// plannedSender reports whether a signal to the agent came the way
// Kubernetes stops a pod: from the container runtime, systemd or kubelet
// (recognised by the identity of the file, not its name), or from the node's
// first process at shutdown. Only someone allowed to manage the agent's pods
// or the node can make one of these send it.
func plannedSender(rec *export.Record) bool {
	return rec.Process.Runtime || (rec.Container == nil && rec.Process.PID == 1)
}

// noteSignal remembers who sent the agent a stop signal.
func (a *agent) noteSignal(rec *export.Record) {
	s := rec.Signal
	if s == nil || s.TargetPID != uint32(os.Getpid()) {
		return
	}
	if s.Number != uint32(syscall.SIGTERM) && s.Number != uint32(syscall.SIGINT) {
		return
	}
	a.stop = stopSignal{seen: true, planned: plannedSender(rec), sender: rec.Process.Image}
}

// awaitStop decides whether the stop the agent was just asked for is
// planned. It handles the events that arrive meanwhile, one of which should
// be the kernel's record of the signal. A stop nobody can be seen asking for
// is not planned: a signal from the kernel itself, such as a terminal's ^C,
// or one whose record was lost.
func (a *agent) awaitStop(queue <-chan events.Event) (planned bool, why string) {
	if !a.sensor.Available(events.TypeSignal) {
		// Without the hook nothing tells a rollout from an attack.
		return true, "the kernel does not report signals, so every stop is taken as planned"
	}
	deadline := time.After(stopWait)
	for !a.stop.seen {
		select {
		case ev := <-queue:
			a.handle(ev)
		case <-deadline:
			return false, "no record of who sent the signal"
		}
	}
	if a.stop.planned {
		return true, "sent by " + a.stop.sender
	}
	return false, "sent by " + a.stop.sender + ", which is not how Kubernetes stops a pod"
}

const detectUsage = `usage:
  tephrad detect off [pin directory]

off removes the detection an agent left pinned when it did not stop the
way Kubernetes stops a pod (it was killed, crashed or was stopped by hand).
Its programs detach and what they recorded since is discarded. A running
agent's pins are removed too, and come back when it restarts. The pin
directory defaults to ` + loader.DefaultDetectPinDir + `.
`

// detectCmd runs "tephrad detect ..." and returns the exit code.
func detectCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || len(args) > 2 || args[0] != "off" {
		_, _ = fmt.Fprint(stderr, detectUsage)
		return 2
	}
	dir := loader.DefaultDetectPinDir
	if len(args) == 2 {
		dir = args[1]
	}
	pinned, err := loader.DetectionOff(dir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if !pinned {
		_, _ = fmt.Fprintf(stdout, "nothing is pinned in %s\n", dir)
		return 0
	}
	_, _ = fmt.Fprintln(stdout, "pinned detection removed")
	return 0
}
