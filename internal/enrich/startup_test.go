// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
)

// Pid namespaces in the replays: the node's, and the container's.
const (
	hostPidNS uint32 = 4026531836
	ctrPidNS  uint32 = 4026532900
)

// runcStart replays a container start as runc does it on a node, as
// recorded on a kind node on 5.15: "runc create" on the host forks a child
// that re-executes a protected copy of runc as "runc init"; that process is
// moved into the container's cgroup and clones its setup stages there; the
// stage that created the container's pid namespace exits, and the last stage
// executes the container's program itself. A start hook, as kind installs,
// runs as a child of that last stage before it does.
type runcStart struct {
	f    *fixture
	host uint64
	pod  uint64
}

func newRuncStart(t *testing.T) *runcStart {
	f := newFixture(t)
	f.webPod()
	f.e.SetRuntimes(fakeRuntimes{{8, 100}: true})
	return &runcStart{f: f, host: f.cgroup("system.slice/containerd.service"), pod: f.cgroup(scope)}
}

func hdr(typ events.Type, pid uint32, cg uint64, pidns uint32) events.Header {
	return events.Header{Type: typ, PID: pid, StartTimeNS: uint64(pid) * 1000, CgroupID: cg, PidNS: pidns}
}

func (s *runcStart) exec(pid, ppid uint32, cg uint64, pidns uint32, path string, dev uint32, inode uint64, flags uint32, argv ...string) *export.Record {
	h := hdr(events.TypeExec, pid, cg, pidns)
	h.PPID, h.Flags = ppid, flags
	return s.f.e.Handle(&events.Exec{Header: h, Path: path, Dev: dev, Inode: inode, Argv: argv}, time.Now())
}

func (s *runcStart) fork(parent, child uint32, cg uint64, pidns uint32) *export.Record {
	return s.f.e.Handle(&events.Fork{
		Header:   hdr(events.TypeFork, parent, cg, pidns),
		ChildPID: child, ChildStartNS: uint64(child) * 1000, ParentPID: parent, ParentStartNS: uint64(parent) * 1000,
	}, time.Now())
}

func (s *runcStart) exit(pid uint32, cg uint64, pidns uint32) {
	s.f.e.Handle(&events.Exit{Header: hdr(events.TypeExit, pid, cg, pidns)}, time.Now())
}

func (s *runcStart) net(typ events.Type, pid uint32, remote string) *export.Record {
	return s.f.e.Handle(&events.Net{
		Header: hdr(typ, pid, s.pod, ctrPidNS),
		Family: events.AFInet, Proto: 6,
		Local:  netip.MustParseAddrPort("10.244.1.5:8888"),
		Remote: netip.MustParseAddrPort(remote),
	}, time.Now())
}

// setup runs runc up to the stage that will execute the program, pid 73.
// With hook set, kind's start hook runs first, as a child of that stage.
func (s *runcStart) setup(hook bool) {
	s.exec(70, 60, s.host, hostPidNS, "/usr/local/sbin/runc", 8, 100, 0, "runc", "create")
	s.fork(70, 71, s.host, hostPidNS)
	s.exec(71, 70, s.host, hostPidNS, "/proc/self/fd/6", 1, 5, events.ExecUnlinked, "runc", "init")
	s.fork(71, 72, s.pod, hostPidNS) // runc:[1:CHILD], which unshares the pid namespace
	s.fork(72, 73, s.pod, ctrPidNS)  // runc:[2:INIT], pid 1 of the container
	s.exit(72, s.pod, ctrPidNS)
	if hook {
		s.fork(73, 74, s.pod, ctrPidNS)
		rec := s.exec(74, 73, s.pod, ctrPidNS, "/bin/bash", 9, 6000, 0, "/bin/bash", "/kind/bin/mount-product-files.sh")
		if rec.Process.IsMainBinary {
			s.f.t.Errorf("the start hook was taken for the main binary: %s", toJSON(s.f.t, rec))
		}
		s.exit(74, s.pod, ctrPidNS)
	}
}

// The notebook: the container's program is Python itself. Its own
// connections and the terminals it starts belong to the application.
func pythonApplication(t *testing.T, hook bool) {
	s := newRuncStart(t)
	s.setup(hook)
	if rec := s.exec(73, 72, s.pod, ctrPidNS, "/usr/local/bin/python3", 9, 7000, 0, "python3", "-u", "-c", "notebook"); !rec.Process.IsMainBinary {
		t.Errorf("the program runc started is not the main binary: %s", toJSON(t, rec))
	}
	if rec := s.net(events.TypeAccept, 73, "127.0.0.1:41000"); !rec.Process.IsMainBinary {
		t.Errorf("the application accepting a connection: %s", toJSON(t, rec))
	}
	s.fork(73, 90, s.pod, ctrPidNS)
	rec := s.exec(90, 73, s.pod, ctrPidNS, "/bin/sh", 9, 7100, events.ExecStdinPty|events.ExecStdoutPty, "sh", "-c", "ls /")
	if rec.Parent == nil || !rec.Parent.IsMainBinary || !rec.Parent.ContainerFirst || rec.Process.IsMainBinary {
		t.Errorf("a terminal the application starts: %s", toJSON(t, rec))
	}
}

// The worker: the container's program is a shell loop that starts Python.
// That Python is started directly by the container's first process.
func entrypointWorker(t *testing.T, hook bool) {
	s := newRuncStart(t)
	s.setup(hook)
	if rec := s.exec(73, 72, s.pod, ctrPidNS, "/bin/sh", 9, 7100, 0, "sh", "-c", "while true; do python3 -c fetch; sleep 10; done"); !rec.Process.IsMainBinary {
		t.Errorf("the entrypoint shell is not the main binary: %s", toJSON(t, rec))
	}
	s.fork(73, 90, s.pod, ctrPidNS)
	s.exec(90, 73, s.pod, ctrPidNS, "/usr/local/bin/python3", 9, 7000, 0, "python3", "-c", "fetch")
	rec := s.net(events.TypeConnect, 90, "10.96.0.10:53")
	if rec.Parent == nil || !rec.Parent.ContainerFirst || rec.Process.IsMainBinary {
		t.Errorf("python under the entrypoint: %s", toJSON(t, rec))
	}
}

func TestRuncStartPythonApplication(t *testing.T)         { pythonApplication(t, false) }
func TestRuncStartPythonApplicationWithHook(t *testing.T) { pythonApplication(t, true) }
func TestRuncStartEntrypointWorker(t *testing.T)          { entrypointWorker(t, false) }
func TestRuncStartEntrypointWorkerWithHook(t *testing.T)  { entrypointWorker(t, true) }

// Events from different CPUs can be handled out of order: here the exit of
// the stage that created the pid namespace comes after the program started.
func TestRuncStartExitHandledLate(t *testing.T) {
	s := newRuncStart(t)
	s.exec(70, 60, s.host, hostPidNS, "/usr/local/sbin/runc", 8, 100, 0, "runc", "create")
	s.fork(70, 71, s.host, hostPidNS)
	s.exec(71, 70, s.host, hostPidNS, "/proc/self/fd/6", 1, 5, events.ExecUnlinked, "runc", "init")
	s.fork(71, 72, s.pod, hostPidNS)
	s.fork(72, 73, s.pod, ctrPidNS)
	s.fork(73, 74, s.pod, ctrPidNS)
	s.exec(74, 73, s.pod, ctrPidNS, "/bin/bash", 9, 6000, 0, "/bin/bash", "/kind/bin/mount-product-files.sh")
	if rec := s.exec(73, 72, s.pod, ctrPidNS, "/usr/local/bin/python3", 9, 7000, 0, "python3", "app"); !rec.Process.IsMainBinary {
		t.Errorf("with the hook still running and the setup stage not yet seen to exit: %s", toJSON(t, rec))
	}
	s.exit(74, s.pod, ctrPidNS)
	s.exit(72, s.pod, ctrPidNS)
}
