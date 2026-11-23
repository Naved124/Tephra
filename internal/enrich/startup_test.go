// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
)

// runcStart replays a container start as runc does it on a node: "runc
// create" on the host forks a child that re-executes a protected copy of runc
// as "runc init"; that process is moved into the container's cgroup and
// clones its setup stages there; the last stage executes the container's
// program. No stage but the last executes anything.
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

func (s *runcStart) exec(pid, ppid uint32, cg uint64, path string, dev uint32, inode uint64, flags uint32, argv ...string) *export.Record {
	return s.f.e.Handle(&events.Exec{
		Header: events.Header{Type: events.TypeExec, PID: pid, StartTimeNS: uint64(pid) * 1000, PPID: ppid, CgroupID: cg, Flags: flags},
		Path:   path, Dev: dev, Inode: inode, Argv: argv,
	}, time.Now())
}

func (s *runcStart) fork(parent, child uint32, cg uint64) *export.Record {
	return s.f.e.Handle(&events.Fork{
		Header:   events.Header{Type: events.TypeFork, PID: parent, StartTimeNS: uint64(parent) * 1000, CgroupID: cg},
		ChildPID: child, ChildStartNS: uint64(child) * 1000, ParentPID: parent, ParentStartNS: uint64(parent) * 1000,
	}, time.Now())
}

func (s *runcStart) net(typ events.Type, pid uint32, remote string) *export.Record {
	return s.f.e.Handle(&events.Net{
		Header: events.Header{Type: typ, PID: pid, StartTimeNS: uint64(pid) * 1000, CgroupID: s.pod},
		Family: events.AFInet, Proto: 6,
		Local:  netip.MustParseAddrPort("10.244.1.5:8888"),
		Remote: netip.MustParseAddrPort(remote),
	}, time.Now())
}

// setup runs runc up to the stage that will execute the program, pid 73.
func (s *runcStart) setup() {
	s.exec(70, 60, s.host, "/usr/local/sbin/runc", 8, 100, 0, "runc", "create")
	s.fork(70, 71, s.host)
	s.exec(71, 70, s.host, "/memfd:runc_cloned:/proc/self/exe (deleted)", 1, 5, events.ExecUnlinked, "runc", "init")
	s.fork(71, 72, s.pod) // runc:[1:CHILD]
	s.fork(72, 73, s.pod) // runc:[2:INIT]
}

// The notebook: the container's program is Python itself. Its own
// connections and the terminals it starts belong to the application.
func TestRuncStartPythonApplication(t *testing.T) {
	s := newRuncStart(t)
	s.setup()
	if rec := s.exec(73, 72, s.pod, "/usr/local/bin/python3", 9, 7000, 0, "python3", "-u", "-c", "notebook"); !rec.Process.IsMainBinary {
		t.Errorf("the program runc started is not the main binary: %s", toJSON(t, rec))
	}
	if rec := s.net(events.TypeAccept, 73, "127.0.0.1:41000"); !rec.Process.IsMainBinary {
		t.Errorf("the application accepting a connection: %s", toJSON(t, rec))
	}
	s.fork(73, 90, s.pod)
	rec := s.exec(90, 73, s.pod, "/bin/sh", 9, 7100, events.ExecStdinPty|events.ExecStdoutPty, "sh", "-c", "ls /")
	if rec.Parent == nil || !rec.Parent.IsMainBinary || !rec.Parent.ContainerFirst || rec.Process.IsMainBinary {
		t.Errorf("a terminal the application starts: %s", toJSON(t, rec))
	}
}

// The worker: the container's program is a shell loop that starts Python.
// That Python is started directly by the container's first process.
func TestRuncStartEntrypointWorker(t *testing.T) {
	s := newRuncStart(t)
	s.setup()
	if rec := s.exec(73, 72, s.pod, "/bin/sh", 9, 7100, 0, "sh", "-c", "while true; do python3 -c fetch; sleep 10; done"); !rec.Process.IsMainBinary {
		t.Errorf("the entrypoint shell is not the main binary: %s", toJSON(t, rec))
	}
	s.fork(73, 90, s.pod)
	s.exec(90, 73, s.pod, "/usr/local/bin/python3", 9, 7000, 0, "python3", "-c", "fetch")
	rec := s.net(events.TypeConnect, 90, "10.96.0.10:53")
	if rec.Parent == nil || !rec.Parent.ContainerFirst || rec.Process.IsMainBinary {
		t.Errorf("python under the entrypoint: %s", toJSON(t, rec))
	}
}
