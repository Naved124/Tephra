// SPDX-License-Identifier: Apache-2.0

// Package enrich turns a decoded kernel event into the record that leaves the
// agent: it keeps the process tree up to date and adds ancestry, user name
// and pod attribution.
package enrich

import (
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/proctree"
)

// Enricher is used by one goroutine, the pipeline's enrich stage.
type Enricher struct {
	node    string
	tree    *proctree.Tree
	procfs  proctree.ProcFS
	cgroups *k8s.CgroupResolver
	// pods is nil when the agent runs outside a cluster.
	pods  *k8s.PodIndex
	users *userCache
	// boot is the wall-clock time of boot, sampled once at start-up.
	boot time.Time
}

// New returns an Enricher. pods may be nil.
func New(node string, tree *proctree.Tree, procfs proctree.ProcFS, cgroups *k8s.CgroupResolver, pods *k8s.PodIndex) *Enricher {
	return &Enricher{
		node:    node,
		tree:    tree,
		procfs:  procfs,
		cgroups: cgroups,
		pods:    pods,
		users:   newUserCache(procfs.Root),
		boot:    bootTime(),
	}
}

// bootTime samples the boot-time and wall clocks together. Kernel timestamps
// are nanoseconds since boot.
func bootTime() time.Time {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return time.Now().Add(-time.Duration(ts.Nano()))
}

// Handle applies the event to the process tree and returns its record.
func (e *Enricher) Handle(ev events.Event, now time.Time) *export.Record {
	h := ev.Hdr()
	rec := &export.Record{
		TS:   e.boot.Add(time.Duration(h.TSBootNS)).UTC().Format("2006-01-02T15:04:05.000000Z"),
		Type: h.Type.String(),
		Node: e.node,
	}

	var p proctree.Proc
	switch ev := ev.(type) {
	case *events.Exec:
		p = e.tree.Exec(ev)
		rec.Process.Exec = &export.Exec{
			StdinIsSocket:  ev.Flags&events.ExecStdinSock != 0,
			StdoutIsSocket: ev.Flags&events.ExecStdoutSock != 0,
			Unlinked:       ev.Flags&events.ExecUnlinked != 0,
			Setuid:         ev.Flags&events.ExecSetuid != 0,
			ArgvTruncated:  ev.Flags&events.ExecArgvTrunc != 0,
			Inode:          ev.Inode,
			Dev:            ev.Dev,
			CapEffective:   ev.CapEffective,
		}
	case *events.Fork:
		// The forking process may predate the agent; make sure the
		// child has something to inherit from.
		e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		e.tree.Fork(ev)
		p, _ = e.tree.Get(proctree.Key{PID: ev.ChildPID, StartNS: ev.ChildStartNS})
	case *events.Exit:
		k := proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS}
		p, _ = e.known(k)
		e.tree.Exit(ev, now)
		rec.Exit = &export.Exit{Code: ev.Code(), Signal: ev.Signal()}
	}
	if p.Key.PID == 0 {
		// Not in the tree and already gone from /proc: report what the
		// header carries.
		p = proctree.Proc{
			Key:    proctree.Key{PID: h.PID, StartNS: h.StartTimeNS},
			Parent: proctree.Key{PID: h.PPID},
			Image:  h.Comm,
		}
	}

	// For exec and exit the header is the subject itself, and its ppid is
	// the kernel's answer at the time of the event.
	if _, isFork := ev.(*events.Fork); !isFork && h.PPID != 0 && h.PPID != p.Parent.PID {
		if np, ok := e.byPID(h.PPID); ok {
			e.tree.SetParent(p.Key, np.Key)
			p.Parent = np.Key
		}
	}

	rec.Process.PID = p.Key.PID
	rec.Process.StartTimeNS = p.Key.StartNS
	rec.Process.Image = p.Image
	rec.Process.CommandLine = strings.Join(p.Argv, " ")
	rec.Process.UID = h.UID
	rec.Process.GID = h.GID
	rec.Process.CgroupID = h.CgroupID
	rec.Process.User = e.users.name(h.PID, h.MntNS, h.UID)

	e.ancestry(rec, p)
	e.attribute(rec, p, h.CgroupID)
	return rec
}

// known returns the process, reading it from /proc if the tree has never
// seen it.
func (e *Enricher) known(k proctree.Key) (proctree.Proc, bool) {
	if p, ok := e.tree.Get(k); ok {
		return p, true
	}
	if p, ok := e.tree.Lookup(e.procfs, k.PID); ok {
		return p, true
	}
	return proctree.Proc{}, false
}

// byPID returns the process currently holding a pid, reading it from /proc
// if the tree has never seen it.
func (e *Enricher) byPID(pid uint32) (proctree.Proc, bool) {
	if pid == 0 {
		return proctree.Proc{}, false
	}
	if p, ok := e.tree.ByPID(pid); ok && p.Exited.IsZero() {
		return p, true
	}
	return e.tree.Lookup(e.procfs, pid)
}

// parentOf returns the parent of a process as the kernel has it now. When a
// parent exits, the kernel hands its children to a subreaper or to init; the
// tree only learns of that here, by finding the recorded parent exited or
// gone and asking /proc. Container runtimes do this on every start: runc
// forks the container's first process and exits, leaving it to the shim.
func (e *Enricher) parentOf(cur proctree.Proc) (proctree.Proc, bool) {
	parent, ok := e.known(cur.Parent)
	if ok && parent.Exited.IsZero() {
		return parent, true
	}
	if cur.Exited.IsZero() {
		if ppid, live := e.procfs.ParentOf(cur.Key); live && ppid != cur.Parent.PID {
			if np, found := e.byPID(ppid); found {
				e.tree.SetParent(cur.Key, np.Key)
				return np, true
			}
		}
	}
	// No newer answer: an exited parent that still lingers is better than
	// none.
	return parent, ok
}

// ancestry fills parent and ancestors. A link that the tree is missing is
// read from /proc on the spot. The kernel's single ring buffer preserves the
// order in which events were produced, so a fork that has not arrived yet
// was produced before the agent attached, and waiting would not bring it.
func (e *Enricher) ancestry(rec *export.Record, p proctree.Proc) {
	cur := p
	for i := 0; i < proctree.MaxAncestors; i++ {
		if cur.Parent.PID == 0 {
			break
		}
		parent, ok := e.parentOf(cur)
		if !ok || parent.Key == cur.Key {
			break
		}
		if i == 0 {
			rec.Parent = &export.Parent{
				PID:         parent.Key.PID,
				Image:       parent.Image,
				CommandLine: strings.Join(parent.Argv, " "),
			}
		}
		rec.Ancestors = append(rec.Ancestors, parent.Image)
		cur = parent
	}
}

// attribute fills container and k8s.
func (e *Enricher) attribute(rec *export.Record, p proctree.Proc, cgroupID uint64) {
	a := p.Attr
	resolved := false
	if !a.Complete() {
		path, ok := e.cgroups.Path(cgroupID)
		resolved = ok
		cid := k8s.ContainerID(path)
		if !ok {
			// The cgroup is gone or was never seen; fall back to
			// what seeding read from /proc/<pid>/cgroup.
			cid = p.ContainerID
		}
		switch {
		case cid == "":
			a = nil
		case e.pods == nil:
			a = &k8s.Attribution{ContainerID: cid}
		default:
			found, ok := e.pods.Lookup(cid, k8s.PodUID(path))
			if !ok {
				found = &k8s.Attribution{ContainerID: cid}
			}
			a = found
			if a.Complete() {
				e.tree.SetAttr(p.Key, a)
			}
		}
	}

	if a == nil {
		if resolved {
			rec.K8s.Namespace = export.NamespaceHost
		} else {
			rec.K8s.Namespace = export.NamespaceUnknown
		}
		return
	}
	rec.Container = &export.Container{ID: a.ContainerID, Name: a.ContainerName, Image: a.Image}
	rec.K8s = export.K8s{Namespace: a.Namespace, Pod: a.Pod, Labels: a.Labels}
	if rec.K8s.Namespace == "" {
		rec.K8s.Namespace = export.NamespaceUnknown
	}
}
