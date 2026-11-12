// SPDX-License-Identifier: Apache-2.0

// Package enrich turns a decoded kernel event into the record that leaves the
// agent: it keeps the process tree up to date and adds ancestry, user name
// and pod attribution.
package enrich

import (
	"net/netip"
	"path"
	"regexp"
	"strconv"
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
	// mains is each container's first binary, by container ID.
	mains map[string]*mainBinary
	// inodes, if set, is told about every exec in a container.
	inodes RootObserver
	// apiServers are the addresses of the Kubernetes API.
	apiServers map[netip.AddrPort]bool
	// lastOpen is the latest file_open reported for each thread.
	lastOpen map[uint32]openMark
	nested   uint64
	// hostNS is the inode number of each of the node's own namespaces,
	// by kind.
	hostNS map[string]uint32
	// runtimes, if set, knows the node's runtime binaries.
	runtimes RuntimeSet
	// watched, if set, says which watches cover a path. Refused opens
	// arrive unfiltered and are kept only when one does.
	watched         func(path string) uint32
	deniedUnwatched uint64
}

// RuntimeSet recognises the node's container runtime binaries by file
// identity; runtimeid.Set implements it.
type RuntimeSet interface {
	Has(dev uint32, inode uint64) bool
}

// SetRuntimes sets who recognises runtime binaries.
func (e *Enricher) SetRuntimes(r RuntimeSet) { e.runtimes = r }

// SetWatched sets the matcher for refused opens.
func (e *Enricher) SetWatched(match func(path string) uint32) { e.watched = match }

// DeniedUnwatched is the number of refused opens dropped because no watch
// covers their path.
func (e *Enricher) DeniedUnwatched() uint64 { return e.deniedUnwatched }

// realRuntime reports whether the process runs a runtime binary's own file.
func (e *Enricher) realRuntime(p proctree.Proc) bool {
	return e.runtimes != nil && e.runtimes.Has(p.ExeDev, p.ExeInode)
}

func (e *Enricher) isRuntime(p proctree.Proc) bool {
	return p.RuntimeChild || e.realRuntime(p)
}

func isRuncInit(argv []string) bool {
	return len(argv) == 2 && argv[0] == "runc" && argv[1] == "init"
}

// procRootRE matches the ways of naming a root directory through /proc.
var procRootRE = regexp.MustCompile(`^/proc/(self|thread-self|[0-9]+)(/task/[0-9]+)?/root(/|$)`)

// deniedPath puts the name of a refused open into the form the watches use.
// The kernel never resolved it, so this is done on the text alone: a
// relative name is joined to the working directory, "." and ".." are
// removed, and a detour through /proc/<pid>/root is cut. A symbolic link in
// the name is not followed.
func deniedPath(ev *events.FileDenied) string {
	name := ev.Name
	if !strings.HasPrefix(name, "/") {
		if ev.Cwd == "" || ev.Flags&events.DeniedCwdCut != 0 {
			return name
		}
		name = ev.Cwd + "/" + name
	}
	name = path.Clean(name)
	for i := 0; i < 4; i++ {
		loc := procRootRE.FindStringIndex(name)
		if loc == nil {
			break
		}
		name = path.Clean("/" + name[loc[1]:])
	}
	return name
}

func errnoName(n uint32) string {
	switch unix.Errno(n) {
	case unix.EACCES:
		return "EACCES"
	case unix.EPERM:
		return "EPERM"
	case unix.EROFS:
		return "EROFS"
	}
	return strconv.Itoa(int(n))
}

// readHostNS reads the namespaces of the node's first process.
func readHostNS(procRoot string) map[string]uint32 {
	out := map[string]uint32{}
	for _, name := range events.NSNames {
		var st unix.Stat_t
		if unix.Stat(procRoot+"/1/ns/"+name, &st) == nil {
			out[name] = uint32(st.Ino)
		}
	}
	return out
}

// openMark identifies one reported open.
type openMark struct {
	inode uint64
	path  string
	ts    uint64
}

// On overlayfs one open reaches the kernel hook twice: for the file the
// process asked for, and straight after, in the same thread, for the backing
// file overlayfs opens under its own credentials. The second one says
// nothing new, so it is dropped: a file_open marked as made under
// substituted credentials, straight after an open the same thread was
// reported for, of the same file. "The same file" is the same inode number
// or the same path: overlayfs shows a file's original inode number even
// after the file has been copied to the upper layer, where the backing file
// has another. Anything that does not fit all of that is kept.
const (
	nestedWindow = 10 * time.Millisecond
	maxLastOpen  = 8192
)

func (e *Enricher) nestedOpen(ev *events.FileOpen) bool {
	if ev.Flags&events.FileKernelCreds != 0 {
		last, ok := e.lastOpen[ev.TID]
		return ok && ev.TSBootNS-last.ts < uint64(nestedWindow) &&
			(last.inode == ev.Inode || (ev.Path != "" && last.path == ev.Path))
	}
	if len(e.lastOpen) >= maxLastOpen {
		e.lastOpen = map[uint32]openMark{}
	}
	e.lastOpen[ev.TID] = openMark{inode: ev.Inode, path: ev.Path, ts: ev.TSBootNS}
	return false
}

// NestedOpens is the number of duplicate opens dropped.
func (e *Enricher) NestedOpens() uint64 { return e.nested }

// RootObserver learns of processes whose root filesystem may hold watched
// files; inodewatch.Tracker implements it.
type RootObserver interface {
	Observe(pid uint32, owner string)
	// WatchedPath names the watched file an identity belongs to.
	WatchedPath(dev uint32, inode uint64) (string, bool)
}

// mainBinary is the first process of a container and the binary it runs.
type mainBinary struct {
	key   proctree.Key
	image string
}

// maxMains bounds the main-binary cache; entries are cheap to recompute.
const maxMains = 4096

// ObserveRoots sets who is told about execs in containers.
func (e *Enricher) ObserveRoots(o RootObserver) { e.inodes = o }

// SetAPIServers sets the addresses that count as the Kubernetes API.
func (e *Enricher) SetAPIServers(addrs []netip.AddrPort) {
	e.apiServers = make(map[netip.AddrPort]bool, len(addrs))
	for _, a := range addrs {
		e.apiServers[a] = true
	}
}

// New returns an Enricher. pods may be nil.
func New(node string, tree *proctree.Tree, procfs proctree.ProcFS, cgroups *k8s.CgroupResolver, pods *k8s.PodIndex) *Enricher {
	return &Enricher{
		node:     node,
		tree:     tree,
		procfs:   procfs,
		cgroups:  cgroups,
		pods:     pods,
		users:    newUserCache(procfs.Root),
		boot:     bootTime(),
		mains:    map[string]*mainBinary{},
		lastOpen: map[uint32]openMark{},
		hostNS:   readHostNS(procfs.Root),
	}
}

// bootTime samples the boot-time and wall clocks together. Kernel timestamps
// are nanoseconds since boot.
func bootTime() time.Time {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return time.Now().Add(-time.Duration(ts.Nano()))
}

// Handle applies the event to the process tree and returns its record, or
// nil for an event that repeats one already reported.
func (e *Enricher) Handle(ev events.Event, now time.Time) *export.Record {
	h := ev.Hdr()
	if f, ok := ev.(*events.FileOpen); ok && e.nestedOpen(f) {
		e.nested++
		return nil
	}
	var denied string
	if f, ok := ev.(*events.FileDenied); ok {
		denied = deniedPath(f)
		if e.watched == nil || e.watched(denied) == 0 {
			e.deniedUnwatched++
			return nil
		}
	}
	rec := &export.Record{
		TS:   e.boot.Add(time.Duration(h.TSBootNS)).UTC().Format("2006-01-02T15:04:05.000000Z"),
		Type: h.Type.String(),
		Node: e.node,
	}

	var p proctree.Proc
	// runc does not run its own file as "runc init", the stage that sets
	// up and enters a container. It runs a protected copy: a sealed
	// memory file in older versions, the binary seen through a private
	// read-only overlay in newer ones. Neither has the identity of the
	// node's runc. The copy is taken for the runtime when the task that
	// executed it was running the node's real runc as something other
	// than "runc init", the new command line is exactly "runc init", and
	// the new file is unlinked or has runc's inode number. A process in a
	// container never runs the node's real runc, and what the copy
	// executes next (the container's program) fails the first test.
	runtimeCopy := false
	switch ev := ev.(type) {
	case *events.Exec:
		// What the task was running until now, for runtimeCopy below.
		prev, known := e.tree.Get(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		p = e.tree.Exec(ev)
		runtimeCopy = known && e.realRuntime(prev) && !isRuncInit(prev.Argv) && isRuncInit(ev.Argv) &&
			(ev.Flags&events.ExecUnlinked != 0 || ev.Inode == prev.ExeInode)
		rec.Process.Exec = &export.Exec{
			StdinIsSocket:  ev.Flags&events.ExecStdinSock != 0,
			StdoutIsSocket: ev.Flags&events.ExecStdoutSock != 0,
			Unlinked:       ev.Flags&events.ExecUnlinked != 0,
			Setuid:         ev.Flags&events.ExecSetuid != 0,
			ArgvTruncated:  ev.Flags&events.ExecArgvTrunc != 0,
			Inode:          ev.Inode,
			Dev:            ev.Dev,
			CapEffective:   ev.CapEffective,
			EnvTruncated:   ev.Flags&events.ExecEnvTrunc != 0,
		}
		for _, kv := range ev.Env {
			if name, value, ok := strings.Cut(kv, "="); ok {
				if rec.Process.Env == nil {
					rec.Process.Env = map[string]string{}
				}
				rec.Process.Env[name] = value
			}
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
	case *events.Net:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Network = e.network(ev)
	case *events.UnixConnect:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		// On the wire a Unix connect is a connect with another family,
		// so one rule event type covers both.
		rec.Type = events.TypeConnect.String()
		rec.Network = &export.Network{Direction: "outbound", Family: "unix", UnixPath: ev.Path}
	case *events.Ptrace:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Ptrace = &export.Ptrace{TargetPID: ev.TargetPID, Mode: ev.Mode}
		if target, ok := e.byPID(ev.TargetPID); ok {
			rec.Ptrace.TargetImage = target.Image
			rec.Ptrace.TargetCommandLine = strings.Join(target.Argv, " ")
		}
	case *events.Memfd:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Memfd = &export.Memfd{Flags: ev.MemfdFlags}
	case *events.ModuleLoad:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Module = &export.Module{Name: ev.Name}
	case *events.BPFLoad:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.BPF = &export.BPF{ProgType: ev.ProgType, Name: ev.Name}
	case *events.CredChange:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Cred = &export.Cred{
			OldUID: ev.OldUID, NewUID: ev.NewUID, OldEUID: ev.OldEUID, NewEUID: ev.NewEUID, OldGID: ev.OldGID, NewGID: ev.NewGID,
			InExec:          ev.Flags&events.CredInExec != 0,
			CapsGained:      ev.NewCap&^ev.OldCap != 0,
			OldCapEffective: ev.OldCap, NewCapEffective: ev.NewCap,
		}
	case *events.Mount:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Mount = &export.Mount{FSType: ev.FSType, Flags: ev.MntFlags, Target: ev.Target}
	case *events.Setns:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Namespaces = &export.Namespaces{Changed: ev.Changed}
		for _, name := range ev.Changed {
			if host, ok := e.hostNS[name]; ok && host == ev.Inum[name] {
				rec.Namespaces.Host = append(rec.Namespaces.Host, name)
			}
		}
	case *events.FileChange:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.File = &export.File{
			Path:      ev.Path,
			Write:     true,
			Inode:     ev.Inode,
			Dev:       ev.Dev,
			MatchedBy: matchedBy(ev.Flags),
			Op:        ev.Op,
		}
		if e.inodes != nil && ev.Flags&events.FileByInode != 0 {
			if target, ok := e.inodes.WatchedPath(ev.Dev, ev.Inode); ok && target != ev.Path {
				rec.File.Target = target
			}
		}
	case *events.FileDenied:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.File = &export.File{
			Path:      denied,
			Flags:     ev.OpenFlags,
			Write:     ev.Write(),
			Truncate:  ev.OpenFlags&events.OTrunc != 0,
			MatchedBy: "path",
			Error:     errnoName(ev.Errno),
		}
	case *events.FileOpen:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.File = &export.File{
			Path:      ev.Path,
			Flags:     ev.OpenFlags,
			Write:     ev.Write(),
			Truncate:  ev.OpenFlags&events.OTrunc != 0,
			Inode:     ev.Inode,
			Dev:       ev.Dev,
			MatchedBy: matchedBy(ev.Flags),
		}
		if e.inodes != nil && ev.Flags&events.FileByInode != 0 {
			if target, ok := e.inodes.WatchedPath(ev.Dev, ev.Inode); ok && target != ev.Path {
				rec.File.Target = target
			}
		}
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
	rec.Process.Runtime = e.isRuntime(p)

	e.ancestry(rec, p)
	e.attribute(rec, p, h.CgroupID)
	if runtimeCopy {
		e.tree.SetRuntimeChild(p.Key)
		rec.Process.Runtime = true
	}
	if rec.Container != nil {
		_, isExec := ev.(*events.Exec)
		rec.Process.IsMainBinary = e.isMainBinary(rec.Container.ID, p, isExec)
		if isExec && e.inodes != nil {
			// A new root filesystem shows up with its first exec.
			e.inodes.Observe(p.Key.PID, rec.Container.ID)
		}
	}
	return rec
}

// isMainBinary reports whether p runs the binary its container started
// with. The first process of a container is the oldest one the tree knows in
// it; if that process execs again, the main binary follows.
func (e *Enricher) isMainBinary(containerID string, p proctree.Proc, isExec bool) bool {
	m := e.mains[containerID]
	switch {
	case m == nil:
		first, ok := e.tree.OldestInContainer(containerID)
		if !ok {
			first = p
		}
		if len(e.mains) >= maxMains {
			e.mains = map[string]*mainBinary{}
		}
		m = &mainBinary{key: first.Key, image: first.Image}
		e.mains[containerID] = m
	case isExec && p.Key == m.key:
		m.image = p.Image
	}
	return p.Image != "" && p.Image == m.image
}

func (e *Enricher) network(ev *events.Net) *export.Network {
	n := &export.Network{Family: "ipv4", Protocol: protocol(ev.Proto)}
	if ev.Remote.Addr().Is6() {
		n.Family = "ipv6"
	}
	src, dst := ev.Local, ev.Remote
	n.Direction = "outbound"
	if ev.Type == events.TypeAccept {
		n.Direction = "inbound"
		src, dst = ev.Remote, ev.Local
	}
	// An unbound local side reads as the zero address; leave it out.
	if !src.Addr().IsUnspecified() {
		n.SourceIP = src.Addr().String()
	}
	n.SourcePort = src.Port()
	n.DestinationIP = dst.Addr().String()
	n.DestinationPort = dst.Port()
	n.IsK8sAPI = ev.Type == events.TypeConnect && e.apiServers[dst]
	return n
}

func protocol(p uint16) string {
	switch p {
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_ICMPV6:
		return "icmpv6"
	case unix.IPPROTO_SCTP:
		return "sctp"
	}
	return strconv.Itoa(int(p))
}

func matchedBy(flags uint32) string {
	switch {
	case flags&events.FileByInode != 0:
		return "inode"
	case flags&events.FileByName != 0:
		return "name"
	}
	return "path"
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
				Runtime:     e.isRuntime(parent),
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

	if a != nil && a.ContainerID != p.ContainerID {
		e.tree.SetContainerID(p.Key, a.ContainerID)
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
