// SPDX-License-Identifier: Apache-2.0

// Package enrich turns a decoded kernel event into the record that leaves the
// agent: it keeps the process tree up to date and adds ancestry, user name
// and pod attribution.
package enrich

import (
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Naved124/tephra/internal/credwatch"
	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/identity"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/proctree"
)

// Enricher is used by one goroutine, the pipeline's enrich stage.
type Enricher struct {
	// onMainChange is told when a container's main binary changes.
	onMainChange func(containerID string)
	node         string
	tree         *proctree.Tree
	// agent is the agent's own process, so that access to it is named;
	// agentContainer and agentMnt are its container and mount namespace.
	agent          proctree.Key
	agentContainer string
	agentMnt       uint32
	// mntOwners caches the oldest process of each mount namespace and
	// when it was last found alive.
	mntOwners map[uint32]ownerMark
	// alive checks a process against /proc; ghosts counts the processes
	// it found gone while the tree still had them as live.
	alive   func(p proctree.Proc, mnt uint32) bool
	ghosts  uint64
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
	// creds, if set, says which files are Kubernetes credentials.
	creds CredentialLookup
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
	// ids, if set, recognises binaries by their content; idRoots are the
	// containers whose root it has been shown.
	ids     Identifier
	idRoots map[string]bool
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

// Identifier recognises executables by content; identity.Catalog
// implements it.
type Identifier interface {
	// ObserveRoot reads the root filesystem of pid, and reports whether it
	// could.
	ObserveRoot(pid uint32) bool
	Identify(x identity.Exe) identity.Role
	// Applet is the program a multi-call binary runs, "" for any other.
	Applet(x identity.Exe) string
}

// SetIdentity sets who recognises binaries by their content.
func (e *Enricher) SetIdentity(ids Identifier) { e.ids = ids }

// Lost returns the record standing for n tamper records of type t that the
// kernel counted but could not store: the node and what happened are known,
// not who did it. Rules match it like any record of its type.
func (e *Enricher) Lost(t events.Type, n uint64, now time.Time) *export.Record {
	rec := &export.Record{
		TS:   now.UTC().Format("2006-01-02T15:04:05.000000Z"),
		Type: t.String(),
		Node: e.node,
	}
	switch t {
	case events.TypeSignal:
		rec.Signal = &export.Signal{Name: "unknown", Lost: n}
	case events.TypePtrace:
		rec.Ptrace = &export.Ptrace{TargetIsAgent: true, Lost: n}
	}
	return rec
}

// Wall renders a kernel boot-clock time as the records' wall-clock time.
func (e *Enricher) Wall(bootNS uint64) string {
	return e.boot.Add(time.Duration(bootNS)).UTC().Format("2006-01-02T15:04:05.000000Z")
}

// OnMainChange calls f with a container's ID when the binary taken for its
// main one changes, which changes is_main_binary for processes that ran no
// exec of their own.
func (e *Enricher) OnMainChange(f func(containerID string)) { e.onMainChange = f }

// SetAgent names the agent's own process: its pid in the node's namespace
// and its start time.
func (e *Enricher) SetAgent(pid uint32, startNS uint64) {
	e.agent = proctree.Key{PID: pid, StartNS: startNS}
	// Outside a container the agent shares the node's mount namespace,
	// which is no mark of anything.
	if p, _, err := e.procfs.Read(pid); err == nil && p.ContainerID != "" {
		e.agentContainer, e.agentMnt = p.ContainerID, p.MntNS
	}
}

const (
	// maxMntOwners bounds the mount namespace cache.
	maxMntOwners = 50000
	// ownerRecheck is how long an owner found alive is trusted before it
	// is checked against /proc again.
	ownerRecheck = 10 * time.Second
	// maxGhosts bounds the candidates tried for one namespace.
	maxGhosts = 8
)

type ownerMark struct {
	key     proctree.Key
	checked time.Time
}

// Ghosts is the number of processes found gone, at a lookup or a sweep,
// while the tree still had them as live.
func (e *Enricher) Ghosts() uint64 { return e.ghosts }

// Sweep checks every live process in the tree against /proc and marks those
// that are gone as exited: run after the ring buffer reports drops, which
// can lose exits. It returns how many it found and how many it checked.
func (e *Enricher) Sweep(now time.Time) (found, checked int) {
	found, checked = e.tree.Prune(func(p proctree.Proc) bool { return e.alive(p, 0) }, now)
	e.ghosts += uint64(found)
	if found > 0 {
		e.mntOwners = nil
	}
	return found, checked
}

// mntOwner returns the container of the oldest live process in a mount
// namespace, and whether there is one. The tree's view of who is live can be
// wrong: an exit lost with a ring buffer drop leaves a ghost, and Linux hands
// a freed namespace number to the next namespace made, so a ghost can sit
// in a new pod's namespace number, older than anything really in it (E26).
// The owner is therefore checked against /proc, with its start time and
// mount namespace, before it is trusted.
func (e *Enricher) mntOwner(mnt uint32) (string, bool) {
	if mnt == 0 {
		return "", false
	}
	now := time.Now()
	if m, ok := e.mntOwners[mnt]; ok {
		if p, ok := e.tree.Get(m.key); ok && p.Exited.IsZero() && p.MntNS == mnt {
			if now.Sub(m.checked) < ownerRecheck {
				return p.ContainerID, true
			}
			if e.alive(p, mnt) {
				e.mntOwners[mnt] = ownerMark{p.Key, now}
				return p.ContainerID, true
			}
		}
		delete(e.mntOwners, mnt)
	}
	for range maxGhosts {
		p, ok := e.tree.MntOwner(mnt)
		if !ok {
			return "", false
		}
		if !e.alive(p, mnt) {
			if e.tree.MarkExited(p.Key, now) {
				e.ghosts++
			}
			continue
		}
		if e.mntOwners == nil || len(e.mntOwners) >= maxMntOwners {
			e.mntOwners = map[uint32]ownerMark{}
		}
		e.mntOwners[mnt] = ownerMark{p.Key, now}
		return p.ContainerID, true
	}
	return "", false
}

// cameFrom is the container a process came from: the one it was born in,
// else the one whose mount namespace it is in, else its cgroup's.
func (e *Enricher) cameFrom(p proctree.Proc, mnt uint32) string {
	if p.Origin != "" {
		return p.Origin
	}
	if mnt == 0 {
		mnt = p.MntNS
	}
	// An owner the pod index does not know is no better a guess than the
	// cgroup: it is a container that is gone, or not a pod's.
	if owner, ok := e.mntOwner(mnt); ok && owner != "" && (e.pods == nil || e.podOf(owner) != "") {
		return owner
	}
	return p.ContainerID
}

// otherPod lists the namespaces a setns entered that belong to another
// container than the one the process came from: for a mount namespace,
// another container; for a pid or network namespace, which the containers
// of a pod share and the pod's sandbox owns, another pod. The node's own
// namespaces are R018's and are left out.
func (e *Enricher) otherPod(p proctree.Proc, ev *events.Setns, host []string) []string {
	own := e.cameFrom(p, 0)
	ownPod := e.podOf(own)
	var out []string
	for _, kind := range []string{"mnt", "pid", "net"} {
		if !contains(ev.Changed, kind) || contains(host, kind) {
			continue
		}
		for _, q := range e.tree.InNamespace(kind, ev.Inum[kind]) {
			if q.ContainerID == "" || q.Key == p.Key {
				continue
			}
			if kind == "mnt" {
				if q.ContainerID != own {
					out = append(out, kind)
				}
				break
			}
			// The sandbox's own process belongs to no known container;
			// the pod is that of the oldest one that does.
			pod := e.podOf(q.ContainerID)
			if pod == "" {
				continue
			}
			if pod != ownPod {
				out = append(out, kind)
			}
			break
		}
	}
	return out
}

// podOf names the pod of a container as namespace/name, empty if unknown.
func (e *Enricher) podOf(containerID string) string {
	if containerID == "" || e.pods == nil {
		return ""
	}
	if a, ok := e.pods.Lookup(containerID, ""); ok && a.Pod != "" {
		return a.Namespace + "/" + a.Pod
	}
	return ""
}

// checkIdentity compares the container the cgroup names with where the
// process came from. Moving into another container's cgroup is how a
// process borrows that container's name and exemptions (E15, E20, E26).
// Where it came from is, first, the container it was born in, which a move
// does not change; for a process seeded from /proc, whose birth was not
// seen, the container whose mount namespace it is in. Only a move between
// two containers is relabelled: a process on the node that enters a
// container, or one in a container that enters the node's namespaces, keeps
// what the cgroup says, and R018 and R036 report the entry.
func (e *Enricher) checkIdentity(rec *export.Record, p proctree.Proc, mnt uint32) {
	if rec.Process.Runtime || p.Key == e.agent {
		return
	}
	cgroup := ""
	if rec.Container != nil {
		cgroup = rec.Container.ID
	}
	if e.agent.PID != 0 && ((e.agentContainer != "" && cgroup == e.agentContainer) || (e.agentMnt != 0 && mnt == e.agentMnt)) {
		rec.Process.InAgentContainer = true
	}
	from := e.cameFrom(p, mnt)
	if from == "" || cgroup == "" || from == cgroup {
		return
	}
	rec.Process.IdentityMismatch = true
	a := &k8s.Attribution{ContainerID: from}
	if e.pods != nil {
		found, ok := e.pods.Lookup(from, "")
		if !ok {
			// Never trade a known pod for no pod: the container it came
			// from is gone or not a pod's, and the cgroup's pod is the
			// better name. The mismatch stays marked.
			return
		}
		a = found
	}
	rec.Container = &export.Container{ID: a.ContainerID, Name: a.ContainerName, Image: a.Image}
	rec.K8s = export.K8s{Namespace: a.Namespace, Pod: a.Pod, Labels: a.Labels}
	if rec.K8s.Namespace == "" {
		rec.K8s.Namespace = export.NamespaceUnknown
	}
}

// exeSlack is how long after a container's start a binary's change still
// counts as part of the image: file times and process start times come from
// different clocks.
const exeSlack = time.Second

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
	dev   uint32
	inode uint64
	// applet: the program the main binary runs when it is busybox.
	applet string
	// runtime: the oldest process seen so far is the runtime setting the
	// container up, so the main binary is still to come.
	runtime bool
}

// maxMains bounds the main-binary cache; entries are cheap to recompute.
const maxMains = 4096

// CredentialLookup says whether an open file is a Kubernetes credential;
// credwatch.Watcher implements it.
type CredentialLookup interface {
	Lookup(dev uint32, inode uint64, path string) (credwatch.Credential, bool)
}

// SetCredentials sets who says which files are credentials.
func (e *Enricher) SetCredentials(c CredentialLookup) { e.creds = c }

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
		alive:    func(p proctree.Proc, mnt uint32) bool { return procfs.Alive(p.Key, mnt) },
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
		TS:   e.Wall(h.TSBootNS),
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
			ExeCtimeNS:     ev.CtimeNS,
			EnvTruncated:   ev.Flags&events.ExecEnvTrunc != 0,
			StdinIsPty:     ev.Flags&events.ExecStdinPty != 0,
			StdoutIsPty:    ev.Flags&events.ExecStdoutPty != 0,
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
		src, _ := e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		e.tree.Fork(ev)
		child := proctree.Key{PID: ev.ChildPID, StartNS: ev.ChildStartNS}
		// Born in the forking process's container, unless that is the
		// runtime handing a process in.
		if !e.isRuntime(src) {
			if from := e.cameFrom(src, 0); from != "" {
				e.tree.SetOrigin(child, from)
			}
		}
		p, _ = e.tree.Get(child)
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
		// The kernel numbers only attaches to an agent, which may be
		// an earlier one when the record is replayed from its table.
		rec.Ptrace.TargetIsAgent = ev.TamperSeq != 0 || e.agent.PID != 0 &&
			proctree.Key{PID: ev.TargetPID, StartNS: ev.TargetStartNS} == e.agent
		if target, ok := e.byPID(ev.TargetPID); ok {
			rec.Ptrace.TargetImage = target.Image
			rec.Ptrace.TargetCommandLine = strings.Join(target.Argv, " ")
		}
	case *events.Signal:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Signal = &export.Signal{Number: ev.Signal, Name: unix.SignalName(syscall.Signal(ev.Signal)), TargetPID: ev.TargetPID}
		if rec.Signal.Name == "" {
			rec.Signal.Name = fmt.Sprintf("SIG%d", ev.Signal)
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
		if !e.isRuntime(p) {
			rec.Namespaces.OtherPod = e.otherPod(p, ev, rec.Namespaces.Host)
		}
	case *events.Enforce:
		p, _ = e.known(proctree.Key{PID: ev.PID, StartNS: ev.StartTimeNS})
		rec.Enforce = &export.Enforce{Action: ev.Action, Denied: ev.Denied(), Blind: ev.Blind()}
		if ev.Action == "file_write" || ev.Action == "file_read" {
			path := ev.Path
			if ev.Flags&events.EnforceNoPath != 0 {
				path = ""
			}
			rec.File = &export.File{Path: path, Write: ev.Action == "file_write", Inode: ev.Inode, Dev: ev.Dev, MatchedBy: "block"}
			// Refused through a hard link: name the protected file, as
			// a file_open record does.
			if e.inodes != nil {
				if target, ok := e.inodes.WatchedPath(ev.Dev, ev.Inode); ok && target != path {
					rec.File.Target = target
				}
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
		if e.creds != nil && ev.Flags&(events.FileByDev|events.FileByInode) != 0 {
			if c, ok := e.creds.Lookup(ev.Dev, ev.Inode, ev.Path); ok {
				rec.File.K8sCredential = c.Kind
				rec.File.CredentialPod = c.Namespace + "/" + c.Pod
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

	parent, hasParent := e.ancestry(rec, p, h.CgroupID)
	e.attribute(rec, p, h.CgroupID)
	e.checkIdentity(rec, p, h.MntNS)
	if f := rec.File; f != nil && f.CredentialPod != "" {
		f.CredentialOtherPod = f.CredentialPod != rec.K8s.Namespace+"/"+rec.K8s.Pod
	}
	if runtimeCopy {
		e.tree.SetRuntimeChild(p.Key)
		rec.Process.Runtime = true
	}
	if x, ok := ev.(*events.Exec); ok && !rec.Process.Runtime {
		p.Identity, p.ExeModified, p.Applet = e.identify(x, rec, p)
		e.tree.SetIdentity(p.Key, p.Identity, p.ExeModified, p.Applet)
	}
	rec.Process.Identity = p.Identity
	rec.Process.ExeModified = p.ExeModified
	if rec.Container != nil {
		_, isExec := ev.(*events.Exec)
		rec.Process.IsMainBinary = e.isMainBinary(rec.Container.ID, p, isExec)
		if isExec && e.inodes != nil {
			// A new root filesystem shows up with its first exec.
			e.inodes.Observe(p.Key.PID, rec.Container.ID)
		}
		if hasParent && rec.Parent != nil && !rec.Parent.Runtime &&
			(parent.CgroupID == h.CgroupID || parent.ContainerID == rec.Container.ID) {
			rec.Parent.Identity = parent.Identity
			rec.Parent.IsMainBinary = e.isMainBinary(rec.Container.ID, parent, false)
			if first, ok := e.firstProcess(rec.Container.ID); ok {
				rec.Parent.ContainerFirst = first == parent.Key
			}
		}
	}
	return rec
}

// identify says what the binary just executed is, by content, and whether
// it changed after its container started. Only processes in containers are
// identified: the catalogue is learned from container images, and the
// change time is judged against the container's start.
func (e *Enricher) identify(ev *events.Exec, rec *export.Record, p proctree.Proc) (string, bool, string) {
	if rec.Container == nil {
		return "", false, ""
	}
	var rootPID uint32
	modified := false
	if first, ok := e.tree.OldestInContainer(rec.Container.ID); ok {
		rootPID = first.Key.PID
		started := e.boot.Add(time.Duration(first.Key.StartNS))
		if ev.CtimeNS != 0 && time.Unix(0, int64(ev.CtimeNS)).After(started.Add(exeSlack)) {
			modified = true
		}
	}
	if e.ids == nil {
		return "", modified, ""
	}
	// A new root filesystem shows up with its first exec. The process may
	// be gone by the time its event is handled (runc's setup stage often
	// is), so the root is read through the oldest live process of the
	// container if it cannot be through this one, and the container counts
	// as read only once it was: a copy of a shell executed later is
	// recognised only if the shells it was copied from were read.
	// The oldest process of a container is often runc's setup stage, long
	// exited but still in the tree; the oldest live process of the mount
	// namespace has the same root. It is looked for only when needed.
	liveRoot := func() uint32 {
		if o, ok := e.tree.MntOwner(ev.MntNS); ok && ev.MntNS != 0 {
			return o.Key.PID
		}
		return 0
	}
	if !e.idRoots[rec.Container.ID] {
		ok := e.ids.ObserveRoot(p.Key.PID)
		if !ok && rootPID != 0 && rootPID != p.Key.PID {
			ok = e.ids.ObserveRoot(rootPID)
		}
		if !ok {
			if pid := liveRoot(); pid != 0 && pid != p.Key.PID && pid != rootPID {
				ok = e.ids.ObserveRoot(pid)
			}
		}
		if ok {
			if e.idRoots == nil || len(e.idRoots) >= maxMains {
				e.idRoots = map[string]bool{}
			}
			e.idRoots[rec.Container.ID] = true
		}
	}
	x := identity.Exe{
		PID: ev.PID, Path: ev.Path, Dev: ev.Dev, Inode: ev.Inode, Ctime: ev.CtimeNS,
		Argv: ev.Argv, RootPID: rootPID, LiveRoot: liveRoot,
	}
	role := e.ids.Identify(x)
	return string(role), modified, e.ids.Applet(x)
}

// isMainBinary reports whether p runs the binary its container started
// with. The first process of a container is the oldest one the tree knows in
// it; if that process execs again, the main binary follows.
//
// A container watched while it starts has the runtime in it first: runc's
// setup processes are older than the program they hand over to, and that
// program runs in another of them. So while the oldest process is the
// runtime, the first program executed that is not the runtime becomes the
// main binary. Read from /proc later, the runtime is already gone.
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
		m = &mainBinary{key: first.Key, image: first.Image, dev: first.ExeDev, inode: first.ExeInode, applet: first.Applet, runtime: e.isRuntime(first)}
		e.mains[containerID] = m
		if m.runtime && isExec && !e.isRuntime(p) && e.containerInit(containerID, p) {
			m.key, m.image, m.dev, m.inode, m.applet, m.runtime = p.Key, p.Image, p.ExeDev, p.ExeInode, p.Applet, false
		}
	case isExec && (p.Key == m.key || m.runtime && !e.isRuntime(p) && e.containerInit(containerID, p)):
		before := *m
		m.key, m.image, m.dev, m.inode, m.applet = p.Key, p.Image, p.ExeDev, p.ExeInode, p.Applet
		m.runtime = e.isRuntime(p)
		if *m != before && e.onMainChange != nil {
			e.onMainChange(containerID)
		}
	}
	if m.runtime {
		return false
	}
	// A binary written after the container started is never the main
	// one, even at the main one's path: copying a tool over the
	// application's binary must not inherit its exemptions.
	if p.ExeModified {
		return false
	}
	// The same file, when both are known; a path names whatever file is
	// there now. Every busybox applet is the same file, so for busybox the
	// applet must be the same too: wget in a pod whose program is busybox's
	// sleep is not the main binary (A05).
	if m.inode != 0 && p.ExeInode != 0 {
		return p.ExeDev == m.dev && p.ExeInode == m.inode && p.Applet == m.applet
	}
	return p.Image != "" && p.Image == m.image
}

// containerInit reports whether p is the process the runtime hands the
// container over to: the first process born in the container's pid
// namespace. runc's init stage executes the program itself; a hook the
// runtime runs while starting the container (kind's
// mount-product-files.sh, for one) is a child of that stage, born in the
// same namespace after it, so it never takes the place. The setup stage
// that created the namespace was not born in it. Exited processes count,
// so the answer does not depend on the order exits are handled in. With
// the namespace unknown (0), any program executed qualifies, as before.
func (e *Enricher) containerInit(containerID string, p proctree.Proc) bool {
	if p.PidNS == 0 {
		return true
	}
	first, ok := e.tree.FirstBornIn(containerID, p.PidNS)
	return !ok || first.Key == p.Key
}

// firstProcess is the container's first process: the one that runs its
// program. It is the process isMainBinary settled on, so a container
// watched while it starts gets the program the runtime handed over to, not
// runc's setup stage that is older than it. While the runtime is still
// setting the container up there is no first process yet.
func (e *Enricher) firstProcess(containerID string) (proctree.Key, bool) {
	if m := e.mains[containerID]; m != nil {
		return m.key, !m.runtime
	}
	first, ok := e.tree.OldestInContainer(containerID)
	if !ok || e.isRuntime(first) {
		return proctree.Key{}, false
	}
	return first.Key, true
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
	// An unbound local side reads as the zero address, and a summary of
	// connections has none; leave it out.
	if src.Addr().IsValid() && !src.Addr().IsUnspecified() {
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
	case flags&events.FileByDev != 0:
		return "device"
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
//
// It also names the process's tree: the topmost ancestor still in the
// subject's cgroup. The walk leaves a container's cgroup at the runtime
// (the shim, or runc for an exec into the container), so that ancestor is
// the container's first process or the process an exec into it started.
// It returns the parent it found.
func (e *Enricher) ancestry(rec *export.Record, p proctree.Proc, cgroupID uint64) (parent proctree.Proc, found bool) {
	cur := p
	root, inTree := p.Key, true
	defer func() {
		rec.Process.Tree = fmt.Sprintf("%d.%d", root.PID, root.StartNS)
	}()
	for i := 0; i < proctree.MaxAncestors; i++ {
		if cur.Parent.PID == 0 {
			break
		}
		next, ok := e.parentOf(cur)
		if !ok || next.Key == cur.Key {
			break
		}
		if i == 0 {
			parent, found = next, true
			rec.Parent = &export.Parent{
				PID:         parent.Key.PID,
				Image:       parent.Image,
				CommandLine: strings.Join(parent.Argv, " "),
				Runtime:     e.isRuntime(parent),
			}
		}
		rec.Ancestors = append(rec.Ancestors, next.Image)
		if inTree && sameGroup(next, p, cgroupID) && !e.isRuntime(next) {
			root = next.Key
		} else {
			inTree = false
		}
		cur = next
	}
	return parent, found
}

// sameGroup reports whether an ancestor is in the subject's cgroup. An
// ancestor seeded from /proc that has produced no event yet has no cgroup ID,
// and is compared by container.
func sameGroup(ancestor, subject proctree.Proc, cgroupID uint64) bool {
	if ancestor.CgroupID != 0 && cgroupID != 0 {
		return ancestor.CgroupID == cgroupID
	}
	return ancestor.ContainerID != "" && ancestor.ContainerID == subject.ContainerID
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

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
