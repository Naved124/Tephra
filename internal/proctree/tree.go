// SPDX-License-Identifier: Apache-2.0

// Package proctree is the agent's cache of processes on the node. Rules need
// ancestry, which a single event does not carry.
package proctree

import (
	"container/list"
	"sort"
	"sync"
	"time"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/k8s"
)

const (
	// DefaultCap is the default maximum number of entries.
	DefaultCap = 65536
	// DefaultLinger is how long an exited process stays, so that late
	// events from other hooks still resolve.
	DefaultLinger = 60 * time.Second
	// MaxAncestors bounds an ancestor walk.
	MaxAncestors = 32

	// /proc reports start times in clock ticks; USER_HZ is 100 on every
	// Linux architecture.
	nsPerTick = 10_000_000
)

// Key identifies a process. The kernel reuses pids; (pid, start time) is
// unique for the uptime of the node.
type Key struct {
	PID     uint32
	StartNS uint64
}

// Proc is one process.
type Proc struct {
	Key    Key
	Parent Key
	Image  string
	Argv   []string
	Comm   string
	UID    uint32
	// ExeDev and ExeInode identify the file of the running binary; zero
	// if unknown. ExeDev is in the kernel's encoding.
	ExeDev   uint32
	ExeInode uint64
	// RuntimeChild marks an image with no file of its own that a node
	// runtime binary executed: runc re-executing itself from memory.
	RuntimeChild bool
	// Identity is what the running binary is by content (a shell, an
	// interpreter, a download tool), empty when unknown. ExeModified says
	// the binary changed after its container started: it is not the file
	// the image shipped. Both are set by the enricher after an exec.
	Identity    string
	ExeModified bool
	// Applet is the program a multi-call binary (busybox) runs, set by the
	// enricher after an exec; empty for any other binary.
	Applet string
	// CgroupID is 0 for a process seeded from /proc that has not produced
	// an event yet.
	CgroupID uint64
	MntNS    uint32
	// PidNS is the pid namespace the process's children are born in;
	// NetNS its network namespace.
	PidNS uint32
	NetNS uint32
	// ContainerID is set at seeding, from /proc/<pid>/cgroup.
	ContainerID string
	// Origin is the container the process was born in: the container of
	// the nearest ancestor that was not the runtime. It does not follow
	// the process into another cgroup, so a process that moves itself
	// into another container's cgroup still shows where it came from.
	// Empty for a process born on the node or handed in by the runtime,
	// and for one seeded from /proc.
	Origin string
	// Seeded entries come from /proc, whose start time is only precise to
	// one clock tick.
	Seeded bool
	// Exited is zero while the process is alive.
	Exited time.Time
	// Attr caches the pod attribution once it is complete.
	Attr *k8s.Attribution

	elem *list.Element // position in Tree.order
}

// Tree is safe for concurrent use.
type Tree struct {
	mu     sync.Mutex
	cap    int
	linger time.Duration
	procs  map[Key]*Proc
	// byPID is the most recent process seen for each pid.
	byPID map[uint32]*Proc
	// order holds every entry, oldest first; exited is the reap queue in
	// exit order.
	order  *list.List
	exited *list.List

	// The processes of each container, and the answers to "oldest in the
	// container" and "first born in its pid namespace", which every exec
	// asks. A cached answer stays right while no older process arrives
	// and it stays in the tree, in its container and namespace; index and
	// unindex keep it so, and a missing one is found again from members.
	members   map[string]map[*Proc]struct{}
	oldest    map[string]*Proc
	firstBorn map[bornKey]*Proc
}

type bornKey struct {
	containerID string
	pidNS       uint32
}

// New returns an empty tree. Zero values select the defaults.
func New(capacity int, linger time.Duration) *Tree {
	if capacity <= 0 {
		capacity = DefaultCap
	}
	if linger <= 0 {
		linger = DefaultLinger
	}
	return &Tree{
		cap:    capacity,
		linger: linger,
		procs:  make(map[Key]*Proc),
		byPID:  make(map[uint32]*Proc),
		order:  list.New(),
		exited: list.New(),

		members:   make(map[string]map[*Proc]struct{}),
		oldest:    make(map[string]*Proc),
		firstBorn: make(map[bornKey]*Proc),
	}
}

func older(a, b *Proc) bool { return a.Key.StartNS < b.Key.StartNS }

// index adds p to its container's members and to any cached answer it
// beats. A container with no cached answer is left to be found on demand.
func (t *Tree) index(p *Proc) {
	if p.ContainerID == "" {
		return
	}
	m := t.members[p.ContainerID]
	if m == nil {
		m = make(map[*Proc]struct{})
		t.members[p.ContainerID] = m
	}
	m[p] = struct{}{}
	if o, ok := t.oldest[p.ContainerID]; ok && older(p, o) {
		t.oldest[p.ContainerID] = p
	}
	k := bornKey{p.ContainerID, p.PidNS}
	if o, ok := t.firstBorn[k]; ok && older(p, o) {
		t.firstBorn[k] = p
	}
}

// unindex removes p from its container's members and drops any cached
// answer that was p.
func (t *Tree) unindex(p *Proc) {
	if p.ContainerID == "" {
		return
	}
	if m := t.members[p.ContainerID]; m != nil {
		delete(m, p)
		if len(m) == 0 {
			delete(t.members, p.ContainerID)
		}
	}
	if t.oldest[p.ContainerID] == p {
		delete(t.oldest, p.ContainerID)
	}
	k := bornKey{p.ContainerID, p.PidNS}
	if t.firstBorn[k] == p {
		delete(t.firstBorn, k)
	}
}

// Len is the number of entries, live and lingering.
func (t *Tree) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.procs)
}

// Get returns a copy of the process, or false.
func (t *Tree) Get(k Key) (Proc, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(k); p != nil {
		return *p, true
	}
	return Proc{}, false
}

// get finds a process by exact key, or a seeded one for the same pid whose
// start time falls in the same clock tick.
func (t *Tree) get(k Key) *Proc {
	if p, ok := t.procs[k]; ok {
		return p
	}
	if p, ok := t.byPID[k.PID]; ok && p.Seeded && p.Key.StartNS/nsPerTick == k.StartNS/nsPerTick {
		return p
	}
	return nil
}

func (t *Tree) insert(p *Proc) *Proc {
	// This also replaces a seeded entry for the same process, whose key is
	// only tick-precise.
	if old := t.get(p.Key); old != nil {
		t.remove(old)
	}
	for len(t.procs) >= t.cap {
		t.evict()
	}
	t.procs[p.Key] = p
	t.byPID[p.Key.PID] = p
	p.elem = t.order.PushBack(p)
	t.index(p)
	return p
}

func (t *Tree) remove(p *Proc) {
	delete(t.procs, p.Key)
	if t.byPID[p.Key.PID] == p {
		delete(t.byPID, p.Key.PID)
	}
	t.order.Remove(p.elem)
	t.unindex(p)
}

// evict drops the process that exited longest ago. If nothing has exited,
// the oldest entry goes instead.
func (t *Tree) evict() {
	for e := t.exited.Front(); e != nil; e = t.exited.Front() {
		t.exited.Remove(e)
		// The queue can hold entries that were already replaced.
		if p := e.Value.(*Proc); t.procs[p.Key] == p {
			t.remove(p)
			return
		}
	}
	if e := t.order.Front(); e != nil {
		t.remove(e.Value.(*Proc))
	}
}

// Fork records a new process. The child starts as a copy of its parent.
func (t *Tree) Fork(ev *events.Fork) {
	t.mu.Lock()
	defer t.mu.Unlock()

	child := &Proc{
		Key:      Key{ev.ChildPID, ev.ChildStartNS},
		Parent:   Key{ev.ParentPID, ev.ParentStartNS},
		Comm:     ev.Comm,
		UID:      ev.UID,
		CgroupID: ev.CgroupID,
		MntNS:    ev.MntNS,
		PidNS:    ev.PidNS,
		NetNS:    ev.NetNS,
	}
	// The forking task and the real parent differ only with CLONE_PARENT;
	// either way the child's image is the forking task's.
	if src := t.get(Key{ev.PID, ev.StartTimeNS}); src != nil {
		child.Image = src.Image
		child.Argv = src.Argv
		child.ExeDev = src.ExeDev
		child.ExeInode = src.ExeInode
		child.RuntimeChild = src.RuntimeChild
		child.Identity = src.Identity
		child.ExeModified = src.ExeModified
		child.Applet = src.Applet
		child.ContainerID = src.ContainerID
		child.Origin = src.Origin
		child.Attr = src.Attr
	}
	t.insert(child)
}

// Exec records the new image of a process, creating the entry if the fork was
// never seen. It returns a copy of the updated process.
func (t *Tree) Exec(ev *events.Exec) Proc {
	t.mu.Lock()
	defer t.mu.Unlock()

	k := Key{ev.PID, ev.StartTimeNS}
	p := t.get(k)
	if p == nil {
		p = t.insert(&Proc{Key: k})
		if parent, ok := t.byPID[ev.PPID]; ok && ev.PPID != 0 {
			p.Parent = parent.Key
		} else {
			p.Parent = Key{PID: ev.PPID}
		}
	}
	p.Image = ev.Path
	p.Argv = ev.Argv
	p.ExeDev = ev.Dev
	p.ExeInode = ev.Inode
	p.RuntimeChild = false
	p.Identity = ""
	p.ExeModified = false
	p.Applet = ""
	p.Comm = ev.Comm
	p.UID = ev.UID
	if p.CgroupID != ev.CgroupID {
		// Moved cgroup, or seeded without one: attribution is stale.
		p.CgroupID = ev.CgroupID
		p.Attr = nil
	}
	p.MntNS = ev.MntNS
	if p.PidNS != ev.PidNS {
		t.unindex(p)
		p.PidNS = ev.PidNS
		t.index(p)
	}
	p.NetNS = ev.NetNS
	return *p
}

// Exit marks a process as exited. It stays resolvable for the linger period.
func (t *Tree) Exit(ev *events.Exit, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(Key{ev.PID, ev.StartTimeNS}); p != nil && p.Exited.IsZero() {
		p.Exited = now
		t.exited.PushBack(p)
	}
}

// MarkExited marks a live process as exited whose exit event never arrived,
// lost with the ring buffer's drops. It reports whether it was live.
func (t *Tree) MarkExited(k Key, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(k); p != nil && p.Exited.IsZero() {
		p.Exited = now
		t.exited.PushBack(p)
		return true
	}
	return false
}

// Prune marks as exited every live process that alive says is gone, and
// returns how many. When the ring buffer drops records, exits are among
// them, and the tree keeps the processes as live: ghosts, which a later
// lookup can take for the owner of a reused namespace number (E26). alive
// is called without the tree's lock held. It also returns how many it
// checked.
func (t *Tree) Prune(alive func(Proc) bool, now time.Time) (gone, checked int) {
	live := t.Live()
	for _, p := range live {
		if !alive(p) && t.MarkExited(p.Key, now) {
			gone++
		}
	}
	return gone, len(live)
}

// ByPID returns a copy of the most recent process seen with a pid.
func (t *Tree) ByPID(pid uint32) (Proc, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.byPID[pid]; ok {
		return *p, true
	}
	return Proc{}, false
}

// OldestInContainer returns the earliest-started process known in a
// container, live or lingering: the container's first process, as long as it
// is still there.
func (t *Tree) OldestInContainer(containerID string) (Proc, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.oldest[containerID]; ok {
		return *p, true
	}
	var best *Proc
	for p := range t.members[containerID] {
		if best == nil || older(p, best) {
			best = p
		}
	}
	if best == nil {
		return Proc{}, false
	}
	t.oldest[containerID] = best
	return *best, true
}

// SetOrigin records the container a process was born in.
func (t *Tree) SetOrigin(k Key, id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(k); p != nil {
		p.Origin = id
	}
}

// FirstBornIn returns the oldest process the tree has, exited or not, of a
// container whose children are born in a pid namespace: the namespace's
// first process. Exited processes count, so the answer does not depend on
// whether an exit was handled before a later event.
func (t *Tree) FirstBornIn(containerID string, pidNS uint32) (Proc, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := bornKey{containerID, pidNS}
	if p, ok := t.firstBorn[k]; ok {
		return *p, true
	}
	var best *Proc
	for p := range t.members[containerID] {
		if p.PidNS == pidNS && (best == nil || older(p, best)) {
			best = p
		}
	}
	if best == nil {
		return Proc{}, false
	}
	t.firstBorn[k] = best
	return *best, true
}

// InNamespace returns the live processes in a namespace of a kind (mnt,
// pid or net), oldest first.
func (t *Tree) InNamespace(kind string, inum uint32) []Proc {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Proc
	for _, p := range t.procs {
		if !p.Exited.IsZero() {
			continue
		}
		switch {
		case kind == "mnt" && p.MntNS == inum, kind == "pid" && p.PidNS == inum, kind == "net" && p.NetNS == inum:
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.StartNS < out[j].Key.StartNS })
	return out
}

// MntOwner returns the oldest live process in a mount namespace. A
// container's mount namespace is made for its first program, so that
// process is older than anything that enters the namespace later.
func (t *Tree) MntOwner(mnt uint32) (Proc, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var best *Proc
	for _, p := range t.procs {
		if p.MntNS == mnt && p.Exited.IsZero() && (best == nil || p.Key.StartNS < best.Key.StartNS) {
			best = p
		}
	}
	if best == nil {
		return Proc{}, false
	}
	return *best, true
}

// SetContainerID records which container a process runs in.
func (t *Tree) SetContainerID(k Key, id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(k); p != nil && p.ContainerID != id {
		t.unindex(p)
		p.ContainerID = id
		t.index(p)
	}
}

// Live returns a copy of every process that has not exited.
func (t *Tree) Live() []Proc {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Proc, 0, len(t.procs))
	for _, p := range t.procs {
		if p.Exited.IsZero() {
			out = append(out, *p)
		}
	}
	return out
}

// SetRuntimeChild marks the current image of a process as the runtime's own.
func (t *Tree) SetRuntimeChild(k Key) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(k); p != nil {
		p.RuntimeChild = true
	}
}

// SetIdentity records what the process's current binary is.
func (t *Tree) SetIdentity(k Key, identity string, modified bool, applet string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(k); p != nil {
		p.Identity = identity
		p.ExeModified = modified
		p.Applet = applet
	}
}

// SetParent records a new parent, after the kernel re-parented a process
// whose original parent exited.
func (t *Tree) SetParent(k, parent Key) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(k); p != nil {
		p.Parent = parent
	}
}

// SetAttr caches a complete attribution on a process.
func (t *Tree) SetAttr(k Key, a *k8s.Attribution) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.get(k); p != nil {
		p.Attr = a
	}
}

// Add inserts a process learned from /proc, unless events already described
// it. It returns a copy of the entry now in the tree.
func (t *Tree) Add(p Proc) Proc {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur := t.get(p.Key); cur != nil {
		return *cur
	}
	// An entry built from events has a nanosecond key that the tick-precise
	// key from /proc cannot match exactly.
	if cur, ok := t.byPID[p.Key.PID]; ok && cur.Key.StartNS/nsPerTick == p.Key.StartNS/nsPerTick {
		return *cur
	}
	p.Seeded = true
	p.Exited = time.Time{}
	return *t.insert(&p)
}

// Ancestors returns the chain above a process, nearest first.
func (t *Tree) Ancestors(k Key) []Proc {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []Proc
	p := t.get(k)
	for p != nil && len(out) < MaxAncestors {
		parent := t.get(p.Parent)
		// pid 0 has no entry; a self-parent would loop.
		if parent == nil || parent == p {
			break
		}
		out = append(out, *parent)
		p = parent
	}
	return out
}

// Reap removes processes that exited more than the linger period ago, and
// returns how many.
func (t *Tree) Reap(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	n := 0
	for e := t.exited.Front(); e != nil; e = t.exited.Front() {
		p := e.Value.(*Proc)
		if now.Sub(p.Exited) < t.linger {
			break
		}
		t.exited.Remove(e)
		if t.procs[p.Key] == p {
			t.remove(p)
			n++
		}
	}
	return n
}
