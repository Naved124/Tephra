// SPDX-License-Identifier: Apache-2.0

// Package proctree is the agent's cache of processes on the node. Rules need
// ancestry, which a single event does not carry.
package proctree

import (
	"container/list"
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
	// CgroupID is 0 for a process seeded from /proc that has not produced
	// an event yet.
	CgroupID uint64
	MntNS    uint32
	// ContainerID is set at seeding, from /proc/<pid>/cgroup.
	ContainerID string
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
	return p
}

func (t *Tree) remove(p *Proc) {
	delete(t.procs, p.Key)
	if t.byPID[p.Key.PID] == p {
		delete(t.byPID, p.Key.PID)
	}
	t.order.Remove(p.elem)
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
	}
	// The forking task and the real parent differ only with CLONE_PARENT;
	// either way the child's image is the forking task's.
	if src := t.get(Key{ev.PID, ev.StartTimeNS}); src != nil {
		child.Image = src.Image
		child.Argv = src.Argv
		child.ContainerID = src.ContainerID
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
	p.Comm = ev.Comm
	p.UID = ev.UID
	if p.CgroupID != ev.CgroupID {
		// Moved cgroup, or seeded without one: attribution is stale.
		p.CgroupID = ev.CgroupID
		p.Attr = nil
	}
	p.MntNS = ev.MntNS
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

// ByPID returns a copy of the most recent process seen with a pid.
func (t *Tree) ByPID(pid uint32) (Proc, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.byPID[pid]; ok {
		return *p, true
	}
	return Proc{}, false
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
