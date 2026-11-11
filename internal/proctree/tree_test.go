// SPDX-License-Identifier: Apache-2.0

package proctree

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/k8s"
)

func fork(parent, child Key) *events.Fork {
	return &events.Fork{
		Header:    events.Header{PID: parent.PID, StartTimeNS: parent.StartNS, CgroupID: 7},
		ChildPID:  child.PID,
		ParentPID: parent.PID, ChildStartNS: child.StartNS, ParentStartNS: parent.StartNS,
	}
}

func execEv(k Key, path string, argv ...string) *events.Exec {
	return &events.Exec{
		Header: events.Header{PID: k.PID, StartTimeNS: k.StartNS, CgroupID: 7},
		Path:   path, Argv: argv,
	}
}

func exit(k Key) *events.Exit {
	return &events.Exit{Header: events.Header{PID: k.PID, StartTimeNS: k.StartNS}}
}

func images(ps []Proc) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Image)
	}
	return out
}

func TestForkExecAncestry(t *testing.T) {
	tr := New(0, 0)
	shim, nginx, sh := Key{10, 100}, Key{20, 200}, Key{30, 300}

	tr.Exec(execEv(shim, "/usr/bin/containerd-shim-runc-v2", "shim"))
	tr.Fork(fork(shim, nginx))
	// Between fork and exec the child is a copy of its parent.
	if p, _ := tr.Get(nginx); p.Image != "/usr/bin/containerd-shim-runc-v2" {
		t.Errorf("forked child image = %q, want the parent's", p.Image)
	}
	tr.Exec(execEv(nginx, "/usr/sbin/nginx", "nginx"))
	tr.Fork(fork(nginx, sh))
	tr.Exec(execEv(sh, "/bin/sh", "sh", "-i"))

	got := images(tr.Ancestors(sh))
	want := []string{"/usr/sbin/nginx", "/usr/bin/containerd-shim-runc-v2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ancestors = %v, want %v", got, want)
	}
	if p, _ := tr.Get(sh); p.Parent != nginx || !reflect.DeepEqual(p.Argv, []string{"sh", "-i"}) {
		t.Errorf("sh entry = %+v", p)
	}
}

// A reused pid must not resolve to the previous process.
func TestPidReuse(t *testing.T) {
	tr := New(0, 0)
	parent, old, reused := Key{1, 1}, Key{50, 1000}, Key{50, 9_000_000_000}
	tr.Exec(execEv(parent, "/sbin/init"))
	tr.Fork(fork(parent, old))
	tr.Exec(execEv(old, "/bin/old"))
	tr.Exit(exit(old), time.Unix(0, 0))
	tr.Fork(fork(parent, reused))
	tr.Exec(execEv(reused, "/bin/new"))

	if p, ok := tr.Get(old); !ok || p.Image != "/bin/old" {
		t.Errorf("old process = %+v, %v; want it still resolvable", p, ok)
	}
	if p, _ := tr.Get(reused); p.Image != "/bin/new" {
		t.Errorf("reused pid resolves to %q", p.Image)
	}
}

func TestExitLingersThenReaps(t *testing.T) {
	tr := New(0, time.Minute)
	k := Key{5, 50}
	tr.Exec(execEv(k, "/bin/x"))
	t0 := time.Unix(1000, 0)
	tr.Exit(exit(k), t0)
	tr.Exit(exit(k), t0.Add(time.Hour)) // a duplicate must not extend the linger

	if n := tr.Reap(t0.Add(59 * time.Second)); n != 0 {
		t.Errorf("reaped %d before the linger period", n)
	}
	if _, ok := tr.Get(k); !ok {
		t.Error("exited process not resolvable during linger")
	}
	if n := tr.Reap(t0.Add(61 * time.Second)); n != 1 {
		t.Errorf("reaped %d after the linger period, want 1", n)
	}
	if _, ok := tr.Get(k); ok || tr.Len() != 0 {
		t.Error("process still present after reap")
	}
}

func TestCapEvictsOldestExitedFirst(t *testing.T) {
	tr := New(3, 0)
	a, b, c, d, e := Key{1, 1}, Key{2, 2}, Key{3, 3}, Key{4, 4}, Key{5, 5}
	for _, k := range []Key{a, b, c} {
		tr.Exec(execEv(k, fmt.Sprint("/bin/", k.PID)))
	}
	tr.Exit(exit(b), time.Unix(1, 0))

	tr.Exec(execEv(d, "/bin/4")) // evicts b, the only exited one
	if _, ok := tr.Get(b); ok {
		t.Error("exited process survived eviction")
	}
	if _, ok := tr.Get(a); !ok {
		t.Error("live process evicted while an exited one existed")
	}

	tr.Exec(execEv(e, "/bin/5")) // nothing exited: the oldest entry goes
	if _, ok := tr.Get(a); ok {
		t.Error("oldest live process survived with no exited entries")
	}
	if tr.Len() != 3 {
		t.Errorf("len = %d, want the cap of 3", tr.Len())
	}
}

// /proc start times are tick-precise; kernel events are nanosecond-precise.
func TestSeededEntryMatchesByTick(t *testing.T) {
	tr := New(0, 0)
	seeded := Proc{Key: Key{77, 1230 * nsPerTick}, Image: "/usr/sbin/nginx", ContainerID: "abc"}
	tr.Add(seeded)
	exact := Key{77, 1230*nsPerTick + 4_567_891}

	if p, ok := tr.Get(exact); !ok || p.Image != "/usr/sbin/nginx" {
		t.Fatalf("seeded entry not found by exact key: %+v %v", p, ok)
	}
	// Same pid, a later tick: a different process.
	if _, ok := tr.Get(Key{77, 1231 * nsPerTick}); ok {
		t.Error("seeded entry matched a different start tick")
	}

	// A child forked by the seeded process inherits and links to it.
	child := Key{78, 99_000_000_000}
	tr.Fork(fork(exact, child))
	if got := images(tr.Ancestors(child)); !reflect.DeepEqual(got, []string{"/usr/sbin/nginx"}) {
		t.Errorf("ancestors through a seeded parent = %v", got)
	}
	if p, _ := tr.Get(child); p.ContainerID != "abc" {
		t.Errorf("child container ID = %q, want inherited", p.ContainerID)
	}

	// Its exit is applied to the seeded entry, which then reaps.
	tr.Exit(exit(exact), time.Unix(0, 0))
	tr.Reap(time.Unix(3600, 0))
	if _, ok := tr.Get(exact); ok {
		t.Error("seeded entry not reaped after its exit")
	}
}

// Events win over /proc, and a later fork replaces a seeded duplicate.
func TestAddDoesNotOverrideEvents(t *testing.T) {
	tr := New(0, 0)
	k := Key{9, 500*nsPerTick + 3}
	tr.Exec(execEv(k, "/from/event"))
	tr.Add(Proc{Key: Key{9, 500 * nsPerTick}, Image: "/from/proc"})
	if p, _ := tr.Get(k); p.Image != "/from/event" || tr.Len() != 1 {
		t.Errorf("after Add: image %q, len %d", p.Image, tr.Len())
	}

	tr2 := New(0, 0)
	tr2.Add(Proc{Key: Key{9, 500 * nsPerTick}, Image: "/from/proc"})
	tr2.Fork(fork(Key{1, 1}, k))
	if tr2.Len() != 1 {
		t.Errorf("fork left the seeded duplicate: len %d", tr2.Len())
	}
}

func TestExecMovingCgroupDropsAttribution(t *testing.T) {
	tr := New(0, 0)
	k := Key{3, 3}
	tr.Exec(execEv(k, "/usr/bin/runc", "runc", "init"))
	tr.SetAttr(k, &k8s.Attribution{ContainerID: "old", ContainerName: "c"})
	ev := execEv(k, "/bin/sh")
	ev.CgroupID = 8
	if p := tr.Exec(ev); p.Attr != nil {
		t.Error("attribution kept across a cgroup change")
	}
}

func TestAncestorsStopOnCycleAndMissing(t *testing.T) {
	tr := New(0, 0)
	self := Key{1, 1}
	tr.Add(Proc{Key: self, Parent: self, Image: "/sbin/init"})
	if got := tr.Ancestors(self); len(got) != 0 {
		t.Errorf("self-parented process has ancestors %v", got)
	}
	orphan := Key{2, 2}
	tr.Add(Proc{Key: orphan, Parent: Key{999, 1}})
	if got := tr.Ancestors(orphan); len(got) != 0 {
		t.Errorf("missing parent produced ancestors %v", got)
	}
}

func TestParseStat(t *testing.T) {
	// comm containing spaces and parentheses, as a process can set.
	line := "4242 (tmux: server (1) x) S 77 4242 4242 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 987654 1000 200 18446744073709551615"
	comm, ppid, ticks, err := parseStat([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if comm != "tmux: server (1) x" || ppid != 77 || ticks != 987654 {
		t.Errorf("got comm %q ppid %d ticks %d", comm, ppid, ticks)
	}
	for _, bad := range []string{"", "1 (x", "1 (x) S 2", "1 (x) S notanumber 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21"} {
		if _, _, _, err := parseStat([]byte(bad)); err == nil {
			t.Errorf("parseStat(%q) succeeded", bad)
		}
	}
}

func writeProc(t *testing.T, root string, pid, ppid int, ticks uint64, exe, cmdline, cgroup string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (c) S %d 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0", pid, ppid, ticks)
	files := map[string]string{
		"stat":    stat,
		"cmdline": cmdline,
		"status":  "Name:\tc\nUid:\t33\t33\t33\t33\nGid:\t33\t33\t33\t33\n",
		"cgroup":  "0::" + cgroup + "\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if exe != "" {
		if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSeedFromProc(t *testing.T) {
	root := t.TempDir()
	const cid = "3f9c0000000000000000000000000000000000000000000000000000000000aa"
	scope := "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod0a1b2c3d_1111_2222_3333_444455556666.slice/cri-containerd-" + cid + ".scope"
	// The child sorts before its parent, so linking must not depend on order.
	writeProc(t, root, 15, 200, 5000, "/usr/sbin/nginx", "nginx: worker process\x00", scope)
	writeProc(t, root, 200, 1, 4000, "/usr/sbin/nginx", "nginx\x00-g\x00daemon off;\x00", scope)
	writeProc(t, root, 1, 0, 10, "/sbin/init", "/sbin/init\x00", "/init.scope")
	writeProc(t, root, 2, 0, 11, "", "", "/") // kernel thread
	if err := os.WriteFile(filepath.Join(root, "uptime"), []byte("1 1"), 0o644); err != nil {
		t.Fatal(err)
	}

	tr := New(0, 0)
	n, err := tr.Seed(ProcFS{Root: root})
	if err != nil || n != 4 {
		t.Fatalf("Seed = %d, %v; want 4", n, err)
	}

	worker, ok := tr.Get(Key{15, 5000 * nsPerTick})
	if !ok {
		t.Fatal("worker not seeded")
	}
	if worker.Image != "/usr/sbin/nginx" || worker.UID != 33 || worker.ContainerID != cid || !worker.Seeded {
		t.Errorf("worker = %+v", worker)
	}
	if !reflect.DeepEqual(worker.Argv, []string{"nginx: worker process"}) {
		t.Errorf("worker argv = %q", worker.Argv)
	}
	if got := images(tr.Ancestors(worker.Key)); !reflect.DeepEqual(got, []string{"/usr/sbin/nginx", "/sbin/init"}) {
		t.Errorf("seeded ancestors = %v", got)
	}
	master, _ := tr.Get(Key{200, 4000 * nsPerTick})
	if !reflect.DeepEqual(master.Argv, []string{"nginx", "-g", "daemon off;"}) {
		t.Errorf("master argv = %q", master.Argv)
	}
	if init, _ := tr.Get(Key{1, 10 * nsPerTick}); init.ContainerID != "" {
		t.Errorf("init container ID = %q, want none", init.ContainerID)
	}

	// Lookup of a single late pid links to a parent already in the tree.
	writeProc(t, root, 300, 200, 6000, "/bin/sh", "sh\x00", scope)
	p, ok := tr.Lookup(ProcFS{Root: root}, 300)
	if !ok || p.Parent != master.Key {
		t.Errorf("Lookup = %+v, %v; want parent %v", p, ok, master.Key)
	}
	if _, ok := tr.Lookup(ProcFS{Root: root}, 9999); ok {
		t.Error("Lookup of a missing pid succeeded")
	}
}
