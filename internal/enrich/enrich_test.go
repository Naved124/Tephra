// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Naved124/tephra/internal/credwatch"
	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/identity"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/proctree"
)

const (
	cid    = "3f9c0000000000000000000000000000000000000000000000000000000000aa"
	podUID = "0a1b2c3d-1111-2222-3333-444455556666"
	tick   = 10_000_000
)

type fixture struct {
	t       testing.TB
	proc    string
	cgroups string
	tree    *proctree.Tree
	pods    *k8s.PodIndex
	e       *Enricher
	dead    map[uint32]bool
}

func newFixture(t testing.TB) *fixture {
	f := &fixture{
		t:       t,
		proc:    t.TempDir(),
		cgroups: t.TempDir(),
		tree:    proctree.New(0, 0),
		pods:    k8s.NewPodIndex(),
	}
	f.e = New("kind-worker", f.tree, proctree.ProcFS{Root: f.proc}, k8s.NewCgroupResolver(f.cgroups), f.pods)
	f.e.boot = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
	// Processes made from events have no /proc entry here; the ones a
	// test kills are gone.
	f.dead = map[uint32]bool{}
	f.e.alive = func(p proctree.Proc, _ uint32) bool { return !f.dead[p.Key.PID] }
	return f
}

// cgroup creates a cgroup directory and returns its ID, the inode number.
func (f *fixture) cgroup(rel string) uint64 {
	f.t.Helper()
	dir := filepath.Join(f.cgroups, rel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		f.t.Fatal(err)
	}
	return st.Sys().(*syscall.Stat_t).Ino
}

func (f *fixture) procEntry(pid, ppid uint32, ticks uint64, exe string, argv ...string) {
	f.t.Helper()
	dir := filepath.Join(f.proc, fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(dir, "root", "etc"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	write("stat", fmt.Sprintf("%d (c) S %d 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0", pid, ppid, ticks))
	write("cmdline", strings.Join(argv, "\x00")+"\x00")
	write("status", "Uid:\t0\t0\t0\t0\n")
	write("cgroup", "0::/\n")
	write("root/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n# comment:x:33:33::/:/bin/false\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		f.t.Fatal(err)
	}
}

// inContainer puts an existing /proc entry into the web container's cgroup.
func (f *fixture) inContainer(pid uint32) {
	f.t.Helper()
	path := filepath.Join(f.proc, fmt.Sprint(pid), "cgroup")
	if err := os.WriteFile(path, []byte("0::/"+scope+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) webPod() {
	f.pods.Update(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-7c9d8-xk2lp", Namespace: "shop", UID: podUID, Labels: map[string]string{"app": "web"}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "web", Image: "nginx:1.27", ContainerID: "containerd://" + cid},
		}},
	})
}

const scope = "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod0a1b2c3d_1111_2222_3333_444455556666.slice/cri-containerd-" + cid + ".scope"

// The event from section 5 of the design: a shell under nginx in a pod.
func TestExecInPod(t *testing.T) {
	f := newFixture(t)
	f.webPod()
	cg := f.cgroup(scope)

	// The shim and nginx predate the agent and are known only to /proc.
	f.procEntry(100, 1, 1000, "/usr/bin/containerd-shim-runc-v2", "containerd-shim-runc-v2", "-namespace", "k8s.io")
	f.procEntry(48190, 100, 2000, "/usr/sbin/nginx", "nginx: worker process")
	f.inContainer(48190)
	// The shell itself, for the passwd lookup through its root.
	f.procEntry(48211, 48190, 9182, "/bin/sh", "sh", "-i")
	if _, err := f.tree.Seed(proctree.ProcFS{Root: f.proc}); err != nil {
		t.Fatal(err)
	}

	nginx := proctree.Key{PID: 48190, StartNS: 2000*tick + 123}
	sh := proctree.Key{PID: 48211, StartNS: 91822330114}
	f.e.Handle(&events.Fork{
		Header:   events.Header{Type: events.TypeFork, PID: nginx.PID, StartTimeNS: nginx.StartNS, CgroupID: cg, UID: 33},
		ChildPID: sh.PID, ChildStartNS: sh.StartNS, ParentPID: nginx.PID, ParentStartNS: nginx.StartNS,
	}, time.Now())
	rec := f.e.Handle(&events.Exec{
		Header: events.Header{
			Type: events.TypeExec, TSBootNS: uint64(22*time.Minute + 31*time.Second + 4512*time.Microsecond),
			PID: sh.PID, StartTimeNS: sh.StartNS, PPID: nginx.PID, CgroupID: cg, UID: 33, GID: 33, MntNS: 4026532001,
			Flags: events.ExecStdinSock | events.ExecStdoutSock,
		},
		Path: "/bin/sh", Argv: []string{"sh", "-i"}, Inode: 77,
	}, time.Now())

	want := &export.Record{
		TS: "2026-11-10T08:22:31.004512Z", Type: "exec", Node: "kind-worker",
		Process: export.Process{
			PID: 48211, StartTimeNS: 91822330114, Image: "/bin/sh", CommandLine: "sh -i",
			User: "www-data", UID: 33, GID: 33, CgroupID: cg,
			// The nginx worker: the shim above it is not in the
			// container's cgroup.
			Tree: "48190.20000000000",
			Exec: &export.Exec{StdinIsSocket: true, StdoutIsSocket: true, Inode: 77},
		},
		// nginx is both the container's first process and its
		// application.
		Parent:    &export.Parent{PID: 48190, Image: "/usr/sbin/nginx", CommandLine: "nginx: worker process", IsMainBinary: true, ContainerFirst: true},
		Ancestors: []string{"/usr/sbin/nginx", "/usr/bin/containerd-shim-runc-v2"},
		Container: &export.Container{ID: cid, Name: "web", Image: "nginx:1.27"},
		K8s:       export.K8s{Namespace: "shop", Pod: "web-7c9d8-xk2lp", Labels: map[string]string{"app": "web"}},
	}
	if !reflect.DeepEqual(rec, want) {
		t.Errorf("got  %s\nwant %s", toJSON(t, rec), toJSON(t, want))
	}

	// The wire names are the contract with rules and dashboards.
	line := toJSON(t, rec)
	for _, field := range []string{
		`"ts":"2026-11-10T08:22:31.004512Z"`, `"type":"exec"`, `"node":"kind-worker"`,
		`"Image":"/bin/sh"`, `"CommandLine":"sh -i"`, `"User":"www-data"`, `"uid":33`,
		`"stdin_is_socket":true`, `"stdout_is_socket":true`, `"start_time_ns":91822330114`,
		`"parent":{"pid":48190,"Image":"/usr/sbin/nginx","CommandLine":"nginx: worker process","is_main_binary":true,"container_first":true}`,
		`"ancestors":["/usr/sbin/nginx","/usr/bin/containerd-shim-runc-v2"]`,
		`"container":{"id":"` + cid + `","name":"web","image":"nginx:1.27"}`,
		`"k8s":{"namespace":"shop","pod":"web-7c9d8-xk2lp","labels":{"app":"web"}}`,
	} {
		if !strings.Contains(line, field) {
			t.Errorf("JSON lacks %s\n%s", field, line)
		}
	}
}

func TestHostProcess(t *testing.T) {
	f := newFixture(t)
	cg := f.cgroup("system.slice/containerd.service")
	f.procEntry(1, 0, 1, "/sbin/init", "/sbin/init")

	rec := f.e.Handle(&events.Exec{
		Header: events.Header{Type: events.TypeExec, PID: 500, StartTimeNS: 5, PPID: 1, CgroupID: cg},
		Path:   "/usr/bin/ls", Argv: []string{"ls"},
	}, time.Now())
	if rec.Container != nil || rec.K8s.Namespace != export.NamespaceHost || rec.K8s.Pod != "" {
		t.Errorf("host process attributed as %+v / %+v", rec.Container, rec.K8s)
	}
	if !strings.Contains(toJSON(t, rec), `"k8s":{"namespace":"host"}`) {
		t.Errorf("host JSON = %s", toJSON(t, rec))
	}
	if rec.Parent == nil || rec.Parent.Image != "/sbin/init" {
		t.Errorf("parent = %+v, want init read from /proc", rec.Parent)
	}
}

// A cgroup that cannot be resolved must not be passed off as a host process.
func TestUnresolvedCgroupIsUnknown(t *testing.T) {
	f := newFixture(t)
	rec := f.e.Handle(&events.Exec{
		Header: events.Header{Type: events.TypeExec, PID: 500, StartTimeNS: 5, CgroupID: 1 << 60},
		Path:   "/bin/x",
	}, time.Now())
	if rec.K8s.Namespace != export.NamespaceUnknown || rec.Container != nil {
		t.Errorf("unresolved cgroup attributed as %+v / %+v", rec.Container, rec.K8s)
	}
}

// The first exec of a new container runs before its status reaches the API
// server: the pod resolves through the UID in the cgroup path, and the
// container name follows once the status arrives.
func TestContainerStatusArrivesLate(t *testing.T) {
	f := newFixture(t)
	cg := f.cgroup(scope)
	f.pods.Update(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "shop", UID: podUID}})

	k := proctree.Key{PID: 700, StartNS: 7}
	ev := &events.Exec{Header: events.Header{Type: events.TypeExec, PID: k.PID, StartTimeNS: k.StartNS, CgroupID: cg}, Path: "/docker-entrypoint.sh"}
	rec := f.e.Handle(ev, time.Now())
	if rec.K8s.Pod != "web-1" || rec.K8s.Namespace != "shop" || rec.Container == nil || rec.Container.ID != cid || rec.Container.Name != "" {
		t.Errorf("early exec = %+v / %+v", rec.Container, rec.K8s)
	}
	if p, _ := f.tree.Get(k); p.Attr != nil {
		t.Error("an incomplete attribution was cached")
	}

	f.webPod()
	ev.Path = "/usr/sbin/nginx"
	rec = f.e.Handle(ev, time.Now())
	if rec.Container.Name != "web" || rec.Container.Image != "nginx:1.27" {
		t.Errorf("after status update, container = %+v", rec.Container)
	}
	if p, _ := f.tree.Get(k); !p.Attr.Complete() {
		t.Error("complete attribution not cached on the process")
	}
}

// Without a cluster the container ID still comes through.
func TestNoPodIndex(t *testing.T) {
	f := newFixture(t)
	f.e.pods = nil
	cg := f.cgroup(scope)
	rec := f.e.Handle(&events.Exec{Header: events.Header{Type: events.TypeExec, PID: 9, StartTimeNS: 9, CgroupID: cg}, Path: "/bin/x"}, time.Now())
	if rec.Container == nil || rec.Container.ID != cid || rec.K8s.Namespace != export.NamespaceUnknown {
		t.Errorf("got %+v / %+v", rec.Container, rec.K8s)
	}
}

func TestForkAndExitRecords(t *testing.T) {
	f := newFixture(t)
	cg := f.cgroup("system.slice/x.service")
	parent := proctree.Key{PID: 10, StartNS: 100}
	child := proctree.Key{PID: 11, StartNS: 200}
	f.e.Handle(&events.Exec{Header: events.Header{Type: events.TypeExec, PID: parent.PID, StartTimeNS: parent.StartNS, CgroupID: cg}, Path: "/bin/bash", Argv: []string{"bash"}}, time.Now())

	rec := f.e.Handle(&events.Fork{
		Header:   events.Header{Type: events.TypeFork, PID: parent.PID, StartTimeNS: parent.StartNS, CgroupID: cg},
		ChildPID: child.PID, ChildStartNS: child.StartNS, ParentPID: parent.PID, ParentStartNS: parent.StartNS,
	}, time.Now())
	if rec.Type != "fork" || rec.Process.PID != 11 || rec.Process.Image != "/bin/bash" || rec.Parent == nil || rec.Parent.PID != 10 || rec.Process.Exec != nil {
		t.Errorf("fork record = %s", toJSON(t, rec))
	}

	now := time.Unix(5000, 0)
	rec = f.e.Handle(&events.Exit{Header: events.Header{Type: events.TypeExit, PID: child.PID, StartTimeNS: child.StartNS, CgroupID: cg}, Status: 2 << 8}, now)
	if rec.Type != "exit" || rec.Exit == nil || rec.Exit.Code != 2 || rec.Process.Image != "/bin/bash" {
		t.Errorf("exit record = %s", toJSON(t, rec))
	}
	if p, _ := f.tree.Get(child); !p.Exited.Equal(now) {
		t.Errorf("exit not recorded in the tree: %+v", p)
	}

	// An exit for a process nobody knows still yields a usable record.
	rec = f.e.Handle(&events.Exit{Header: events.Header{Type: events.TypeExit, PID: 999, StartTimeNS: 1, PPID: 10, Comm: "ghost", CgroupID: cg}}, now)
	if rec.Process.PID != 999 || rec.Process.Image != "ghost" {
		t.Errorf("unknown-process exit = %s", toJSON(t, rec))
	}
}

// runc forks the container's first process and exits; the kernel hands the
// child to the shim. Once runc is forgotten the chain must follow.
func TestReparentedAfterParentExit(t *testing.T) {
	f := newFixture(t)
	cg := f.cgroup(scope)
	shim := proctree.Key{PID: 100, StartNS: 1000 * tick}
	runc := proctree.Key{PID: 200, StartNS: 50_000_000_001}
	sh := proctree.Key{PID: 201, StartNS: 50_100_000_002}
	child := proctree.Key{PID: 300, StartNS: 99_000_000_003}
	hdr := func(typ events.Type, k proctree.Key, ppid uint32) events.Header {
		return events.Header{Type: typ, PID: k.PID, StartTimeNS: k.StartNS, PPID: ppid, CgroupID: cg}
	}

	f.procEntry(shim.PID, 1, 1000, "/usr/bin/containerd-shim-runc-v2", "shim")
	f.e.Handle(&events.Exec{Header: hdr(events.TypeExec, runc, shim.PID), Path: "/usr/bin/runc", Argv: []string{"runc", "create"}}, time.Now())
	f.e.Handle(&events.Fork{Header: hdr(events.TypeFork, runc, shim.PID), ChildPID: sh.PID, ChildStartNS: sh.StartNS, ParentPID: runc.PID, ParentStartNS: runc.StartNS}, time.Now())
	rec := f.e.Handle(&events.Exec{Header: hdr(events.TypeExec, sh, runc.PID), Path: "/bin/sh", Argv: []string{"sh"}}, time.Now())
	if want := []string{"/usr/bin/runc", "/usr/bin/containerd-shim-runc-v2"}; !reflect.DeepEqual(rec.Ancestors, want) {
		t.Errorf("while runc lives, ancestors = %v, want %v", rec.Ancestors, want)
	}

	// runc exits and is reaped from the tree; /proc now shows the shim as
	// the shell's parent.
	t0 := time.Unix(1000, 0)
	f.e.Handle(&events.Exit{Header: hdr(events.TypeExit, runc, shim.PID)}, t0)
	f.procEntry(sh.PID, shim.PID, sh.StartNS/tick, "/bin/sh", "sh")

	// Still lingering: the exited parent is replaced by the live one.
	f.e.Handle(&events.Fork{Header: hdr(events.TypeFork, sh, shim.PID), ChildPID: child.PID, ChildStartNS: child.StartNS, ParentPID: sh.PID, ParentStartNS: sh.StartNS}, t0)
	f.tree.Reap(t0.Add(time.Hour))
	rec = f.e.Handle(&events.Exec{Header: hdr(events.TypeExec, child, sh.PID), Path: "/bin/sleep", Argv: []string{"sleep", "5"}}, t0)
	if want := []string{"/bin/sh", "/usr/bin/containerd-shim-runc-v2"}; !reflect.DeepEqual(rec.Ancestors, want) {
		t.Errorf("after runc exited, ancestors = %v, want %v", rec.Ancestors, want)
	}
	if p, _ := f.tree.Get(sh); p.Parent.PID != shim.PID {
		t.Errorf("shell's parent in the tree = %d, want the shim %d", p.Parent.PID, shim.PID)
	}
}

// The header's ppid is the kernel's word at event time and overrides a stale
// link in the tree.
func TestHeaderPPIDOverridesStaleParent(t *testing.T) {
	f := newFixture(t)
	cg := f.cgroup("system.slice/x.service")
	f.procEntry(1, 0, 1, "/sbin/init", "init")
	f.procEntry(50, 1, 500, "/usr/bin/old-parent", "old")
	k := proctree.Key{PID: 60, StartNS: 77}
	f.e.Handle(&events.Fork{Header: events.Header{Type: events.TypeFork, PID: 50, StartTimeNS: 500 * tick, CgroupID: cg}, ChildPID: k.PID, ChildStartNS: k.StartNS, ParentPID: 50, ParentStartNS: 500 * tick}, time.Now())
	rec := f.e.Handle(&events.Exec{Header: events.Header{Type: events.TypeExec, PID: k.PID, StartTimeNS: k.StartNS, PPID: 1, CgroupID: cg}, Path: "/bin/daemon"}, time.Now())
	if rec.Parent == nil || rec.Parent.PID != 1 || rec.Parent.Image != "/sbin/init" {
		t.Errorf("parent = %+v, want init from the header's ppid", rec.Parent)
	}
}

func TestLookupPasswd(t *testing.T) {
	passwd := "root:x:0:0::/root:/bin/sh\nmalformed line\n:x:33:33::/:/x\n#www:x:33:33::/:/x\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nother:x:33:33::/:/x\nshort:x\n"
	for uid, want := range map[uint32]string{0: "root", 33: "www-data", 1000: ""} {
		if got := lookupPasswd(strings.NewReader(passwd), uid); got != want {
			t.Errorf("uid %d = %q, want %q", uid, got, want)
		}
	}
}

func TestJSONLinesNoHTMLEscape(t *testing.T) {
	var buf bytes.Buffer
	out := export.NewJSONLines(&buf)
	rec := &export.Record{Type: "exec", Process: export.Process{CommandLine: "sh -c 'a && b > /dev/null <&1'"}}
	if err := out.Write(rec); err != nil {
		t.Fatal(err)
	}
	if err := out.Write(rec); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Error("records written before Flush")
	}
	if err := out.Flush(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `a && b > /dev/null <&1`) {
		t.Errorf("output = %q", buf.String())
	}
	var back export.Record
	if err := json.Unmarshal([]byte(lines[1]), &back); err != nil {
		t.Errorf("line is not valid JSON: %v", err)
	}
}

func toJSON(t testing.TB, r *export.Record) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type observed struct {
	pid   uint32
	owner string
}

type fakeObserver struct{ seen []observed }

func (o *fakeObserver) Observe(pid uint32, owner string) {
	o.seen = append(o.seen, observed{pid, owner})
}

func (o *fakeObserver) WatchedPath(dev uint32, inode uint64) (string, bool) {
	if dev == 0x100002 && inode == 9 {
		return "/etc/shadow", true
	}
	return "", false
}

// webShell sets up nginx as the container's first process and returns the
// header of a process it then starts.
func (f *fixture) webShell(image string, argv ...string) events.Header {
	f.t.Helper()
	f.webPod()
	cg := f.cgroup(scope)
	f.procEntry(100, 1, 1000, "/usr/bin/containerd-shim-runc-v2", "containerd-shim-runc-v2")
	f.procEntry(48190, 100, 2000, "/usr/sbin/nginx", "nginx: master process")
	f.inContainer(48190)
	if _, err := f.tree.Seed(proctree.ProcFS{Root: f.proc}); err != nil {
		f.t.Fatal(err)
	}
	h := events.Header{PID: 48300, StartTimeNS: 99_000_000_000, PPID: 48190, CgroupID: cg, UID: 33, GID: 33}
	h.Type = events.TypeExec
	f.e.Handle(&events.Exec{Header: h, Path: image, Argv: argv}, time.Now())
	return h
}

func TestNetworkRecords(t *testing.T) {
	f := newFixture(t)
	h := f.webShell("/usr/bin/curl", "curl", "https://kubernetes.default")
	f.e.SetAPIServers([]netip.AddrPort{netip.MustParseAddrPort("10.96.0.1:443")})

	h.Type = events.TypeConnect
	rec := f.e.Handle(&events.Net{
		Header: h, Family: events.AFInet, Proto: 6,
		Local:  netip.MustParseAddrPort("0.0.0.0:0"),
		Remote: netip.MustParseAddrPort("10.96.0.1:443"),
	}, time.Now())
	want := &export.Network{Direction: "outbound", Family: "ipv4", Protocol: "tcp", DestinationIP: "10.96.0.1", DestinationPort: 443, IsK8sAPI: true}
	if !reflect.DeepEqual(rec.Network, want) {
		t.Errorf("connect: got %+v, want %+v", rec.Network, want)
	}
	// The event is tied to the process the tree already knows.
	if rec.Type != "connect" || rec.Process.Image != "/usr/bin/curl" || rec.Process.CommandLine != "curl https://kubernetes.default" ||
		rec.Parent == nil || rec.Parent.Image != "/usr/sbin/nginx" || rec.K8s.Pod != "web-7c9d8-xk2lp" || rec.Process.Exec != nil {
		t.Errorf("connect record: %s", toJSON(t, rec))
	}
	if rec.Process.IsMainBinary {
		t.Error("curl reported as the container's main binary")
	}

	h.Type = events.TypeAccept
	rec = f.e.Handle(&events.Net{
		Header: h, Family: events.AFInet6, Proto: 6,
		Local:  netip.MustParseAddrPort("[fd00:10:244::5]:8080"),
		Remote: netip.MustParseAddrPort("[fd00:10:244::9]:51000"),
	}, time.Now())
	want = &export.Network{Direction: "inbound", Family: "ipv6", Protocol: "tcp",
		SourceIP: "fd00:10:244::9", SourcePort: 51000, DestinationIP: "fd00:10:244::5", DestinationPort: 8080}
	if !reflect.DeepEqual(rec.Network, want) {
		t.Errorf("accept: got %+v, want %+v", rec.Network, want)
	}

	h.Type = events.TypeUnixConnect
	rec = f.e.Handle(&events.UnixConnect{Header: h, Path: "/run/containerd/containerd.sock"}, time.Now())
	if rec.Type != "connect" || rec.Network.Family != "unix" || rec.Network.UnixPath != "/run/containerd/containerd.sock" {
		t.Errorf("unix connect record: %s", toJSON(t, rec))
	}
}

func TestFileRecord(t *testing.T) {
	f := newFixture(t)
	f.e.ObserveRoots(&fakeObserver{})
	h := f.webShell("/bin/cat", "cat", "/tmp/link")
	h.Type = events.TypeFileOpen
	h.Flags = events.FileByInode
	rec := f.e.Handle(&events.FileOpen{Header: h, Inode: 9, Dev: 0x100002, OpenFlags: 0o1 | events.OTrunc, WatchBits: 3, Path: "/tmp/link"}, time.Now())
	want := &export.File{Path: "/tmp/link", Target: "/etc/shadow", Flags: 0o1001, Write: true, Truncate: true, Inode: 9, Dev: 0x100002, MatchedBy: "inode"}
	if !reflect.DeepEqual(rec.File, want) {
		t.Errorf("got %+v, want %+v", rec.File, want)
	}
	if rec.Type != "file_open" || rec.Process.Image != "/bin/cat" || rec.Container == nil {
		t.Errorf("file record: %s", toJSON(t, rec))
	}
}

// A write refused through a hard link names the protected file.
func TestEnforceRecordTarget(t *testing.T) {
	f := newFixture(t)
	f.e.ObserveRoots(&fakeObserver{})
	h := f.webShell("/bin/sh", "sh")
	h.Type = events.TypeEnforce
	h.Flags = events.EnforceDenied
	rec := f.e.Handle(&events.Enforce{Header: h, Action: "file_write", Inode: 9, Dev: 0x100002, Path: "/tmp/link"}, time.Now())
	want := &export.File{Path: "/tmp/link", Target: "/etc/shadow", Write: true, Inode: 9, Dev: 0x100002, MatchedBy: "block"}
	if !reflect.DeepEqual(rec.File, want) || rec.Enforce == nil || !rec.Enforce.Denied {
		t.Errorf("got %s", toJSON(t, rec))
	}
}

// The main binary is the one the container's first process runs, and it
// follows that process through a later exec.
func TestMainBinary(t *testing.T) {
	f := newFixture(t)
	obs := &fakeObserver{}
	f.e.ObserveRoots(obs)
	h := f.webShell("/bin/sh", "sh")

	rec := f.e.Handle(&events.Exec{Header: h, Path: "/usr/sbin/nginx", Argv: []string{"nginx", "-t"}}, time.Now())
	if !rec.Process.IsMainBinary {
		t.Error("a second nginx is not reported as the main binary")
	}
	// Every exec in a container is shown to the root observer.
	if want := []observed{{48300, cid}, {48300, cid}}; !reflect.DeepEqual(obs.seen, want) {
		t.Errorf("observed %v, want %v", obs.seen, want)
	}

	// The first process execs something else, as "sh -c 'exec app'" does.
	first, _ := f.tree.ByPID(48190)
	init := events.Header{Type: events.TypeExec, PID: first.Key.PID, StartTimeNS: first.Key.StartNS, PPID: 100, CgroupID: h.CgroupID}
	rec = f.e.Handle(&events.Exec{Header: init, Path: "/app/server", Argv: []string{"server"}}, time.Now())
	if !rec.Process.IsMainBinary {
		t.Error("the first process is not the main binary after its own exec")
	}
	rec = f.e.Handle(&events.Exec{Header: h, Path: "/usr/sbin/nginx", Argv: []string{"nginx"}}, time.Now())
	if rec.Process.IsMainBinary {
		t.Error("nginx still the main binary after the first process moved on")
	}

	// A host process never is.
	host := f.cgroup("system.slice/ssh.service")
	rec = f.e.Handle(&events.Exec{Header: events.Header{Type: events.TypeExec, PID: 700, StartTimeNS: 5, CgroupID: host}, Path: "/usr/sbin/sshd"}, time.Now())
	if rec.Process.IsMainBinary || rec.Container != nil {
		t.Errorf("host process: %s", toJSON(t, rec))
	}
}

func TestExecEnv(t *testing.T) {
	f := newFixture(t)
	cg := f.cgroup("system.slice/x.service")
	rec := f.e.Handle(&events.Exec{
		Header: events.Header{Type: events.TypeExec, PID: 9, StartTimeNS: 1, CgroupID: cg, Flags: events.ExecEnvTrunc},
		Path:   "/bin/true", Env: []string{"LD_PRELOAD=/tmp/x.so", "LD_LIBRARY_PATH="},
	}, time.Now())
	want := map[string]string{"LD_PRELOAD": "/tmp/x.so", "LD_LIBRARY_PATH": ""}
	if !reflect.DeepEqual(rec.Process.Env, want) || !rec.Process.EnvTruncated {
		t.Errorf("env %v truncated %v", rec.Process.Env, rec.Process.EnvTruncated)
	}
	if got := rec.Process.EnvNames(); !reflect.DeepEqual(got, []string{"LD_LIBRARY_PATH", "LD_PRELOAD"}) {
		t.Errorf("env names %v", got)
	}
}

// One open on overlayfs is reported once.
func TestNestedOverlayOpenDropped(t *testing.T) {
	f := newFixture(t)
	h := f.webShell("/bin/cat", "cat", "/etc/shadow")
	h.Type = events.TypeFileOpen
	h.TID = 48300
	h.TSBootNS = 1_000_000_000
	path := "/etc/shadow"
	open := func(flags uint32, inode uint64, at uint64) *export.Record {
		h := h
		h.Flags = flags
		h.TSBootNS = at
		return f.e.Handle(&events.FileOpen{Header: h, Inode: inode, Path: path}, time.Now())
	}
	kernel := uint32(events.FileByPath | events.FileKernelCreds)

	if open(events.FileByInode, 9, 1_000_000_000) == nil {
		t.Fatal("the process's own open was dropped")
	}
	if open(kernel, 9, 1_000_009_000) != nil {
		t.Error("the backing-file open that followed it was reported again")
	}
	// A file that was copied up has another inode number in the upper
	// layer; the path still says it is the same open.
	if open(events.FileByInode, 9, 1_100_000_000) == nil {
		t.Fatal("the process's own open was dropped")
	}
	if open(kernel, 77, 1_100_009_000) != nil {
		t.Error("the backing-file open of a copied-up file was reported again")
	}
	// Everything else under substituted credentials is kept: another
	// file, a later time, a thread with no open reported.
	path = "/etc/gshadow"
	if open(kernel, 10, 1_100_010_000) == nil {
		t.Error("an open of another file was dropped")
	}
	path = "/etc/shadow"
	if open(kernel, 9, 1_500_000_000) == nil {
		t.Error("an open long after the first was dropped")
	}
	h.TID = 48301
	if open(kernel, 9, 1_000_009_000) == nil {
		t.Error("an open in another thread was dropped")
	}
	if f.e.NestedOpens() != 2 {
		t.Errorf("nested opens = %d, want 2", f.e.NestedOpens())
	}
}

func TestDeniedPath(t *testing.T) {
	for _, c := range []struct {
		name, cwd string
		flags     uint32
		want      string
	}{
		{"/etc/shadow", "", 0, "/etc/shadow"},
		{"/etc/../etc/./shadow", "", 0, "/etc/shadow"},
		{"shadow", "/etc", 0, "/etc/shadow"},
		{"../etc/shadow", "/tmp", 0, "/etc/shadow"},
		{"/proc/self/root/etc/shadow", "", 0, "/etc/shadow"},
		{"/proc/1234/root/proc/thread-self/root/etc/shadow", "", 0, "/etc/shadow"},
		{"/proc/self/task/7/root", "", 0, "/"},
		// No working directory to join: left as it was passed.
		{"shadow", "", events.DeniedNoCwd, "shadow"},
		{"shadow", "/a/b", events.DeniedCwdCut, "shadow"},
	} {
		ev := &events.FileDenied{Header: events.Header{Flags: c.flags}, Name: c.name, Cwd: c.cwd}
		if got := deniedPath(ev); got != c.want {
			t.Errorf("deniedPath(%q in %q) = %q, want %q", c.name, c.cwd, got, c.want)
		}
	}
}

func TestDeniedOpenKeptOnlyWhenWatched(t *testing.T) {
	f := newFixture(t)
	f.webPod()
	h := f.webShell("/bin/cat", "cat", "shadow")
	h.Type = events.TypeFileDenied
	ev := &events.FileDenied{Header: h, Errno: uint32(syscall.EACCES), Name: "shadow", Cwd: "/etc"}

	if rec := f.e.Handle(ev, time.Now()); rec != nil {
		t.Fatalf("a refused open is reported with no matcher set: %+v", rec.File)
	}
	f.e.SetWatched(func(p string) uint32 {
		if p == "/etc/shadow" {
			return 4
		}
		return 0
	})
	rec := f.e.Handle(ev, time.Now())
	if rec == nil {
		t.Fatal("a refused open of a watched file is dropped")
	}
	if rec.Type != "file_denied" || rec.File.Path != "/etc/shadow" || rec.File.Error != "EACCES" || rec.File.Write {
		t.Errorf("record %s %+v", rec.Type, rec.File)
	}
	if rec.K8s.Pod == "" {
		t.Error("refused open not attributed to its pod")
	}

	ev.Name = "/etc/hostname"
	if rec := f.e.Handle(ev, time.Now()); rec != nil {
		t.Errorf("a refused open of an unwatched file is reported: %+v", rec.File)
	}
	if f.e.DeniedUnwatched() != 2 {
		t.Errorf("DeniedUnwatched() = %d, want 2", f.e.DeniedUnwatched())
	}
}

func TestFileChangeRecord(t *testing.T) {
	f := newFixture(t)
	f.webPod()
	h := f.webShell("/bin/mv", "mv", "/tmp/p", "/etc/ld.so.preload")
	h.Type = events.TypeFileChange
	h.Flags = events.FileByPath
	rec := f.e.Handle(&events.FileChange{Header: h, Op: "rename_to", Path: "/etc/ld.so.preload"}, time.Now())
	if rec.Type != "file_change" || rec.File.Op != "rename_to" || !rec.File.Write || rec.File.MatchedBy != "path" {
		t.Errorf("record %s %+v", rec.Type, rec.File)
	}
}

type fakeRuntimes map[[2]uint64]bool

func (r fakeRuntimes) Has(dev uint32, inode uint64) bool { return r[[2]uint64{uint64(dev), inode}] }

// The runtime is known by the file it runs, and by nothing a process can
// choose for itself.
func TestRuntimeByIdentity(t *testing.T) {
	f := newFixture(t)
	f.webPod()
	f.e.SetRuntimes(fakeRuntimes{{8, 100}: true})
	cg := f.cgroup("system.slice/containerd.service")
	pod := f.cgroup(scope)
	exec := func(pid uint32, path string, dev uint32, inode uint64, flags uint32, argv ...string) *export.Record {
		return f.e.Handle(&events.Exec{
			Header: events.Header{Type: events.TypeExec, PID: pid, StartTimeNS: uint64(pid) * 1000, PPID: 1, CgroupID: cg, Flags: flags},
			Path:   path, Dev: dev, Inode: inode, Argv: argv,
		}, time.Now())
	}

	if rec := exec(50, "/usr/local/sbin/runc", 8, 100, 0, "runc", "create"); !rec.Process.Runtime {
		t.Error("the node's runc is not recognised")
	}
	// runc re-executing a copy of itself from memory.
	if rec := exec(50, "/proc/self/fd/7", 1, 999, events.ExecUnlinked, "runc", "init"); !rec.Process.Runtime {
		t.Error("runc init run from memory by the node's runc is not recognised")
	}
	// What that copy executes next is the container's own program.
	if rec := exec(50, "/proc/self/fd/3", 1, 555, events.ExecUnlinked, "runc", "init"); rec.Process.Runtime {
		t.Error("a second image without a file inherits the runtime's standing")
	}

	// The same name and command line on another file is not the runtime,
	if rec := exec(60, "/usr/local/sbin/runc", 8, 200, 0, "runc", "create"); rec.Process.Runtime {
		t.Error("a binary recognised by its path alone")
	}
	// nor is what it runs from memory,
	if rec := exec(60, "/proc/self/fd/7", 1, 998, events.ExecUnlinked, "runc", "init"); rec.Process.Runtime {
		t.Error("runc init recognised without the node's runc behind it")
	}
	// nor anything else the real runc executes from memory.
	exec(70, "/usr/local/sbin/runc", 8, 100, 0, "runc", "exec")
	if rec := exec(70, "/proc/self/fd/9", 1, 997, events.ExecUnlinked, "payload"); rec.Process.Runtime {
		t.Error("an arbitrary memory image run by runc is taken for the runtime")
	}

	// Newer runc runs itself through a private overlay, already in the
	// container's cgroup: the same inode number on another device.
	exec(75, "/usr/local/sbin/runc", 8, 100, 0, "runc", "exec")
	sealed := func(pid uint32, inode uint64, argv ...string) *export.Record {
		return f.e.Handle(&events.Exec{
			Header: events.Header{Type: events.TypeExec, PID: pid, StartTimeNS: uint64(pid) * 1000, PPID: 1, CgroupID: pod},
			Path:   "/proc/self/fd/6", Dev: 404, Inode: inode, Argv: argv,
		}, time.Now())
	}
	if rec := sealed(75, 100, "runc", "init"); !rec.Process.Runtime || rec.Container == nil {
		t.Errorf("runc init through an overlay not recognised (runtime %v, container %v)", rec.Process.Runtime, rec.Container)
	}
	// The program it then executes in the container is not the runtime,
	// whatever it calls itself.
	if rec := sealed(75, 100, "runc", "init"); rec.Process.Runtime {
		t.Error("a program executed by runc init is taken for the runtime")
	}
	// A runc that runs its own file as "runc init" is the runtime by
	// identity; what that executes is not, even from memory and under
	// runc's command line.
	exec(76, "/usr/local/sbin/runc", 8, 100, 0, "runc", "exec")
	if rec := exec(76, "/usr/local/sbin/runc", 8, 100, 0, "runc", "init"); !rec.Process.Runtime {
		t.Error("runc init run from runc's own file is not recognised")
	}
	if rec := exec(76, "/proc/self/fd/9", 1, 996, events.ExecUnlinked, "runc", "init"); rec.Process.Runtime {
		t.Error("a memory image executed by runc init is taken for the runtime")
	}
	// Another file with another inode number, on a filesystem of the
	// caller's choosing.
	exec(77, "/usr/local/sbin/runc", 8, 100, 0, "runc", "exec")
	if rec := sealed(77, 4242, "runc", "init"); rec.Process.Runtime {
		t.Error("a file that is neither unlinked nor runc's inode is taken for the runtime")
	}

	// A child of the runtime runs the same file until it execs.
	exec(80, "/usr/local/sbin/runc", 8, 100, 0, "runc", "create")
	f.e.Handle(&events.Fork{
		Header:   events.Header{Type: events.TypeFork, PID: 80, StartTimeNS: 80000, CgroupID: cg},
		ChildPID: 81, ChildStartNS: 81000, ParentPID: 80, ParentStartNS: 80000,
	}, time.Now())
	rec := exec(81, "/bin/true", 8, 300, 0, "true")
	if rec.Process.Runtime {
		t.Error("a program executed by the runtime is taken for the runtime")
	}
	if rec.Parent == nil || !rec.Parent.Runtime {
		t.Errorf("parent of a process started by runc not marked as the runtime: %+v", rec.Parent)
	}
}

type fakeIdentifier struct {
	roots []uint32
	asked []identity.Exe
	roles map[string]identity.Role
	// gone are processes whose root can no longer be read.
	gone map[uint32]bool
}

func (f *fakeIdentifier) ObserveRoot(pid uint32) bool {
	f.roots = append(f.roots, pid)
	return !f.gone[pid]
}

func (f *fakeIdentifier) Identify(x identity.Exe) identity.Role {
	f.asked = append(f.asked, x)
	return f.roles[x.Path]
}

// A binary in a container is identified by content, and judged against
// the container's start: a file changed after it is not from the image.
func TestIdentityAndDrift(t *testing.T) {
	f := newFixture(t)
	ids := &fakeIdentifier{roles: map[string]identity.Role{"/tmp/kworker": identity.Shell}}
	f.e.SetIdentity(ids)
	h := f.webShell("/bin/sh", "sh")

	// The container started at its first process's start; a file written
	// now is long after that, one from the image long before.
	now := uint64(time.Now().UnixNano())
	rec := f.e.Handle(&events.Exec{Header: h, Path: "/tmp/kworker", Argv: []string{"/tmp/kworker"}, Dev: 5, Inode: 77, CtimeNS: now}, time.Now())
	if rec.Process.Identity != "shell" || !rec.Process.ExeModified {
		t.Errorf("copied shell: identity %q modified %v", rec.Process.Identity, rec.Process.ExeModified)
	}
	last := ids.asked[len(ids.asked)-1]
	if last.PID != h.PID || last.RootPID != 48190 || last.Inode != 77 || last.Ctime != now {
		t.Errorf("asked %+v", last)
	}
	// The container's root was shown once, with its first exec.
	if !reflect.DeepEqual(ids.roots, []uint32{h.PID}) {
		t.Errorf("roots observed %v", ids.roots)
	}

	// Later events of the process carry what its exec found.
	h2 := h
	h2.Type = events.TypeFileOpen
	rec = f.e.Handle(&events.FileOpen{Header: h2, Path: "/etc/shadow"}, time.Now())
	if rec.Process.Identity != "shell" || !rec.Process.ExeModified {
		t.Errorf("file_open after exec: identity %q modified %v", rec.Process.Identity, rec.Process.ExeModified)
	}

	// A file from the image: changed before the container started.
	rec = f.e.Handle(&events.Exec{Header: h, Path: "/usr/bin/id", Argv: []string{"id"}, Dev: 5, Inode: 78, CtimeNS: 1}, time.Now())
	if rec.Process.Identity != "" || rec.Process.ExeModified {
		t.Errorf("image file: identity %q modified %v", rec.Process.Identity, rec.Process.ExeModified)
	}

	// Host processes are not identified.
	before := len(ids.asked)
	host := f.cgroup("system.slice/ssh.service")
	rec = f.e.Handle(&events.Exec{Header: events.Header{Type: events.TypeExec, PID: 700, StartTimeNS: 5, CgroupID: host}, Path: "/tmp/kworker", CtimeNS: now}, time.Now())
	if len(ids.asked) != before || rec.Process.Identity != "" || rec.Process.ExeModified {
		t.Errorf("host process identified: %s", toJSON(t, rec))
	}
}

// A container's root is read even when the process of its first exec is
// gone by the time the event is handled, and is not counted as read until
// it was: E01 and E09 were missed when it was.
func TestRootReadThroughLiveProcess(t *testing.T) {
	f := newFixture(t)
	h := f.webShell("/bin/sh", "sh")
	ids := &fakeIdentifier{gone: map[uint32]bool{h.PID: true}}
	f.e.SetIdentity(ids)
	f.e.Handle(&events.Exec{Header: h, Path: "/usr/bin/id", Argv: []string{"id"}, Dev: 5, Inode: 78}, time.Now())
	if !reflect.DeepEqual(ids.roots, []uint32{h.PID, 48190}) {
		t.Fatalf("roots asked %v, want the process then the container's oldest", ids.roots)
	}
	f.e.Handle(&events.Exec{Header: h, Path: "/usr/bin/id", Argv: []string{"id"}, Dev: 5, Inode: 78}, time.Now())
	if len(ids.roots) != 2 {
		t.Errorf("a root that was read is read again: %v", ids.roots)
	}

	// Neither readable: asked again at the next exec.
	g := newFixture(t)
	h = g.webShell("/bin/sh", "sh")
	ids = &fakeIdentifier{gone: map[uint32]bool{h.PID: true, 48190: true}}
	g.e.SetIdentity(ids)
	g.e.Handle(&events.Exec{Header: h, Path: "/usr/bin/id", Argv: []string{"id"}, Dev: 5, Inode: 78}, time.Now())
	ids.gone = nil
	g.e.Handle(&events.Exec{Header: h, Path: "/usr/bin/id", Argv: []string{"id"}, Dev: 5, Inode: 78}, time.Now())
	if !reflect.DeepEqual(ids.roots, []uint32{h.PID, 48190, h.PID}) {
		t.Errorf("roots asked %v, want a retry at the second exec", ids.roots)
	}
}

// The main binary is the same file as the container's first process, not
// a file at the same path; and a file changed after the start never is.
func TestMainBinaryByFile(t *testing.T) {
	f := newFixture(t)
	h := f.webShell("/bin/sh", "sh")
	first, _ := f.tree.ByPID(48190)
	init := events.Header{Type: events.TypeExec, PID: first.Key.PID, StartTimeNS: first.Key.StartNS, PPID: 100, CgroupID: h.CgroupID}
	f.e.Handle(&events.Exec{Header: init, Path: "/app/server", Argv: []string{"server"}, Dev: 5, Inode: 500, CtimeNS: 1}, time.Now())

	rec := f.e.Handle(&events.Exec{Header: h, Path: "/app/server", Argv: []string{"server"}, Dev: 5, Inode: 500, CtimeNS: 1}, time.Now())
	if !rec.Process.IsMainBinary {
		t.Error("same file is not the main binary")
	}
	// A tool copied over the main binary's path: another file.
	rec = f.e.Handle(&events.Exec{Header: h, Path: "/app/server", Argv: []string{"server"}, Dev: 5, Inode: 501, CtimeNS: 1}, time.Now())
	if rec.Process.IsMainBinary {
		t.Error("another file at the main binary's path is the main binary")
	}
	// Written in place over the main binary: same inode, changed since.
	rec = f.e.Handle(&events.Exec{Header: h, Path: "/app/server", Argv: []string{"server"}, Dev: 5, Inode: 500, CtimeNS: uint64(time.Now().UnixNano())}, time.Now())
	if rec.Process.IsMainBinary || !rec.Process.ExeModified {
		t.Error("main binary overwritten in place is still the main binary")
	}
}

// An interpreter in a container starts a shell on a terminal, as a pty
// relay does (E13): the shell's record says so, and says what its parent is.
func TestPtyAndParentFacts(t *testing.T) {
	f := newFixture(t)
	f.e.SetIdentity(&fakeIdentifier{roles: map[string]identity.Role{"/usr/local/bin/python3": identity.Interpreter}})
	h := f.webShell("/usr/local/bin/python3", "python3", "-")

	// The interpreter's own parent is nginx: first process and application.
	rec := f.e.Handle(&events.Exec{Header: h, Path: "/usr/local/bin/python3", Argv: []string{"python3", "-"}, Inode: 90}, time.Now())
	if rec.Parent == nil || !rec.Parent.ContainerFirst || !rec.Parent.IsMainBinary || rec.Parent.Identity != "" {
		t.Fatalf("python's parent: %s", toJSON(t, rec))
	}
	if rec.Process.Identity != "interpreter" {
		t.Errorf("python identity %q", rec.Process.Identity)
	}

	child := events.Header{Type: events.TypeFork, PID: h.PID, StartTimeNS: h.StartTimeNS, CgroupID: h.CgroupID}
	f.e.Handle(&events.Fork{Header: child, ChildPID: 48301, ChildStartNS: 99_500_000_000, ParentPID: h.PID, ParentStartNS: h.StartTimeNS}, time.Now())
	sh := events.Header{
		Type: events.TypeExec, PID: 48301, StartTimeNS: 99_500_000_000, PPID: h.PID, CgroupID: h.CgroupID,
		Flags: events.ExecStdinPty | events.ExecStdoutPty,
	}
	rec = f.e.Handle(&events.Exec{Header: sh, Path: "/bin/sh", Argv: []string{"sh"}, Inode: 91}, time.Now())
	if !rec.Process.StdinIsPty || !rec.Process.StdoutIsPty || rec.Process.StdinIsSocket {
		t.Errorf("stdio: %s", toJSON(t, rec))
	}
	p := rec.Parent
	if p == nil || p.PID != h.PID || p.Identity != "interpreter" || p.IsMainBinary || p.ContainerFirst {
		t.Errorf("shell's parent: %s", toJSON(t, rec))
	}

	// A host process's parent carries none of it.
	host := f.cgroup("system.slice/ssh.service")
	rec = f.e.Handle(&events.Exec{Header: events.Header{Type: events.TypeExec, PID: 701, StartTimeNS: 6, PPID: 1, CgroupID: host}, Path: "/bin/sh"}, time.Now())
	if p := rec.Parent; p != nil && (p.Identity != "" || p.IsMainBinary || p.ContainerFirst) {
		t.Errorf("host parent: %s", toJSON(t, rec))
	}
}

// Access to the agent is named, by pid and start time: a process that later
// gets the agent's pid number is not the agent.
func TestPtraceTargetIsAgent(t *testing.T) {
	f := newFixture(t)
	cg := f.cgroup("system.slice/containerd.service")
	f.e.SetAgent(3121, 777)
	for _, tc := range []struct {
		pid   uint32
		start uint64
		want  bool
	}{
		{3121, 777, true},
		{3121, 999, false},
		{4100, 777, false},
	} {
		rec := f.e.Handle(&events.Ptrace{
			Header:    events.Header{Type: events.TypePtrace, PID: 600, StartTimeNS: 6, PPID: 1, CgroupID: cg},
			TargetPID: tc.pid, TargetStartNS: tc.start, Mode: 2,
		}, time.Now())
		if rec.Ptrace == nil || rec.Ptrace.TargetIsAgent != tc.want {
			t.Errorf("target %d/%d: %+v, want target_is_agent %v", tc.pid, tc.start, rec.Ptrace, tc.want)
		}
	}
}

// A container watched while it starts has runc in it before its program, in
// another process. The program runc hands over to is the main binary, not
// runc, and a terminal it gives a shell is the application's (Phase 4 run
// 1: R029 fired on a notebook's terminals until the agent restarted).
func TestMainBinaryOfContainerSeenStarting(t *testing.T) {
	f := newFixture(t)
	f.webPod()
	f.e.SetRuntimes(fakeRuntimes{{8, 100}: true})
	host := f.cgroup("system.slice/containerd.service")
	pod := f.cgroup(scope)
	exec := func(pid, ppid uint32, cg uint64, path string, dev uint32, inode uint64, argv ...string) *export.Record {
		return f.e.Handle(&events.Exec{
			Header: events.Header{Type: events.TypeExec, PID: pid, StartTimeNS: uint64(pid) * 1000, PPID: ppid, CgroupID: cg},
			Path:   path, Dev: dev, Inode: inode, Argv: argv,
		}, time.Now())
	}
	// runc's first setup process, already in the container's cgroup.
	exec(80, 1, host, "/usr/local/sbin/runc", 8, 100, "runc", "create")
	if rec := exec(80, 1, pod, "/usr/local/sbin/runc", 8, 100, "runc", "init"); !rec.Process.Runtime || rec.Process.IsMainBinary {
		t.Fatalf("runc init: runtime %v, main %v", rec.Process.Runtime, rec.Process.IsMainBinary)
	}
	// The second one executes the container's program.
	exec(81, 80, pod, "/usr/local/sbin/runc", 8, 100, "runc", "init")
	if rec := exec(81, 80, pod, "/usr/local/bin/python3", 9, 7000, "python3", "-c", "notebook"); !rec.Process.IsMainBinary {
		t.Error("the program runc handed over to is not the main binary")
	}
	// A terminal shell the notebook starts: its parent is the application.
	if rec := exec(90, 81, pod, "/bin/sh", 9, 7100, "sh", "-c", "ls /"); rec.Parent == nil || !rec.Parent.IsMainBinary || rec.Process.IsMainBinary {
		t.Errorf("shell under the application: parent %+v, main %v", rec.Parent, rec.Process.IsMainBinary)
	}
	// Something executed later never takes the place.
	if rec := exec(95, 1, pod, "/usr/bin/perl", 9, 7200, "perl"); rec.Process.IsMainBinary {
		t.Error("a later program became the main binary")
	}
}

// Two more pods for the identity tests: the agent's and a bystander's.
const (
	agentCID     = "a9e00000000000000000000000000000000000000000000000000000000000bb"
	bystanderCID = "b7500000000000000000000000000000000000000000000000000000000000cc"
	agentScope   = "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-podaaaa0000_1111_2222_3333_444455556666.slice/cri-containerd-" + agentCID + ".scope"
	byScope      = "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-podbbbb0000_1111_2222_3333_444455556666.slice/cri-containerd-" + bystanderCID + ".scope"
)

func (f *fixture) identityPods() (web, agent, bystander uint64) {
	f.webPod()
	f.pods.Update(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "tephra-agent-x1", Namespace: "tephra", UID: "aaaa0000-1111-2222-3333-444455556666"},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "agent", Image: "tephra/tephrad", ContainerID: "containerd://" + agentCID}}},
	})
	f.pods.Update(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "bystander", Namespace: "shop", UID: "bbbb0000-1111-2222-3333-444455556666"},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "bystander", Image: "busybox", ContainerID: "containerd://" + bystanderCID}}},
	})
	return f.cgroup(scope), f.cgroup(agentScope), f.cgroup(byScope)
}

// A process that moves into another container's cgroup is named where it
// came from (E15, E20, E26), and one in the agent's container that is not the
// agent is marked.
func TestBorrowedIdentity(t *testing.T) {
	f := newFixture(t)
	web, agentCg, byCg := f.identityPods()
	const webMnt, agentMnt, byMnt = 4026530001, 4026530002, 4026530003
	f.e.agent, f.e.agentContainer, f.e.agentMnt = proctree.Key{PID: 7000, StartNS: 7000 * 1000}, agentCID, agentMnt

	exec := func(pid, ppid uint32, cg uint64, mnt uint32, path string) *export.Record {
		return f.e.Handle(&events.Exec{
			Header: events.Header{Type: events.TypeExec, PID: pid, StartTimeNS: uint64(pid) * 1000, PPID: ppid, CgroupID: cg, MntNS: mnt},
			Path:   path, Argv: []string{path},
		}, time.Now())
	}
	fork := func(parent, child uint32, cg uint64, mnt uint32) {
		f.e.Handle(&events.Fork{
			Header:    events.Header{Type: events.TypeFork, PID: parent, StartTimeNS: uint64(parent) * 1000, CgroupID: cg, MntNS: mnt},
			ParentPID: parent, ParentStartNS: uint64(parent) * 1000, ChildPID: child, ChildStartNS: uint64(child) * 1000,
		}, time.Now())
	}
	// The containers' own programs, oldest in their namespaces.
	exec(100, 1, web, webMnt, "/bin/sh")
	exec(200, 1, byCg, byMnt, "/bin/sleep")

	// E15 and E20: a child of the web pod's shell moves into the agent's
	// cgroup and runs cat there.
	fork(100, 101, web, webMnt)
	rec := exec(101, 100, agentCg, webMnt, "/bin/cat")
	if rec.K8s.Pod != "web-7c9d8-xk2lp" || !rec.Process.IdentityMismatch || !rec.Process.InAgentContainer {
		t.Errorf("in the agent's cgroup: pod %q mismatch %v in agent %v", rec.K8s.Pod, rec.Process.IdentityMismatch, rec.Process.InAgentContainer)
	}

	// E26: into the bystander's cgroup and mount namespace.
	fork(100, 102, web, webMnt)
	rec = exec(102, 100, byCg, byMnt, "/bin/cat")
	if rec.K8s.Pod != "web-7c9d8-xk2lp" || !rec.Process.IdentityMismatch || rec.Process.InAgentContainer {
		t.Errorf("as the bystander: pod %q mismatch %v in agent %v", rec.K8s.Pod, rec.Process.IdentityMismatch, rec.Process.InAgentContainer)
	}
	// Entering the bystander's mount namespace is entering another pod's.
	ns := f.e.Handle(&events.Setns{
		Header:  events.Header{Type: events.TypeSetns, PID: 102, StartTimeNS: 102000, CgroupID: byCg, MntNS: byMnt},
		Changed: []string{"mnt"}, Inum: map[string]uint32{"mnt": byMnt},
	}, time.Now())
	if ns.Namespaces == nil || !reflect.DeepEqual(ns.Namespaces.OtherPod, []string{"mnt"}) {
		t.Errorf("setns into the bystander: %+v", ns.Namespaces)
	}

	// Network and pid namespaces are judged by pod. The pod's sandbox
	// (pause) owns them and belongs to no known container, so it is
	// skipped; entering one's own pod's namespace is not reported.
	const webNet, byNet = 4026540001, 4026540003
	f.tree.Add(proctree.Proc{Key: proctree.Key{PID: 90, StartNS: 1}, Image: "/pause", ContainerID: "pause0000", NetNS: webNet, PidNS: 4026550001})
	f.tree.Add(proctree.Proc{Key: proctree.Key{PID: 91, StartNS: 2}, Image: "/pause", ContainerID: "pause0001", NetNS: byNet})
	for _, x := range []struct {
		pid      uint32
		cg       uint64
		mnt, net uint32
		path     string
	}{{100, web, webMnt, webNet, "/bin/sh"}, {200, byCg, byMnt, byNet, "/bin/sleep"}} {
		f.e.Handle(&events.Exec{
			Header: events.Header{Type: events.TypeExec, PID: x.pid, StartTimeNS: uint64(x.pid) * 1000, PPID: 1, CgroupID: x.cg, MntNS: x.mnt, NetNS: x.net},
			Path:   x.path, Argv: []string{x.path},
		}, time.Now())
	}
	fork(100, 104, web, webMnt)
	setns := func(pid uint32, cg uint64, kind string, inum uint32) []string {
		r := f.e.Handle(&events.Setns{
			Header:  events.Header{Type: events.TypeSetns, PID: pid, StartTimeNS: uint64(pid) * 1000, CgroupID: cg, MntNS: webMnt},
			Changed: []string{kind}, Inum: map[string]uint32{kind: inum},
		}, time.Now())
		return r.Namespaces.OtherPod
	}
	if got := setns(104, web, "net", byNet); !reflect.DeepEqual(got, []string{"net"}) {
		t.Errorf("setns into the bystander's network: %v", got)
	}
	if got := setns(104, web, "net", webNet); got != nil {
		t.Errorf("setns into its own pod's network: %v", got)
	}

	// A process whose birth was not seen, in the bystander's cgroup but
	// the web pod's mount namespace, is named by the mount namespace.
	f.tree.Add(proctree.Proc{Key: proctree.Key{PID: 103, StartNS: 103000}, Parent: proctree.Key{PID: 1}, Image: "/bin/sh", ContainerID: bystanderCID, MntNS: webMnt, Seeded: true})
	rec = exec(103, 1, byCg, webMnt, "/bin/cat")
	if rec.K8s.Pod != "web-7c9d8-xk2lp" || !rec.Process.IdentityMismatch {
		t.Errorf("seeded intruder: pod %q mismatch %v", rec.K8s.Pod, rec.Process.IdentityMismatch)
	}

	// kubectl exec: the runtime hands a process in. Nothing to report.
	f.e.SetRuntimes(fakeRuntimes{{8, 100}: true})
	f.e.Handle(&events.Exec{
		Header: events.Header{Type: events.TypeExec, PID: 300, StartTimeNS: 300000, PPID: 1, CgroupID: f.cgroup("system.slice/containerd.service"), MntNS: 4026531840},
		Path:   "/usr/local/sbin/runc", Dev: 8, Inode: 100, Argv: []string{"runc", "exec"},
	}, time.Now())
	fork(300, 301, byCg, byMnt)
	rec = exec(301, 300, byCg, byMnt, "/bin/sh")
	if rec.K8s.Pod != "bystander" || rec.Process.IdentityMismatch || rec.Process.InAgentContainer {
		t.Errorf("kubectl exec: pod %q mismatch %v in agent %v", rec.K8s.Pod, rec.Process.IdentityMismatch, rec.Process.InAgentContainer)
	}
	// kubectl exec into the agent's own container is marked.
	fork(300, 302, agentCg, agentMnt)
	if rec = exec(302, 300, agentCg, agentMnt, "/bin/sh"); !rec.Process.InAgentContainer || rec.Process.IdentityMismatch {
		t.Errorf("exec into the agent: in agent %v mismatch %v", rec.Process.InAgentContainer, rec.Process.IdentityMismatch)
	}
	// The agent itself is not.
	if rec = exec(7000, 1, agentCg, agentMnt, "/tephrad"); rec.Process.InAgentContainer {
		t.Error("the agent is marked as a stranger in its own container")
	}
}

type fakeCreds map[uint32]credwatch.Credential

func (c fakeCreds) Lookup(dev uint32, _ uint64, path string) (credwatch.Credential, bool) {
	cr, ok := c[dev]
	return cr, ok && !strings.HasSuffix(path, "ca.crt")
}

// A file the pod specs name as a credential is marked, whatever its path,
// and so is a credential that belongs to another pod than the reader's.
func TestCredentialRecord(t *testing.T) {
	f := newFixture(t)
	f.e.SetCredentials(fakeCreds{
		0x200005: {Kind: credwatch.KindSAToken, Namespace: "shop", Pod: "web-7c9d8-xk2lp"},
		0x200006: {Kind: credwatch.KindSAToken, Namespace: "bank", Pod: "payments-0"},
	})
	h := f.webShell("/bin/dd", "dd", "if=/opt/svc/creds")
	h.Type = events.TypeFileOpen
	h.Flags = events.FileByDev
	open := func(dev uint32, path string) *export.File {
		return f.e.Handle(&events.FileOpen{Header: h, Inode: 7, Dev: dev, WatchBits: 1, Path: path}, time.Now()).File
	}
	if got := open(0x200005, "/opt/svc/..2026_11_22_10_00_00.1/creds"); got.K8sCredential != "sa_token" ||
		got.CredentialPod != "shop/web-7c9d8-xk2lp" || got.CredentialOtherPod || got.MatchedBy != "device" {
		t.Errorf("own token: %+v", got)
	}
	if got := open(0x200006, "/hostkubelet/pods/u/volumes/kubernetes.io~projected/t/token"); got.K8sCredential != "sa_token" || !got.CredentialOtherPod {
		t.Errorf("another pod's token: %+v", got)
	}
	if got := open(0x200005, "/opt/svc/ca.crt"); got.K8sCredential != "" || got.CredentialPod != "" {
		t.Errorf("not the token: %+v", got)
	}
	// Matched by path alone: not looked up.
	h.Flags = events.FileByPath
	if got := open(0x200005, "/opt/svc/creds"); got.K8sCredential != "" {
		t.Errorf("matched by path: %+v", got)
	}
}

// E26 after E23: a flood lost the exits of a deleted pod's processes, and a
// new pod got that pod's mount namespace number. The ghost, oldest in the
// number, must not be taken for its owner, and an owner the pod index does
// not know must never turn a known pod into no pod.
func TestGhostNamespaceOwner(t *testing.T) {
	const deadCID = "dead0000000000000000000000000000000000000000000000000000000000dd"
	const deadScope = "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-poddddd0000_1111_2222_3333_444455556666.slice/cri-containerd-" + deadCID + ".scope"
	const reused = 4026530009

	exec := func(f *fixture, pid uint32, cg uint64, path string) *export.Record {
		return f.e.Handle(&events.Exec{
			Header: events.Header{Type: events.TypeExec, PID: pid, StartTimeNS: uint64(pid) * 1000, PPID: 1, CgroupID: cg, MntNS: reused},
			Path:   path, Argv: []string{path},
		}, time.Now())
	}
	setup := func(ghostGone bool) (*fixture, uint64) {
		f := newFixture(t)
		f.dead[50] = ghostGone
		web, _, _ := f.identityPods()
		// The deleted pod's process: its exit was lost, and its pod is no
		// longer in the index.
		exec(f, 50, f.cgroup(deadScope), "/bin/cat")
		// The web pod's first program, in the reused number.
		exec(f, 100, web, "/bin/sh")
		return f, web
	}

	// The ghost is gone from /proc: it is passed over, marked exited and
	// counted, and the web pod's process is named under the web pod.
	f, web := setup(true)
	rec := exec(f, 101, web, "/bin/cat")
	if rec.K8s.Pod != "web-7c9d8-xk2lp" || rec.Process.IdentityMismatch {
		t.Errorf("ghost owner: pod %q namespace %q mismatch %v", rec.K8s.Pod, rec.K8s.Namespace, rec.Process.IdentityMismatch)
	}
	if f.e.Ghosts() != 1 {
		t.Errorf("ghosts: %d, want 1", f.e.Ghosts())
	}
	if p, ok := f.tree.ByPID(50); !ok || p.Exited.IsZero() {
		t.Error("the ghost is still live in the tree")
	}

	// The safety net: even when the stale owner passes the check, a
	// container the pod index does not know never replaces the cgroup's
	// pod.
	f, web = setup(false)
	rec = exec(f, 101, web, "/bin/cat")
	if rec.K8s.Pod != "web-7c9d8-xk2lp" || rec.K8s.Namespace == export.NamespaceUnknown {
		t.Errorf("unknown owner: pod %q namespace %q", rec.K8s.Pod, rec.K8s.Namespace)
	}

	// A sweep after drops finds every ghost at once.
	f, _ = setup(false)
	f.dead[50] = true
	if n, _ := f.e.Sweep(time.Now()); n != 1 || f.e.Ghosts() != 1 {
		t.Errorf("sweep: %d found, %d counted, want 1", n, f.e.Ghosts())
	}
}
