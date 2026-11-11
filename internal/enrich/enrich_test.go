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

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/proctree"
)

const (
	cid    = "3f9c0000000000000000000000000000000000000000000000000000000000aa"
	podUID = "0a1b2c3d-1111-2222-3333-444455556666"
	tick   = 10_000_000
)

type fixture struct {
	t       *testing.T
	proc    string
	cgroups string
	tree    *proctree.Tree
	pods    *k8s.PodIndex
	e       *Enricher
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{
		t:       t,
		proc:    t.TempDir(),
		cgroups: t.TempDir(),
		tree:    proctree.New(0, 0),
		pods:    k8s.NewPodIndex(),
	}
	f.e = New("kind-worker", f.tree, proctree.ProcFS{Root: f.proc}, k8s.NewCgroupResolver(f.cgroups), f.pods)
	f.e.boot = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
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
			Exec: &export.Exec{StdinIsSocket: true, StdoutIsSocket: true, Inode: 77},
		},
		Parent:    &export.Parent{PID: 48190, Image: "/usr/sbin/nginx", CommandLine: "nginx: worker process"},
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
		`"parent":{"pid":48190,"Image":"/usr/sbin/nginx","CommandLine":"nginx: worker process"}`,
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

func toJSON(t *testing.T, r *export.Record) string {
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
	open := func(flags uint32, inode uint64, at uint64) *export.Record {
		h := h
		h.Flags = flags
		h.TSBootNS = at
		return f.e.Handle(&events.FileOpen{Header: h, Inode: inode, Path: "/etc/shadow"}, time.Now())
	}
	kernel := uint32(events.FileByPath | events.FileKernelCreds)

	if open(events.FileByInode, 9, 1_000_000_000) == nil {
		t.Fatal("the process's own open was dropped")
	}
	if open(kernel, 9, 1_000_009_000) != nil {
		t.Error("the backing-file open that followed it was reported again")
	}
	// Everything else under substituted credentials is kept: another
	// file, a later time, a thread with no open reported.
	if open(kernel, 10, 1_000_010_000) == nil {
		t.Error("an open of another inode was dropped")
	}
	if open(kernel, 9, 1_500_000_000) == nil {
		t.Error("an open long after the first was dropped")
	}
	h.TID = 48301
	if open(kernel, 9, 1_000_009_000) == nil {
		t.Error("an open in another thread was dropped")
	}
	if f.e.NestedOpens() != 1 {
		t.Errorf("nested opens = %d, want 1", f.e.NestedOpens())
	}
}
