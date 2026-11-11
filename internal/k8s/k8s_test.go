// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	cidA = "3f9c0000000000000000000000000000000000000000000000000000000000aa"
	cidB = "77770000000000000000000000000000000000000000000000000000000000bb"
	uid  = "0a1b2c3d-1111-2222-3333-444455556666"
)

func TestContainerIDAndPodUID(t *testing.T) {
	for _, tc := range []struct {
		name, path, cid, pod string
	}{
		{
			"systemd driver",
			"/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod0a1b2c3d_1111_2222_3333_444455556666.slice/cri-containerd-" + cidA + ".scope",
			cidA, uid,
		},
		{
			// kind: the node is a container, and the kubelet runs
			// under its own slice inside it.
			"kind nesting",
			"/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod0a1b2c3d_1111_2222_3333_444455556666.slice/cri-containerd-" + cidA + ".scope",
			cidA, uid,
		},
		{
			"cgroupfs driver",
			"/kubepods/burstable/pod" + uid + "/" + cidA,
			cidA, uid,
		},
		{
			"cgroup created inside the container",
			"/kubepods/pod" + uid + "/" + cidA + "/init.scope",
			cidA, uid,
		},
		{
			// As /proc/<pid>/cgroup shows it from another cgroup
			// namespace.
			"relative from a sibling namespace",
			"/../../kubepods-besteffort-pod0a1b2c3d_1111_2222_3333_444455556666.slice/cri-containerd-" + cidA + ".scope",
			cidA, uid,
		},
		{"pod level only", "/kubepods/burstable/pod" + uid, "", uid},
		{"host service", "/system.slice/containerd.service", "", ""},
		{"root", "/", "", ""},
		{"empty", "", "", ""},
		{"63 hex digits", "/kubepods/" + cidA[:63], "", ""},
		{"docker, not supported", "/system.slice/docker-" + cidA + ".scope", "", ""},
		{"ID embedded in a longer name", "/x/prefix-" + cidA + "-suffix", "", ""},
	} {
		if got := ContainerID(tc.path); got != tc.cid {
			t.Errorf("%s: ContainerID = %q, want %q", tc.name, got, tc.cid)
		}
		if got := PodUID(tc.path); got != tc.pod {
			t.Errorf("%s: PodUID = %q, want %q", tc.name, got, tc.pod)
		}
	}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Sys().(*syscall.Stat_t).Ino
}

func TestCgroupResolver(t *testing.T) {
	root := t.TempDir()
	scope := filepath.Join(root, "kubepods.slice", "cri-containerd-"+cidA+".scope")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	// Files are not cgroups.
	if err := os.WriteFile(filepath.Join(scope, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	r := NewCgroupResolver(root)
	r.minRescan = time.Hour

	if p, ok := r.Path(inode(t, scope)); !ok || p != "/kubepods.slice/cri-containerd-"+cidA+".scope" {
		t.Errorf("Path(scope) = %q, %v", p, ok)
	}
	if p, ok := r.Path(inode(t, root)); !ok || p != "/" {
		t.Errorf("Path(root) = %q, %v; want /", p, ok)
	}
	if _, ok := r.Path(inode(t, filepath.Join(scope, "cgroup.procs"))); ok {
		t.Error("a regular file resolved as a cgroup")
	}

	// A cgroup created after the scan is not found while rescans are
	// rate-limited, and is found once they are allowed again.
	late := filepath.Join(root, "late.scope")
	if err := os.Mkdir(late, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Path(inode(t, late)); ok {
		t.Error("rescan was not rate-limited")
	}
	before := r.Scans()
	r.minRescan = 0
	if p, ok := r.Path(inode(t, late)); !ok || p != "/late.scope" {
		t.Errorf("Path(late) = %q, %v", p, ok)
	}
	if r.Scans() != before+1 {
		t.Errorf("scans went from %d to %d, want one more", before, r.Scans())
	}

	// A removed cgroup drops out at the next scan.
	gone := inode(t, late)
	if err := os.Remove(late); err != nil {
		t.Fatal(err)
	}
	r.Path(1 << 60) // unknown ID forces a rescan
	if _, ok := r.Path(gone); ok {
		t.Error("removed cgroup still resolves")
	}
}

func pod(name string, statuses ...corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "shop", UID: types.UID(uid),
			Labels: map[string]string{"app": "web"},
		},
		Status: corev1.PodStatus{ContainerStatuses: statuses},
	}
}

func TestPodIndex(t *testing.T) {
	x := NewPodIndex()

	// Pod scheduled, container not started yet: only the UID resolves.
	x.Update(pod("web-1", corev1.ContainerStatus{Name: "web", Image: "nginx:1.27"}))
	if _, ok := x.Lookup(cidA, ""); ok {
		t.Error("container resolved before it had an ID")
	}
	a, ok := x.Lookup(cidA, uid)
	if !ok || a.Pod != "web-1" || a.Namespace != "shop" || a.ContainerID != cidA || a.Complete() {
		t.Errorf("UID fallback = %+v, %v", a, ok)
	}

	x.Update(pod("web-1", corev1.ContainerStatus{Name: "web", Image: "nginx:1.27", ContainerID: "containerd://" + cidA}))
	a, ok = x.Lookup(cidA, "")
	if !ok || !a.Complete() || a.ContainerName != "web" || a.Image != "nginx:1.27" || a.Labels["app"] != "web" {
		t.Errorf("container lookup = %+v, %v", a, ok)
	}

	// Restart: new ID, and the old one still resolves for late events.
	x.Update(pod("web-1", corev1.ContainerStatus{Name: "web", Image: "nginx:1.27", ContainerID: "containerd://" + cidB}))
	for _, id := range []string{cidA, cidB} {
		if a, ok := x.Lookup(id, ""); !ok || a.ContainerName != "web" {
			t.Errorf("after restart, %s = %+v, %v", id[:4], a, ok)
		}
	}

	// Deleted pods linger, then go, with all their containers.
	t0 := time.Unix(1000, 0)
	x.Delete(pod("web-1"), t0)
	x.Purge(t0.Add(podLinger - time.Second))
	if _, ok := x.Lookup(cidB, ""); !ok {
		t.Error("deleted pod purged before the linger period")
	}
	x.Purge(t0.Add(podLinger + time.Second))
	if _, ok := x.Lookup(cidA, uid); ok || x.Len() != 0 {
		t.Error("deleted pod still resolves after the linger period")
	}
	if _, ok := x.Lookup(cidB, ""); ok {
		t.Error("restarted container ID survived the purge")
	}
}

// A pod that is deleted and comes back before the purge must not be purged.
func TestPodIndexUpdateAfterDelete(t *testing.T) {
	x := NewPodIndex()
	p := pod("web-1", corev1.ContainerStatus{Name: "web", ContainerID: "containerd://" + cidA})
	x.Update(p)
	x.Delete(p, time.Unix(1000, 0))
	x.Update(p)
	x.Purge(time.Unix(1000, 0).Add(time.Hour))
	if _, ok := x.Lookup(cidA, ""); !ok {
		t.Error("pod purged although it was updated after the delete")
	}
}

func TestInitAndEphemeralContainersIndexed(t *testing.T) {
	x := NewPodIndex()
	p := pod("web-1")
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ContainerID: "containerd://" + cidA}}
	p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "debug", ContainerID: "containerd://" + cidB}}
	x.Update(p)
	if a, ok := x.Lookup(cidA, ""); !ok || a.ContainerName != "init" {
		t.Errorf("init container = %+v, %v", a, ok)
	}
	if a, ok := x.Lookup(cidB, ""); !ok || a.ContainerName != "debug" {
		t.Errorf("ephemeral container = %+v, %v", a, ok)
	}
}
