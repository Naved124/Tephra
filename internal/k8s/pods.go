// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// podLinger is how long a deleted pod stays resolvable, as long as a removed
// cgroup does: the last events of a container arrive after its pod is gone,
// and an agent catching up on a backlog or after a flood handles them later
// still.
const podLinger = 5 * time.Minute

type podEntry struct {
	uid        string
	namespace  string
	name       string
	labels     map[string]string
	containers []string // container IDs indexed for this pod
	// tokens are the service account tokens mounted in each container,
	// by container ID.
	tokens  map[string][]TokenMount
	deleted time.Time
}

// TokenMount is a service account token projected into a container, as the
// pod spec says.
type TokenMount struct {
	ContainerID string
	Namespace   string
	Pod         string
	// Path is where the container sees the token.
	Path string
	// Rel is the token's path inside its volume, as the projection names
	// it ("token" for the automounted one).
	Rel string
}

// PodIndex maps container IDs and pod UIDs to pods on this node.
type PodIndex struct {
	mu          sync.Mutex
	pods        map[string]*podEntry    // by pod UID
	byContainer map[string]*Attribution // by container ID
	// changed is signalled, without blocking, when a pod changes.
	changed chan struct{}
}

// NewPodIndex returns an empty index.
func NewPodIndex() *PodIndex {
	return &PodIndex{
		pods:        make(map[string]*podEntry),
		byContainer: make(map[string]*Attribution),
		changed:     make(chan struct{}, 1),
	}
}

// Changed is signalled when a pod was added or changed since the last
// signal.
func (x *PodIndex) Changed() <-chan struct{} { return x.changed }

// Tokens lists the service account tokens mounted in the containers of the
// pods that have not been deleted.
func (x *PodIndex) Tokens() []TokenMount {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []TokenMount
	for _, e := range x.pods {
		if !e.deleted.IsZero() {
			continue
		}
		for _, ts := range e.tokens {
			out = append(out, ts...)
		}
	}
	return out
}

// tokenMounts finds the service account tokens a pod's spec projects into
// each of its containers, by container name: every serviceAccountToken
// source of a projected volume, at every place a container mounts it.
func tokenMounts(pod *corev1.Pod) map[string][]TokenMount {
	vols := map[string][]string{} // volume name to token paths in it
	for _, v := range pod.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, src := range v.Projected.Sources {
			if src.ServiceAccountToken != nil && src.ServiceAccountToken.Path != "" {
				vols[v.Name] = append(vols[v.Name], path.Clean(src.ServiceAccountToken.Path))
			}
		}
	}
	if len(vols) == 0 {
		return nil
	}
	out := map[string][]TokenMount{}
	add := func(name string, mounts []corev1.VolumeMount) {
		for _, m := range mounts {
			for _, rel := range vols[m.Name] {
				p := path.Join(m.MountPath, rel)
				if sub := path.Clean(m.SubPath); m.SubPath != "" {
					// Only the subpath is mounted, at the mount path.
					switch {
					case sub == rel:
						p = m.MountPath
					case strings.HasPrefix(rel, sub+"/"):
						p = path.Join(m.MountPath, strings.TrimPrefix(rel, sub+"/"))
					default:
						continue
					}
				}
				out[name] = append(out[name], TokenMount{Namespace: pod.Namespace, Pod: pod.Name, Path: p, Rel: rel})
			}
		}
	}
	for _, c := range pod.Spec.InitContainers {
		add(c.Name, c.VolumeMounts)
	}
	for _, c := range pod.Spec.Containers {
		add(c.Name, c.VolumeMounts)
	}
	for _, c := range pod.Spec.EphemeralContainers {
		add(c.Name, c.VolumeMounts)
	}
	return out
}

// Update records the current state of a pod.
func (x *PodIndex) Update(pod *corev1.Pod) {
	x.mu.Lock()
	defer x.mu.Unlock()

	uid := string(pod.UID)
	e := x.pods[uid]
	if e == nil {
		e = &podEntry{uid: uid}
		x.pods[uid] = e
	}
	e.namespace = pod.Namespace
	e.name = pod.Name
	e.labels = pod.Labels
	e.deleted = time.Time{}
	byName := tokenMounts(pod)
	e.tokens = map[string][]TokenMount{}
	defer func() {
		select {
		case x.changed <- struct{}{}:
		default:
		}
	}()

	// A restarted container gets a new ID. Old IDs stay until the pod is
	// purged, because the old container's last events can still arrive.
	for _, statuses := range [][]corev1.ContainerStatus{
		pod.Status.InitContainerStatuses,
		pod.Status.ContainerStatuses,
		pod.Status.EphemeralContainerStatuses,
	} {
		for i := range statuses {
			cs := &statuses[i]
			id := trimRuntime(cs.ContainerID)
			if id == "" {
				continue
			}
			if _, known := x.byContainer[id]; !known {
				e.containers = append(e.containers, id)
			}
			// The running container: a restarted one's old ID is not
			// resolved again.
			if cs.State.Running != nil || cs.State.Waiting == nil && cs.State.Terminated == nil {
				for _, t := range byName[cs.Name] {
					t.ContainerID = id
					e.tokens[id] = append(e.tokens[id], t)
				}
			}
			x.byContainer[id] = &Attribution{
				ContainerID:   id,
				ContainerName: cs.Name,
				Image:         cs.Image,
				Namespace:     pod.Namespace,
				Pod:           pod.Name,
				Labels:        pod.Labels,
			}
		}
	}
}

// PodInfo is what enforcement needs to know of a pod.
type PodInfo struct {
	UID       string
	Namespace string
	Labels    map[string]string
}

// Pods lists the pods on this node that have not been deleted.
func (x *PodIndex) Pods() []PodInfo {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := make([]PodInfo, 0, len(x.pods))
	for _, e := range x.pods {
		if e.deleted.IsZero() {
			out = append(out, PodInfo{UID: e.uid, Namespace: e.namespace, Labels: e.labels})
		}
	}
	return out
}

// Delete marks a pod as gone. It is purged after the linger period.
func (x *PodIndex) Delete(pod *corev1.Pod, now time.Time) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e := x.pods[string(pod.UID)]; e != nil {
		e.deleted = now
	}
}

// Purge drops pods deleted more than the linger period ago.
func (x *PodIndex) Purge(now time.Time) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for uid, e := range x.pods {
		if e.deleted.IsZero() || now.Sub(e.deleted) < podLinger {
			continue
		}
		for _, id := range e.containers {
			delete(x.byContainer, id)
		}
		delete(x.pods, uid)
	}
}

// Lookup resolves a container. When the container's status has not reached
// the API server yet, which is normal for the first moments of a container,
// it falls back to the pod UID from the cgroup path and returns an
// attribution without container name and image.
func (x *PodIndex) Lookup(containerID, podUID string) (*Attribution, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()

	if a, ok := x.byContainer[containerID]; ok {
		return a, true
	}
	if e, ok := x.pods[podUID]; ok {
		return &Attribution{
			ContainerID: containerID,
			Namespace:   e.namespace,
			Pod:         e.name,
			Labels:      e.labels,
		}, true
	}
	return nil, false
}

// Len is the number of pods known.
func (x *PodIndex) Len() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.pods)
}

// trimRuntime turns "containerd://<id>" into "<id>".
func trimRuntime(id string) string {
	if _, rest, ok := strings.Cut(id, "://"); ok {
		return rest
	}
	return id
}

// ErrNotInCluster means the agent is not running in a pod.
var ErrNotInCluster = rest.ErrNotInCluster

// WatchPods starts a read-only pod informer scoped to one node and keeps the
// index in step with it. It returns once the first list has been applied, so
// the index is complete before events are attributed.
func WatchPods(ctx context.Context, node string, x *PodIndex) error {
	if node == "" {
		return errors.New("node name is empty; set NODE_NAME")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	factory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", node).String()
		}))
	informer := factory.Core().V1().Pods().Informer()
	reg, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if pod, ok := obj.(*corev1.Pod); ok {
				x.Update(pod)
			}
		},
		UpdateFunc: func(_, obj any) {
			if pod, ok := obj.(*corev1.Pod); ok {
				x.Update(pod)
			}
		},
		DeleteFunc: func(obj any) {
			if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tomb.Obj
			}
			if pod, ok := obj.(*corev1.Pod); ok {
				x.Delete(pod, time.Now())
			}
		},
	})
	if err != nil {
		return fmt.Errorf("pod informer handler: %w", err)
	}

	factory.Start(ctx.Done())
	syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// The registration's HasSynced also covers delivery of the initial
	// list to the handler above, not just the informer's own store.
	if !cache.WaitForCacheSync(syncCtx.Done(), reg.HasSynced) {
		return errors.New("pod informer did not sync within 30s; check the agent's RBAC")
	}

	go func() {
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				x.Purge(now)
			}
		}
	}()
	return nil
}
