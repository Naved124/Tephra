// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
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

// podLinger is how long a deleted pod stays resolvable, matching the process
// tree: the last events of a container arrive after its pod is gone.
const podLinger = 60 * time.Second

type podEntry struct {
	uid        string
	namespace  string
	name       string
	labels     map[string]string
	containers []string // container IDs indexed for this pod
	deleted    time.Time
}

// PodIndex maps container IDs and pod UIDs to pods on this node.
type PodIndex struct {
	mu          sync.Mutex
	pods        map[string]*podEntry    // by pod UID
	byContainer map[string]*Attribution // by container ID
}

// NewPodIndex returns an empty index.
func NewPodIndex() *PodIndex {
	return &PodIndex{
		pods:        make(map[string]*podEntry),
		byContainer: make(map[string]*Attribution),
	}
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
