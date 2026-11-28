// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// A planned stop is an uninstall only when the DaemonSet is gone or being
// deleted; a rollout or a deleted pod leaves it in place. When the API cannot
// be asked, the answer is an error, never "removing": the caller keeps the
// kernel recording rather than leave a gap.
func TestDaemonSetRemoving(t *testing.T) {
	ctx := context.Background()
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "tephra", Name: "tephra-agent"}}

	removing, err := daemonSetRemoving(ctx, fake.NewClientset(ds), "tephra", "tephra-agent")
	if err != nil || removing {
		t.Errorf("DaemonSet in place: removing %v, err %v; want false, nil", removing, err)
	}

	removing, err = daemonSetRemoving(ctx, fake.NewClientset(), "tephra", "tephra-agent")
	if err != nil || !removing {
		t.Errorf("DaemonSet gone: removing %v, err %v; want true, nil", removing, err)
	}

	gone := ds.DeepCopy()
	now := metav1.Now()
	gone.DeletionTimestamp = &now
	gone.Finalizers = []string{"foregroundDeletion"}
	removing, err = daemonSetRemoving(ctx, fake.NewClientset(gone), "tephra", "tephra-agent")
	if err != nil || !removing {
		t.Errorf("DaemonSet being deleted: removing %v, err %v; want true, nil", removing, err)
	}

	for _, deny := range []error{
		apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "daemonsets"}, "tephra-agent", errors.New("role deleted")),
		apierrors.NewUnauthorized("service account deleted"),
	} {
		revoked := fake.NewClientset(ds)
		revoked.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, deny
		})
		removing, err = daemonSetRemoving(ctx, revoked, "tephra", "tephra-agent")
		if err != nil || !removing {
			t.Errorf("access revoked (%v): removing %v, err %v; want true, nil", deny, removing, err)
		}
	}

	broken := fake.NewClientset(ds)
	broken.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	removing, err = daemonSetRemoving(ctx, broken, "tephra", "tephra-agent")
	if err == nil || removing {
		t.Errorf("API unreachable: removing %v, err %v; want false and an error", removing, err)
	}

	if _, err := DaemonSetRemoving(ctx, "tephra", ""); err == nil {
		t.Error("no DaemonSet name: want an error")
	}
}
