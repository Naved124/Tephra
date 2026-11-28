// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// DaemonSetRemoving reports whether the agent's DaemonSet is gone or being
// deleted, which is how an uninstall looks from one of its pods. A rollout,
// a deleted pod or a drained node leaves the DaemonSet in place, and another
// agent follows on the node. An uninstall also deletes the agent's Role and
// service account in the same pass, often before its pods get to ask, so an
// answer that the agent may no longer read its own DaemonSet (forbidden,
// unauthorized) counts as one too: only taking the release down, or someone
// with the power to, takes that away. An error means it could not tell.
func DaemonSetRemoving(ctx context.Context, namespace, name string) (bool, error) {
	if name == "" {
		return false, fmt.Errorf("the agent's DaemonSet name is not set")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return false, err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("kubernetes client: %w", err)
	}
	return daemonSetRemoving(ctx, client, namespace, name)
}

func daemonSetRemoving(ctx context.Context, client kubernetes.Interface, namespace, name string) (bool, error) {
	ds, err := client.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err), apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return true, nil
	case err != nil:
		return false, err
	}
	return ds.DeletionTimestamp != nil, nil
}
