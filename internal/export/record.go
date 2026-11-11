// SPDX-License-Identifier: Apache-2.0

// Package export defines the enriched event as it leaves the agent and the
// sinks that carry it.
package export

// Record is one enriched event. Field names follow Sigma conventions where
// one exists (Image, CommandLine, User).
type Record struct {
	TS        string     `json:"ts"`
	Type      string     `json:"type"`
	Node      string     `json:"node"`
	Process   Process    `json:"process"`
	Parent    *Parent    `json:"parent,omitempty"`
	Ancestors []string   `json:"ancestors,omitempty"`
	Container *Container `json:"container,omitempty"`
	K8s       K8s        `json:"k8s"`
	Exit      *Exit      `json:"exit,omitempty"`
}

// Process is the subject of the event. For a fork it is the new child.
type Process struct {
	PID         uint32 `json:"pid"`
	StartTimeNS uint64 `json:"start_time_ns"`
	Image       string `json:"Image"`
	CommandLine string `json:"CommandLine"`
	User        string `json:"User,omitempty"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	CgroupID    uint64 `json:"cgroup_id"`
	// Exec is set on exec events only; its fields appear inline.
	*Exec
}

// Exec holds what only an exec event knows.
type Exec struct {
	StdinIsSocket  bool   `json:"stdin_is_socket"`
	StdoutIsSocket bool   `json:"stdout_is_socket"`
	Unlinked       bool   `json:"unlinked"`
	Setuid         bool   `json:"setuid"`
	ArgvTruncated  bool   `json:"argv_truncated"`
	Inode          uint64 `json:"inode"`
	Dev            uint32 `json:"dev"`
	CapEffective   uint64 `json:"cap_effective"`
}

// Parent is the process's parent as the process tree knows it.
type Parent struct {
	PID         uint32 `json:"pid"`
	Image       string `json:"Image"`
	CommandLine string `json:"CommandLine"`
}

// Container is absent for host processes.
type Container struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Image string `json:"image,omitempty"`
}

// Namespace values for processes that are not in a pod.
const (
	// NamespaceHost labels a process whose cgroup is not a container's.
	NamespaceHost = "host"
	// NamespaceUnknown labels a process whose cgroup could not be
	// resolved, or whose container is not known to Kubernetes.
	NamespaceUnknown = "unknown"
)

// K8s places the process in the cluster.
type K8s struct {
	Namespace string            `json:"namespace"`
	Pod       string            `json:"pod,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Exit is set on exit events only.
type Exit struct {
	Code   uint32 `json:"code"`
	Signal uint32 `json:"signal"`
}
