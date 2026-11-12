// SPDX-License-Identifier: Apache-2.0

// Package export defines the enriched event as it leaves the agent and the
// sinks that carry it.
package export

import "sort"

// Record is one enriched event. Field names follow Sigma conventions where
// one exists (Image, CommandLine, User).
type Record struct {
	TS   string `json:"ts"`
	Type string `json:"type"`
	Node string `json:"node"`
	// Rule is set on alerts only. An alert is the event that matched,
	// with the rule in front.
	Rule      *Rule      `json:"rule,omitempty"`
	Process   Process    `json:"process"`
	Parent    *Parent    `json:"parent,omitempty"`
	Ancestors []string   `json:"ancestors,omitempty"`
	Container *Container `json:"container,omitempty"`
	K8s       K8s        `json:"k8s"`
	Exit      *Exit      `json:"exit,omitempty"`
	Network   *Network   `json:"network,omitempty"`
	File      *File      `json:"file,omitempty"`
	// One of the following is set on the event type of the same name.
	Ptrace     *Ptrace     `json:"ptrace,omitempty"`
	Memfd      *Memfd      `json:"memfd,omitempty"`
	Module     *Module     `json:"module,omitempty"`
	BPF        *BPF        `json:"bpf,omitempty"`
	Cred       *Cred       `json:"cred,omitempty"`
	Mount      *Mount      `json:"mount,omitempty"`
	Namespaces *Namespaces `json:"namespaces,omitempty"`
	// Health is set on records of type TypeHealth only. They go to the
	// collector and are not printed on stdout.
	Health map[string]uint64 `json:"health,omitempty"`
}

// TypeHealth is the type of the periodic record that carries a sender's own
// counters.
const TypeHealth = "health"

// IsAlert reports whether the record is an alert rather than a raw event.
func (r *Record) IsAlert() bool { return r.Rule != nil }

// Rule identifies the detection rule behind an alert.
type Rule struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Level string   `json:"level"`
	Tags  []string `json:"tags,omitempty"`
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
	// IsMainBinary says the process runs the same binary as its
	// container's first process. Always false outside a container.
	IsMainBinary bool `json:"is_main_binary,omitempty"`
	// Runtime says the process runs one of the node's container runtime
	// binaries, recognised by the identity of the file and not by its
	// name.
	Runtime bool `json:"runtime,omitempty"`
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
	// Env holds only the dynamic loader variables the kernel side
	// captures (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH). The rest of the
	// environment never leaves the kernel.
	Env map[string]string `json:"env,omitempty"`
	// EnvTruncated says the environment was too long to scan to its end,
	// so a variable may have been missed.
	EnvTruncated bool `json:"env_truncated"`
}

// EnvNames lists the captured variable names, sorted.
func (e *Exec) EnvNames() []string {
	if e == nil || len(e.Env) == 0 {
		return nil
	}
	names := make([]string, 0, len(e.Env))
	for k := range e.Env {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Network is set on connect and accept events. Source is the side that
// opened the connection: the process itself on connect, the peer on accept.
type Network struct {
	// Direction is "outbound" for connect and "inbound" for accept.
	Direction string `json:"direction"`
	// Family is "ipv4", "ipv6" or "unix".
	Family          string `json:"family"`
	Protocol        string `json:"protocol,omitempty"`
	SourceIP        string `json:"SourceIp,omitempty"`
	SourcePort      uint16 `json:"SourcePort,omitempty"`
	DestinationIP   string `json:"DestinationIp,omitempty"`
	DestinationPort uint16 `json:"DestinationPort,omitempty"`
	// UnixPath is the address of a Unix socket; an abstract one starts
	// with "@".
	UnixPath string `json:"unix_path,omitempty"`
	// IsK8sAPI says the destination is the cluster's API server.
	IsK8sAPI bool `json:"is_k8s_api,omitempty"`
}

// File is set on file_open, file_change and file_denied events.
type File struct {
	// Path is as the opening process sees it, relative to its own root.
	Path string `json:"path"`
	// Target is set when the file was recognised by identity and not by
	// the path used: it is the watched path of the same file. A hard link
	// to /etc/shadow has the link's name in Path and /etc/shadow here.
	Target string `json:"target,omitempty"`
	// Flags are the open(2) flags.
	Flags    uint32 `json:"flags"`
	Write    bool   `json:"write"`
	Truncate bool   `json:"truncate"`
	Inode    uint64 `json:"inode"`
	Dev      uint32 `json:"dev"`
	// MatchedBy is the kernel filter that let the event through: "path",
	// "name" or "inode".
	MatchedBy string `json:"matched_by"`
	// Op is set on file_change: what was done to the name (unlink,
	// rename_from, rename_to, link, symlink, truncate).
	Op string `json:"op,omitempty"`
	// Error is set on file_denied: why the kernel refused the open
	// (EACCES, EPERM or EROFS).
	Error string `json:"error,omitempty"`
}

// Parent is the process's parent as the process tree knows it.
type Parent struct {
	PID         uint32 `json:"pid"`
	Image       string `json:"Image"`
	CommandLine string `json:"CommandLine"`
	Runtime     bool   `json:"runtime,omitempty"`
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

// Ptrace is set on ptrace events: the process asked for attach-level access
// to the target.
type Ptrace struct {
	TargetPID         uint32 `json:"target_pid"`
	TargetImage       string `json:"target_image,omitempty"`
	TargetCommandLine string `json:"target_command_line,omitempty"`
	Mode              uint32 `json:"mode"`
}

// Memfd is set on memfd events.
type Memfd struct {
	Flags uint32 `json:"flags"`
}

// Module is set on module_load events.
type Module struct {
	Name string `json:"name"`
}

// BPF is set on bpf_load events.
type BPF struct {
	ProgType uint32 `json:"prog_type"`
	Name     string `json:"name,omitempty"`
}

// Cred is set on cred_change events.
type Cred struct {
	OldUID  uint32 `json:"old_uid"`
	NewUID  uint32 `json:"new_uid"`
	OldEUID uint32 `json:"old_euid"`
	NewEUID uint32 `json:"new_euid"`
	OldGID  uint32 `json:"old_gid"`
	NewGID  uint32 `json:"new_gid"`
	// InExec says the change was made by an exec, which is how a setuid
	// binary gains its owner's identity.
	InExec bool `json:"in_exec"`
	// CapsGained says the process has effective capabilities it did not
	// have before.
	CapsGained      bool   `json:"caps_gained"`
	OldCapEffective uint64 `json:"old_cap_effective"`
	NewCapEffective uint64 `json:"new_cap_effective"`
}

// Mount is set on mount events.
type Mount struct {
	// FSType is empty for a bind mount or a remount.
	FSType string `json:"fstype,omitempty"`
	Flags  uint64 `json:"flags"`
	// Target is the mount point within the filesystem it is on, with
	// ".../" in front when its upper directories were not captured.
	Target string `json:"target"`
}

// Namespaces is set on setns events, which cover setns and unshare.
type Namespaces struct {
	// Changed lists the kinds of namespace the process switched: mnt,
	// pid, net, uts, ipc, cgroup, time.
	Changed []string `json:"changed"`
	// Host lists those of them that are now the node's own namespace.
	Host []string `json:"host,omitempty"`
}
