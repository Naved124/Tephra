/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TEPHRA_COMMON_H
#define TEPHRA_COMMON_H

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define PATH_LEN      256
#define ARGV_LEN      1024

#define S_IFMT	 00170000
#define S_IFSOCK 0140000
#define S_ISUID	 0004000

/* Event types. The value is the index into the stats map, the bit position in
 * tephra_cfg.enabled and the type field of the event header. Values are part
 * of the kernel/agent contract: append only, never renumber. */
enum event_type {
	EVENT_EXEC = 1,
	EVENT_FORK = 2,
	EVENT_EXIT = 3,
	EVENT_TYPE_MAX = 32,
};

/* Every record in the ring buffer starts with this header. The layout is
 * mirrored in internal/events and checked against BTF by a unit test. */
struct event_hdr {
	__u64 ts_boot_ns;    /* bpf_ktime_get_boot_ns() */
	__u64 start_time_ns; /* (pid, start_time_ns) is the process key */
	__u64 cgroup_id;     /* cgroup v2 ID of the current task */
	__u32 type;	     /* enum event_type */
	__u32 size;	     /* total record size in bytes */
	__u32 pid;	     /* tgid in the node's pid namespace */
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 pid_ns; /* inode number of the pid namespace */
	__u32 mnt_ns; /* inode number of the mount namespace */
	__u32 flags;  /* per-type flag bits */
	char comm[TASK_COMM_LEN];
};

#define EXEC_F_STDIN_SOCK  (1U << 0)
#define EXEC_F_STDOUT_SOCK (1U << 1)
#define EXEC_F_UNLINKED	   (1U << 2) /* binary has no link on disk */
#define EXEC_F_SETUID	   (1U << 3) /* binary has the setuid bit */
#define EXEC_F_ARGV_TRUNC  (1U << 4)

struct exec_event {
	struct event_hdr h;
	__u64 inode;
	__u32 dev;
	__u32 argv_len; /* bytes used in argv, NUL-separated */
	__u64 cap_effective;
	char path[PATH_LEN];
	char argv[ARGV_LEN]; /* only argv_len bytes are sent */
};

/* The header describes the task that called fork. */
struct fork_event {
	struct event_hdr h;
	__u32 child_pid;
	__u32
	    parent_pid; /* the child's real parent; differs with CLONE_PARENT */
	__u64 child_start_time_ns;
	__u64 parent_start_time_ns;
};

struct exit_event {
	struct event_hdr h;
	__u32 exit_code; /* wait status: code << 8 | signal */
	__u32 _pad;
};

/* Written by the agent before the programs attach. */
struct tephra_cfg {
	__u64 enabled;	   /* bit (1 << event_type) per enabled event */
	__u32 pidns_level; /* depth of the node's pid namespace; 0 = root */
	__u32 pidns_inum;  /* its inode number */
};

/* Filled by the tephra_self program, which the agent runs once in its own
 * context to learn where it sits. */
struct self_info {
	__u64 cgroup_id;
	__u32 pidns_level;
	__u32 pidns_inum;
};

struct stats_val {
	__u64 seen;
	__u64 filtered;
	__u64 emitted;
	__u64 dropped;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024); /* resized by the agent */
} events SEC(".maps");

/* Events larger than the 512-byte BPF stack are built here. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_event);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tephra_cfg);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct self_info);
} self SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EVENT_TYPE_MAX);
	__type(key, __u32);
	__type(value, struct stats_val);
} stats SEC(".maps");

/* cgroups whose events are never emitted: the agent itself, and later other
 * trusted cgroups. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} cgroup_ignore SEC(".maps");

static __always_inline struct stats_val *stats_get(__u32 type)
{
	return bpf_map_lookup_elem(&stats, &type);
}

static __always_inline struct tephra_cfg *cfg_get(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&cfg, &zero);
}

static __always_inline bool event_enabled(const struct tephra_cfg *c,
					  __u32 type)
{
	return c->enabled & (1ULL << type);
}

static __always_inline bool cgroup_ignored(__u64 cgroup_id)
{
	return bpf_map_lookup_elem(&cgroup_ignore, &cgroup_id) != NULL;
}

/* Reads the number @pid has at @level of the pid namespace hierarchy, and the
 * inode number of the namespace at that level. Fails if @pid does not exist
 * that deep, which means it lives in an ancestor namespace. */
static __always_inline int pid_at_level(struct pid *pid, __u32 level, __u32 *nr,
					__u32 *ns_inum)
{
	struct pid_namespace *ns = NULL;
	void *upid;

	if (!pid || BPF_CORE_READ(pid, level) < level)
		return -1;

	/* numbers[] is a flexible array; index it by hand. */
	upid = (void *)pid + bpf_core_field_offset(struct pid, numbers) +
	       (__u64)level * bpf_core_type_size(struct upid);
	if (bpf_probe_read_kernel(
		nr, sizeof(*nr), upid + bpf_core_field_offset(struct upid, nr)))
		return -1;
	if (bpf_probe_read_kernel(
		&ns, sizeof(ns), upid + bpf_core_field_offset(struct upid, ns)))
		return -1;
	*ns_inum = BPF_CORE_READ(ns, ns.inum);
	return 0;
}

/* Translates @pid into the node's pid namespace. Returns false for a task
 * outside it. On a real node the namespace is the root one and every task
 * matches; in kind each node is a container, and this is what keeps one
 * node's agent from reporting its neighbours' processes. */
static __always_inline bool node_pid(const struct tephra_cfg *c,
				     struct pid *pid, __u32 *nr)
{
	__u32 inum = 0;

	if (pid_at_level(pid, c->pidns_level, nr, &inum))
		return false;
	return inum == c->pidns_inum;
}

/* Fills the header from the current task. Returns false if the task is not
 * part of this node. The caller sets h->size and h->flags. */
static __always_inline bool fill_hdr(struct event_hdr *h,
				     const struct tephra_cfg *c, __u32 type)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	__u64 uid_gid = bpf_get_current_uid_gid();

	if (!node_pid(c, BPF_CORE_READ(leader, thread_pid), &h->pid))
		return false;
	if (!node_pid(c, BPF_CORE_READ(task, thread_pid), &h->tid))
		h->tid = 0;
	/* A parent outside the node's namespace is reported as 0. */
	if (!node_pid(
		c, BPF_CORE_READ(task, real_parent, group_leader, thread_pid),
		&h->ppid))
		h->ppid = 0;

	h->ts_boot_ns = bpf_ktime_get_boot_ns();
	h->start_time_ns = BPF_CORE_READ(leader, start_boottime);
	h->cgroup_id = bpf_get_current_cgroup_id();
	h->type = type;
	h->size = 0;
	h->uid = (__u32)uid_gid;
	h->gid = uid_gid >> 32;
	h->pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
	h->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	h->flags = 0;
	bpf_get_current_comm(h->comm, sizeof(h->comm));
	return true;
}

#endif /* TEPHRA_COMMON_H */
