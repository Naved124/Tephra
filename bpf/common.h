/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TEPHRA_COMMON_H
#define TEPHRA_COMMON_H

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN  16
#define PATH_LEN       256
#define ARGV_LEN       1024
#define ENV_VAR_LEN    256 /* longest captured variable, name included */
#define ENV_SLOTS      3   /* one per allowlisted name */
#define ENV_LEN	       (ENV_SLOTS * ENV_VAR_LEN)
#define ENV_MAX_VARS   512 /* variables scanned before giving up */
#define UNIX_PATH_LEN  108
#define WATCH_PATH_LEN 128
#define WATCH_NAME_LEN 32

#define AF_UNIX	 1
#define AF_INET	 2
#define AF_INET6 10

#define O_ACCMODE 00000003
#define O_TRUNC	  00001000

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
	EVENT_CONNECT = 4,
	EVENT_ACCEPT = 5,
	EVENT_UNIX_CONNECT = 6,
	EVENT_FILE_OPEN = 7,
	EVENT_PTRACE = 8,
	EVENT_MEMFD = 9,
	EVENT_MODULE_LOAD = 10,
	EVENT_BPF_LOAD = 11,
	EVENT_CRED_CHANGE = 12,
	EVENT_MOUNT = 13,
	EVENT_SETNS = 14,
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
#define EXEC_F_ENV_TRUNC   (1U << 5) /* environment not scanned to its end */

/* A record ends after argv_len bytes of argv when env_len is zero, which is
 * the usual case. With captured variables the whole of argv is sent, followed
 * by env: one NUL-terminated NAME=value slot per allowlisted name, empty if
 * the variable is not set. */
struct exec_event {
	struct event_hdr h;
	__u64 inode;
	__u32 dev;
	__u32 argv_len; /* bytes used in argv, NUL-separated */
	__u64 cap_effective;
	__u32 env_len; /* 0, or ENV_LEN when any slot is filled */
	__u32 _pad;
	char path[PATH_LEN];
	char argv[ARGV_LEN];
	char env[ENV_LEN];	   /* allowlisted variables only */
	char env_tmp[ENV_VAR_LEN]; /* work area, never sent */
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

/* connect and accept. Addresses are in network byte order, IPv4 in the first
 * four bytes; ports are in host byte order. For connect the local side is
 * usually still unbound and reads as zero. */
struct net_event {
	struct event_hdr h;
	__u16 family; /* AF_INET or AF_INET6 */
	__u16 lport;
	__u16 rport;
	__u16 proto; /* IPPROTO_* */
	__u8 laddr[16];
	__u8 raddr[16];
};

/* connect to an AF_UNIX socket. An abstract address starts with a NUL. */
struct unix_event {
	struct event_hdr h;
	__u32 path_len; /* bytes used in path */
	char path[UNIX_PATH_LEN];
};

#define FILE_F_BY_INODE (1U << 0) /* matched inode_watch */
#define FILE_F_BY_NAME	(1U << 1) /* matched name_watch */
#define FILE_F_BY_PATH	(1U << 2) /* matched path_watch */
#define FILE_F_NO_PATH	(1U << 3) /* path longer than PATH_LEN */
/* The open ran under credentials the kernel put in place for it, not the
 * task's own: a filesystem opening a file on the task's behalf, as overlayfs
 * does for the backing file of every open. */
#define FILE_F_KERNEL_CREDS (1U << 4)

/* Only path_len bytes of path are sent. */
struct file_event {
	struct event_hdr h;
	__u64 inode;
	__u32 dev;
	__u32 open_flags; /* file->f_flags at open, O_TRUNC still present */
	__u32 watch_bits; /* value of the matching watch entry */
	__u32 path_len;	  /* bytes used in path, NUL included */
	char path[PATH_LEN];
};

#define PTRACE_MODE_ATTACH 0x02
#define BPF_PROG_LOAD_CMD  5

/* A task asked for attach-level access to another: ptrace attach, or
 * reading and writing its memory. */
struct ptrace_event {
	struct event_hdr h;
	__u32 target_pid; /* tgid in the node's pid namespace; 0 if outside */
	__u32 mode;	  /* PTRACE_MODE_* bits */
	__u64 target_start_time_ns;
};

struct memfd_event {
	struct event_hdr h;
	__u32 memfd_flags; /* MFD_* as passed; the name pointer is not read */
	__u32 _pad;
};

#define MODULE_NAME_MAX 56

struct module_event {
	struct event_hdr h;
	char name[MODULE_NAME_MAX];
};

struct bpf_event {
	struct event_hdr h;
	__u32 cmd; /* always BPF_PROG_LOAD */
	__u32 prog_type;
	char name[16];
};

/* The change was made by an exec, as a setuid binary does. */
#define CRED_F_IN_EXEC (1U << 0)

struct cred_event {
	struct event_hdr h;
	__u32 old_uid;
	__u32 new_uid;
	__u32 old_euid;
	__u32 new_euid;
	__u32 old_gid;
	__u32 new_gid;
	__u64 old_cap_effective;
	__u64 new_cap_effective;
};

#define MOUNT_COMPONENTS    6
#define MOUNT_COMPONENT_LEN 40
#define MOUNT_F_DEEPER	    (1U << 0) /* target has more parent directories */

/* bpf_d_path cannot be called at this hook. The target is given as its last
 * path components, leaf first, within the filesystem it is on. */
struct mount_event {
	struct event_hdr h;
	__u64 mnt_flags; /* MS_* */
	__u32 ncomp;
	__u32 _pad;
	char fstype[32];
	char comp[MOUNT_COMPONENTS][MOUNT_COMPONENT_LEN];
};

/* Namespace bits of setns_event.changed, and indexes into inum. */
enum ns_kind {
	NS_MNT = 0,
	NS_PID = 1, /* the namespace children will be created in */
	NS_NET = 2,
	NS_UTS = 3,
	NS_IPC = 4,
	NS_CGROUP = 5,
	NS_TIME = 6,
	NS_KINDS = 8,
};

/* A task's namespaces were switched (setns or unshare). inum holds the inode
 * number of every namespace the task has afterwards. */
struct setns_event {
	struct event_hdr h;
	__u32 changed; /* bit (1 << ns_kind) per namespace that differs */
	__u32 _pad;
	__u32 inum[NS_KINDS];
};

/* Watch bits: which kinds of open an entry reports. */
#define WATCH_READ  (1U << 0)
#define WATCH_WRITE (1U << 1)

struct path_key {
	__u32 prefixlen; /* in bits */
	char path[WATCH_PATH_LEN];
};

struct inode_key {
	__u64 inode;
	__u32 dev;
	__u32 _pad;
};

struct name_key {
	char name[WATCH_NAME_LEN];
};

struct ip4_key {
	__u32 prefixlen;
	__u8 addr[4];
};

struct ip6_key {
	__u32 prefixlen;
	__u8 addr[16];
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

/* Path prefixes file_open reports. An exact file is stored with its
 * terminating NUL, so it does not also match longer names. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct path_key);
	__type(value, __u32);
} path_watch SEC(".maps");

/* Files watched by identity, so a hard link or an unexpected path to a
 * watched file is still reported. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct inode_key);
	__type(value, __u32);
} inode_watch SEC(".maps");

/* Files watched by their last path component, wherever they are. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct name_key);
	__type(value, __u32);
} name_watch SEC(".maps");

/* Remote addresses whose connections are never emitted. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ip4_key);
	__type(value, __u8);
} net_ignore_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ip6_key);
	__type(value, __u8);
} net_ignore_v6 SEC(".maps");

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
