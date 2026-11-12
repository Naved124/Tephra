// SPDX-License-Identifier: GPL-2.0
/* Privilege and isolation: ptrace, credential changes, mounts, namespace
 * switches. */
#include "common.h"

const struct ptrace_event *__tephra_ptrace_event __attribute__((unused));
const struct cred_event *__tephra_cred_event __attribute__((unused));
const struct mount_event *__tephra_mount_event __attribute__((unused));
const struct setns_event *__tephra_setns_event __attribute__((unused));

/* Called for every access check on another task. Reading /proc entries asks
 * for read-level access and is not reported; attach-level access is what
 * ptrace(PTRACE_ATTACH), process_vm_writev and /proc/<pid>/mem need. */
SEC("fentry/security_ptrace_access_check")
int BPF_PROG(tephra_ptrace, struct task_struct *child, unsigned int mode)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_PTRACE);
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_struct *leader;
	struct ptrace_event e;

	if (!c || !s || !event_enabled(c, EVENT_PTRACE))
		return 0;
	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	s->seen++;

	/* A process looking at itself is not an attach to another. */
	if (BPF_CORE_READ(child, tgid) == BPF_CORE_READ(task, tgid) ||
	    cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return 0;
	}

	__builtin_memset(&e, 0, sizeof(e));
	if (!fill_hdr(&e.h, c, EVENT_PTRACE)) {
		s->filtered++;
		return 0;
	}
	e.h.size = sizeof(e);
	e.mode = mode;
	leader = BPF_CORE_READ(child, group_leader);
	if (node_pid(c, BPF_CORE_READ(leader, thread_pid), &e.target_pid))
		e.target_start_time_ns = BPF_CORE_READ(leader, start_boottime);
	else
		e.target_pid = 0;

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

/* Every change of a task's credentials goes through here. Only changes that
 * matter are emitted: a different uid, euid or gid, or effective
 * capabilities the task did not have. */
SEC("fentry/commit_creds")
int BPF_PROG(tephra_cred, struct cred *new)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_CRED_CHANGE);
	struct task_struct *task = bpf_get_current_task_btf();
	const struct cred *old;
	struct cred_event e;

	if (!c || !s || !event_enabled(c, EVENT_CRED_CHANGE))
		return 0;
	s->seen++;

	__builtin_memset(&e, 0, sizeof(e));
	old = BPF_CORE_READ(task, real_cred);
	e.old_uid = BPF_CORE_READ(old, uid.val);
	e.old_euid = BPF_CORE_READ(old, euid.val);
	e.old_gid = BPF_CORE_READ(old, gid.val);
	e.new_uid = BPF_CORE_READ(new, uid.val);
	e.new_euid = BPF_CORE_READ(new, euid.val);
	e.new_gid = BPF_CORE_READ(new, gid.val);
	bpf_core_read(&e.old_cap_effective, sizeof(e.old_cap_effective),
		      &old->cap_effective);
	bpf_core_read(&e.new_cap_effective, sizeof(e.new_cap_effective),
		      &new->cap_effective);

	if ((e.old_uid == e.new_uid && e.old_euid == e.new_euid &&
	     e.old_gid == e.new_gid &&
	     !(e.new_cap_effective & ~e.old_cap_effective)) ||
	    cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return 0;
	}
	if (!fill_hdr(&e.h, c, EVENT_CRED_CHANGE)) {
		s->filtered++;
		return 0;
	}
	e.h.size = sizeof(e);
	/* The header's uid and gid are the ones before the change. A setuid
	 * binary changes credentials during exec; anything else does it with
	 * a syscall, or should not be doing it at all. */
	if (BPF_CORE_READ_BITFIELD_PROBED(task, in_execve))
		e.h.flags |= CRED_F_IN_EXEC;

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

SEC("fentry/security_sb_mount")
int BPF_PROG(tephra_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_MOUNT);
	struct mount_event *e;
	struct dentry *d, *parent;
	__u32 zero = 0;
	int i;

	if (!c || !s || !event_enabled(c, EVENT_MOUNT))
		return 0;
	s->seen++;

	if (cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return 0;
	}
	e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e) {
		s->dropped++;
		return 0;
	}
	if (!fill_hdr(&e->h, c, EVENT_MOUNT)) {
		s->filtered++;
		return 0;
	}
	e->h.size = sizeof(*e);
	e->mnt_flags = flags;
	e->_pad = 0;
	/* The kernel's copy of the type string; NULL for a bind or remount. */
	__builtin_memset(e->fstype, 0, sizeof(e->fstype));
	if (type)
		bpf_probe_read_kernel_str(e->fstype, sizeof(e->fstype), type);

	__builtin_memset(e->comp, 0, sizeof(e->comp));
	e->ncomp = 0;
	d = BPF_CORE_READ(path, dentry);
	for (i = 0; i < MOUNT_COMPONENTS; i++) {
		parent = BPF_CORE_READ(d, d_parent);
		if (!d || parent == d)
			break;
		bpf_probe_read_kernel_str(e->comp[i], MOUNT_COMPONENT_LEN,
					  BPF_CORE_READ(d, d_name.name));
		e->ncomp = i + 1;
		d = parent;
	}
	if (i == MOUNT_COMPONENTS && d && BPF_CORE_READ(d, d_parent) != d)
		e->h.flags |= MOUNT_F_DEEPER;

	if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

static __always_inline __u32 ns_inum(struct nsproxy *ns, enum ns_kind kind)
{
	switch (kind) {
	case NS_MNT:
		return BPF_CORE_READ(ns, mnt_ns, ns.inum);
	case NS_PID:
		return BPF_CORE_READ(ns, pid_ns_for_children, ns.inum);
	case NS_NET:
		return BPF_CORE_READ(ns, net_ns, ns.inum);
	case NS_UTS:
		return BPF_CORE_READ(ns, uts_ns, ns.inum);
	case NS_IPC:
		return BPF_CORE_READ(ns, ipc_ns, ns.inum);
	case NS_CGROUP:
		return BPF_CORE_READ(ns, cgroup_ns, ns.inum);
	case NS_TIME:
		return BPF_CORE_READ(ns, time_ns, ns.inum);
	default:
		return 0;
	}
}

/* Where a task's namespaces are actually replaced. Every way in passes
 * through here: setns with a namespace file, setns with a pidfd, unshare.
 * The syscall arguments would say what was asked for; this says what the
 * task ends up in. */
SEC("fentry/switch_task_namespaces")
int BPF_PROG(tephra_setns, struct task_struct *p, struct nsproxy *new)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_SETNS);
	struct nsproxy *old;
	struct setns_event e;
	__u32 was;

	/* NULL when the task exits. */
	if (!c || !s || !new || !event_enabled(c, EVENT_SETNS))
		return 0;
	s->seen++;

	old = BPF_CORE_READ(p, nsproxy);
	if (!old || p != bpf_get_current_task_btf() ||
	    cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return 0;
	}

	__builtin_memset(&e, 0, sizeof(e));
#define NS_DIFF(kind)                                                          \
	e.inum[kind] = ns_inum(new, kind);                                     \
	was = ns_inum(old, kind);                                              \
	if (was != e.inum[kind])                                               \
		e.changed |= 1U << kind;
	NS_DIFF(NS_MNT)
	NS_DIFF(NS_PID)
	NS_DIFF(NS_NET)
	NS_DIFF(NS_UTS)
	NS_DIFF(NS_IPC)
	NS_DIFF(NS_CGROUP)
	NS_DIFF(NS_TIME)
#undef NS_DIFF

	if (!e.changed || !fill_hdr(&e.h, c, EVENT_SETNS)) {
		s->filtered++;
		return 0;
	}
	e.h.size = sizeof(e);
	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}
