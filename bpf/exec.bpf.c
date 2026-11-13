// SPDX-License-Identifier: GPL-2.0
/* Process lifecycle: exec, fork and exit. */
#include "common.h"

/* Keep the small event structs in BTF so the agent's layout test sees them. */
const struct fork_event *__tephra_fork_event __attribute__((unused));
const struct exit_event *__tephra_exit_event __attribute__((unused));

static __always_inline bool fd_is_socket(struct task_struct *task, __u32 fd)
{
	struct file **fds = BPF_CORE_READ(task, files, fdt, fd);
	struct file *f = NULL;

	/* The table always has room for at least the first 64 descriptors. */
	if (!fds || bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || !f)
		return false;
	return (BPF_CORE_READ(f, f_inode, i_mode) & S_IFMT) == S_IFSOCK;
}

/* The dynamic loader variables that change which code a binary runs. Returns
 * the variable's slot in exec_event.env, or -1. @v has at least ENV_VAR_LEN
 * readable bytes. */
static __always_inline int env_slot(const char *v)
{
	if (v[0] != 'L' || v[1] != 'D' || v[2] != '_')
		return -1;
	if (v[3] == 'P' && v[4] == 'R' && v[5] == 'E' && v[6] == 'L' &&
	    v[7] == 'O' && v[8] == 'A' && v[9] == 'D' && v[10] == '=')
		return 0;
	if (v[3] == 'A' && v[4] == 'U' && v[5] == 'D' && v[6] == 'I' &&
	    v[7] == 'T' && v[8] == '=')
		return 1;
	if (v[3] == 'L' && v[4] == 'I' && v[5] == 'B' && v[6] == 'R' &&
	    v[7] == 'A' && v[8] == 'R' && v[9] == 'Y' && v[10] == '_' &&
	    v[11] == 'P' && v[12] == 'A' && v[13] == 'T' && v[14] == 'H' &&
	    v[15] == '=')
		return 2;
	return -1;
}

/* Scans the environment block of the new image and keeps only the
 * allowlisted variables. The kernel has just built this block, so no other
 * thread can be rewriting it. Every variable is read into a work area and
 * copied to its slot only if its name is on the list; nothing else leaves
 * the kernel. The first occurrence of a name wins, as it does for the
 * dynamic loader. A variable longer than the work area is read in pieces,
 * and only its first piece can match.
 *
 * Nothing the loop decides is carried in a register from one iteration to
 * the next, which is what keeps the verifier's work linear in the bound. */
static __always_inline void read_env(struct exec_event *e, struct mm_struct *mm)
{
	__u64 ptr = BPF_CORE_READ(mm, env_start);
	__u64 end = BPF_CORE_READ(mm, env_end);
	long n;
	int i, slot;

	e->env_len = 0;
	e->env[0] = 0;
	e->env[ENV_VAR_LEN] = 0;
	e->env[2 * ENV_VAR_LEN] = 0;

	for (i = 0; i < ENV_MAX_VARS; i++) {
		if (ptr >= end)
			break;
		n = bpf_probe_read_user_str(e->env_tmp, ENV_VAR_LEN,
					    (void *)ptr);
		if (n <= 0)
			break;
		ptr += n;
		slot = env_slot(e->env_tmp);
		if (slot == 0 && !e->env[0])
			bpf_probe_read_kernel_str(&e->env[0], ENV_VAR_LEN,
						  e->env_tmp);
		else if (slot == 1 && !e->env[ENV_VAR_LEN])
			bpf_probe_read_kernel_str(&e->env[ENV_VAR_LEN],
						  ENV_VAR_LEN, e->env_tmp);
		else if (slot == 2 && !e->env[2 * ENV_VAR_LEN])
			bpf_probe_read_kernel_str(&e->env[2 * ENV_VAR_LEN],
						  ENV_VAR_LEN, e->env_tmp);
		else
			continue;
		e->env_len = ENV_LEN;
	}
	/* Stopped early: say so, so that padding the environment to hide a
	 * variable is itself visible. */
	if (ptr < end)
		e->h.flags |= EXEC_F_ENV_TRUNC;
}

/* The inode change time has had three layouts: a timespec64 called i_ctime
 * (before 6.6), the same called __i_ctime (6.6 to 6.10), and two scalars
 * since. In the last form the top bit of the nanoseconds is a flag. */
struct inode___ts {
	struct timespec64 i_ctime;
};

struct inode___ts2 {
	struct timespec64 __i_ctime;
};

static __always_inline __u64 inode_ctime_ns(struct inode *inode)
{
	struct inode___ts2 *mid = (void *)inode;
	struct inode___ts *old = (void *)inode;
	__s64 sec;
	__u32 nsec;

	if (bpf_core_field_exists(inode->i_ctime_sec)) {
		sec = BPF_CORE_READ(inode, i_ctime_sec);
		nsec = BPF_CORE_READ(inode, i_ctime_nsec) & 0x7fffffff;
	} else if (bpf_core_field_exists(mid->__i_ctime)) {
		sec = BPF_CORE_READ(mid, __i_ctime.tv_sec);
		nsec = BPF_CORE_READ(mid, __i_ctime.tv_nsec);
	} else if (bpf_core_field_exists(old->i_ctime)) {
		sec = BPF_CORE_READ(old, i_ctime.tv_sec);
		nsec = BPF_CORE_READ(old, i_ctime.tv_nsec);
	} else {
		return 0;
	}
	if (sec < 0)
		return 0;
	return (__u64)sec * 1000000000ULL + nsec;
}

/* For a script the exec tracepoint sees the interpreter, not the script.
 * This runs once per execve, before any interpreter is looked up, while
 * bprm->file is still the file that was asked for. Its change time is kept
 * per process until the tracepoint collects it; an execve that fails leaves
 * an entry behind, which the LRU map discards in time. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} exec_ctime SEC(".maps");

SEC("fentry/security_bprm_creds_for_exec")
int BPF_PROG(tephra_exec_file, struct linux_binprm *bprm)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 ns = inode_ctime_ns(BPF_CORE_READ(bprm, file, f_inode));

	bpf_map_update_elem(&exec_ctime, &tgid, &ns, BPF_ANY);
	return 0;
}

/* Fires after a successful exec, once the kernel has resolved the binary, so
 * nothing here depends on the caller's view of its own arguments except
 * argv, which is read from the new address space the kernel just built. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(tephra_exec, struct task_struct *p, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_EXEC);
	struct exec_event *e;
	struct inode *inode;
	struct mm_struct *mm;
	const struct cred *cred;
	__u64 arg_start, arg_end, len;
	__u32 zero = 0, total, tgid;
	__u64 *seen;

	if (!c || !s || !event_enabled(c, EVENT_EXEC))
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
	if (!fill_hdr(&e->h, c, EVENT_EXEC)) {
		s->filtered++;
		return 0;
	}

	/* The executable as the kernel mapped it: for a script this is the
	 * interpreter. */
	mm = BPF_CORE_READ(p, mm);
	inode = BPF_CORE_READ(mm, exe_file, f_inode);
	e->inode = BPF_CORE_READ(inode, i_ino);
	e->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	if (BPF_CORE_READ(inode, i_nlink) == 0)
		e->h.flags |= EXEC_F_UNLINKED;
	if (BPF_CORE_READ(inode, i_mode) & S_ISUID)
		e->h.flags |= EXEC_F_SETUID;
	/* The file that was asked for if it is known, else the one mapped. */
	e->ctime_ns = inode_ctime_ns(inode);
	/* The same number the earlier hook used; h.pid is the pid as the
	 * node sees it, which differs inside a nested pid namespace. */
	tgid = bpf_get_current_pid_tgid() >> 32;
	seen = bpf_map_lookup_elem(&exec_ctime, &tgid);
	if (seen) {
		e->ctime_ns = *seen;
		bpf_map_delete_elem(&exec_ctime, &tgid);
	}

	/* kernel_cap_t is two u32 before 6.3 and one u64 after; both are the
	 * same eight little-endian bytes. */
	cred = BPF_CORE_READ(p, cred);
	e->cap_effective = 0;
	bpf_core_read(&e->cap_effective, sizeof(e->cap_effective),
		      &cred->cap_effective);

	/* bpf_d_path cannot be called from this hook, so the path is the
	 * kernel's copy of a name. interp is the binary that actually runs:
	 * the same as filename for an ordinary exec, and the interpreter for
	 * a "#!" script, so a shell started through a script is still seen
	 * as a shell. The script's own path stays visible in argv. */
	__builtin_memset(e->path, 0, sizeof(e->path));
	bpf_probe_read_kernel_str(e->path, sizeof(e->path),
				  BPF_CORE_READ(bprm, interp));

	if (fd_is_socket(p, 0))
		e->h.flags |= EXEC_F_STDIN_SOCK;
	if (fd_is_socket(p, 1))
		e->h.flags |= EXEC_F_STDOUT_SOCK;

	/* One bounded read of the argument block instead of a loop over
	 * arguments. */
	arg_start = BPF_CORE_READ(mm, arg_start);
	arg_end = BPF_CORE_READ(mm, arg_end);
	len = arg_end - arg_start;
	if (len > ARGV_LEN) {
		len = ARGV_LEN;
		e->h.flags |= EXEC_F_ARGV_TRUNC;
	}
	if (bpf_probe_read_user(e->argv, len, (void *)arg_start))
		len = 0;
	e->argv_len = len;

	read_env(e, mm);
	e->_pad = 0;

	/* Send only the bytes in use, so a short argv does not cost 1.3 KiB
	 * of ring space. */
	if (e->env_len)
		total = offsetof(struct exec_event, env) + ENV_LEN;
	else
		total = offsetof(struct exec_event, argv) + len;
	e->h.size = total;
	if (total > offsetof(struct exec_event, env_tmp)) {
		s->dropped++;
		return 0;
	}
	if (bpf_ringbuf_output(&events, e, total, 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

/* Fires in the parent once the child is fully set up. Thread creation is
 * counted and filtered; the process tree tracks processes. */
/* A process the container runtime forks while setting a container up is the
 * runtime at work too: runc's init forks the stages that build the
 * container's namespaces and mount its root filesystem. The enforcement
 * programs' mark (runtime_tasks) passes from parent to child here; the
 * child's own exec of the container's program clears it. Done whatever the
 * event settings, and only while enforcement is not off. */
static __always_inline void runtime_mark_inherit(struct task_struct *child)
{
	struct task_key pk = {}, ck = {};
	struct enforce_cfg *ec;
	__u32 zero = 0;
	__u8 one = 1;

	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))
		return; /* a thread shares its process's key */
	ec = bpf_map_lookup_elem(&enforce_cfg, &zero);
	if (!ec || ec->mode == ENFORCE_OFF)
		return;
	pk.start_time_ns =
	    BPF_CORE_READ((struct task_struct *)bpf_get_current_task_btf(),
			  group_leader, start_boottime);
	pk.tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&runtime_tasks, &pk))
		return;
	ck.start_time_ns = BPF_CORE_READ(child, start_boottime);
	ck.tgid = BPF_CORE_READ(child, tgid);
	bpf_map_update_elem(&runtime_tasks, &ck, &one, BPF_ANY);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(tephra_fork, struct task_struct *parent, struct task_struct *child)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_FORK);
	struct task_struct *real_parent;
	struct fork_event e;

	runtime_mark_inherit(child);
	if (!c || !s || !event_enabled(c, EVENT_FORK))
		return 0;
	s->seen++;

	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid) ||
	    cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return 0;
	}

	__builtin_memset(&e, 0, sizeof(e));
	if (!fill_hdr(&e.h, c, EVENT_FORK) ||
	    !node_pid(c, BPF_CORE_READ(child, thread_pid), &e.child_pid)) {
		s->filtered++;
		return 0;
	}
	e.h.size = sizeof(e);
	e.child_start_time_ns = BPF_CORE_READ(child, start_boottime);

	real_parent = BPF_CORE_READ(child, real_parent, group_leader);
	if (node_pid(c, BPF_CORE_READ(real_parent, thread_pid), &e.parent_pid))
		e.parent_start_time_ns =
		    BPF_CORE_READ(real_parent, start_boottime);
	else
		e.parent_pid = 0;

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

/* Fires for every exiting thread. Only the last thread of a process is
 * emitted: by then signal->live has already been decremented to zero. */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(tephra_exit, struct task_struct *p)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_EXIT);
	struct exit_event e;

	if (!c || !s || !event_enabled(c, EVENT_EXIT))
		return 0;
	s->seen++;

	if (BPF_CORE_READ(p, signal, live.counter) != 0 ||
	    cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return 0;
	}

	__builtin_memset(&e, 0, sizeof(e));
	if (!fill_hdr(&e.h, c, EVENT_EXIT)) {
		s->filtered++;
		return 0;
	}
	e.h.size = sizeof(e);
	e.exit_code = BPF_CORE_READ(p, exit_code);

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

/* Run once by the agent with BPF_PROG_RUN, in the agent's own context. It
 * records the agent's cgroup and pid namespace so the other programs can
 * ignore the agent and translate pids into the node's namespace. */
SEC("syscall")
int tephra_self(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct pid *pid = BPF_CORE_READ(task, thread_pid);
	struct self_info *info;
	__u32 zero = 0, nr = 0, inum = 0, level;

	info = bpf_map_lookup_elem(&self, &zero);
	if (!info)
		return 1;
	level = BPF_CORE_READ(pid, level);
	if (pid_at_level(pid, level, &nr, &inum))
		return 2;

	info->cgroup_id = bpf_get_current_cgroup_id();
	info->pidns_level = level;
	info->pidns_inum = inum;
	return 0;
}
