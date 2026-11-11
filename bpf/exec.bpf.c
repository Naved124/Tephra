// SPDX-License-Identifier: GPL-2.0
/* Process lifecycle: exec, fork and exit. */
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

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
	__u32 zero = 0, total;

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

	/* Send only the bytes in use, so a short argv does not cost 1.3 KiB
	 * of ring space. */
	total = offsetof(struct exec_event, argv) + len;
	e->h.size = total;
	if (total > sizeof(*e)) {
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
SEC("tp_btf/sched_process_fork")
int BPF_PROG(tephra_fork, struct task_struct *parent, struct task_struct *child)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_FORK);
	struct task_struct *real_parent;
	struct fork_event e;

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
