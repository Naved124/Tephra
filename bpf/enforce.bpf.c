// SPDX-License-Identifier: GPL-2.0
/* Enforcement: LSM programs that refuse an action before the kernel carries
 * it out. They run after the kernel has resolved its arguments, so what they
 * judge is what would happen. Each one
 *
 *   - leaves a refusal by another security module alone,
 *   - does nothing while enforce_cfg.mode is ENFORCE_OFF,
 *   - applies only below a cgroup in enforce_cgroups and never below one in
 *     protect_cgroups,
 *   - decides from the maps alone, and
 *   - reports every refusal, and in dry-run mode every refusal it would have
 *     made.
 *
 * While the sensor is blind (blind_now in common.h) they also refuse the
 * actions in blind_cfg below the pod cgroups, whatever the enforcement mode
 * and whether or not a pod opted in, and report each refusal into the
 * tamper buffer, which a flood cannot fill.
 *
 * They need CONFIG_BPF_LSM and "bpf" in the kernel's active LSM list. */
#include "common.h"

const struct enforce_event *__tephra_enforce_event __attribute__((unused));

#define EPERM_		    1
#define PTRACE_MODE_ATTACH_ 0x02
/* Cgroup levels looked at above the task's own. */
#define ENFORCE_MAX_DEPTH 12

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct enforce_event);
} enforce_scratch SEC(".maps");

static __always_inline struct enforce_cfg *enforce_get(__u32 action)
{
	__u32 zero = 0;
	struct enforce_cfg *ec = bpf_map_lookup_elem(&enforce_cfg, &zero);

	if (!ec || ec->mode == ENFORCE_OFF || !(ec->actions & (1U << action)))
		return NULL;
	return ec;
}

/* Whether enforcement applies to the current task: its cgroup or one above
 * it opted in, and none of them is protected. */
static __always_inline bool enforce_scope(void)
{
	__u64 id = bpf_get_current_cgroup_id();
	bool in = false;
	int level;

	if (bpf_map_lookup_elem(&protect_cgroups, &id))
		return false;
	if (bpf_map_lookup_elem(&enforce_cgroups, &id))
		in = true;
	for (level = 1; level <= ENFORCE_MAX_DEPTH; level++) {
		id = bpf_get_current_ancestor_cgroup_id(level);
		if (!id)
			break;
		if (bpf_map_lookup_elem(&protect_cgroups, &id))
			return false;
		if (bpf_map_lookup_elem(&enforce_cgroups, &id))
			in = true;
	}
	return in;
}

/* Whether blind mode applies to the current task: it runs in a pod (below
 * one of blind_cgroups) that the operator does not trust (none of its
 * cgroups in blind_protect). */
static __always_inline bool blind_scope(void)
{
	__u64 id = bpf_get_current_cgroup_id();
	bool in = false;
	int level;

	if (bpf_map_lookup_elem(&blind_protect, &id))
		return false;
	if (bpf_map_lookup_elem(&blind_cgroups, &id))
		in = true;
	for (level = 1; level <= ENFORCE_MAX_DEPTH; level++) {
		id = bpf_get_current_ancestor_cgroup_id(level);
		if (!id)
			break;
		if (bpf_map_lookup_elem(&blind_protect, &id))
			return false;
		if (bpf_map_lookup_elem(&blind_cgroups, &id))
			in = true;
	}
	return in;
}

/* The blind configuration if the sensor is blind, the action is in its
 * list and the task is in its scope; else NULL. */
static __always_inline struct blind_cfg *blind_get(__u32 action)
{
	struct blind_cfg *bc = blind_now();

	if (!bc || !(bc->actions & (1U << action)) || !blind_scope())
		return NULL;
	return bc;
}

static __always_inline void task_key_of(struct task_struct *task,
					struct task_key *k)
{
	k->start_time_ns = BPF_CORE_READ(task, group_leader, start_boottime);
	k->tgid = bpf_get_current_pid_tgid() >> 32;
	k->_pad = 0;
}

static __always_inline bool exe_is_runtime(struct task_struct *task)
{
	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	struct inode_key ik = {};

	if (!inode)
		return false;
	ik.inode = BPF_CORE_READ(inode, i_ino);
	ik.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	return bpf_map_lookup_elem(&runtime_inodes, &ik) != NULL;
}

/* The container runtime at work: one of its binaries, or the copy of itself
 * it started to set a container up. */
static __always_inline bool runtime_at_work(struct task_struct *task)
{
	struct task_key k;

	if (exe_is_runtime(task))
		return true;
	task_key_of(task, &k);
	return bpf_map_lookup_elem(&runtime_tasks, &k) != NULL;
}

/* Reports the action and returns what the hook must return. */
static __always_inline int enforce_report(struct enforce_cfg *ec,
					  struct enforce_event *e, __u32 action,
					  __u32 path_len, __u32 flags)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_ENFORCE);
	bool deny = ec->mode == ENFORCE_ON;
	__u32 total;

	if (c && s) {
		s->seen++;
		if (!fill_hdr(&e->h, c, EVENT_ENFORCE)) {
			s->filtered++;
		} else {
			e->h.flags = flags | (deny ? ENFORCE_F_DENIED : 0);
			e->action = action;
			e->path_len = path_len;
			e->_pad = 0;
			total = offsetof(struct enforce_event, path) + path_len;
			if (total > sizeof(*e))
				total = sizeof(*e);
			e->h.size = total;
			if (bpf_ringbuf_output(&events, e, total, rb_flags()))
				s->dropped++;
			else
				s->emitted++;
		}
	}
	/* The refusal does not depend on the report having been sent. */
	return deny ? -EPERM_ : 0;
}

/* Reports a refusal made while blind, into the tamper buffer, and returns
 * what the hook must return. */
static __always_inline int blind_report(bool deny, struct enforce_event *e,
					__u32 action, __u32 path_len,
					__u32 flags)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_ENFORCE);
	__u32 kind = TAMPER_LOST_BLIND, total, zero = 0;
	struct blind_key bk = {};
	__u64 now = bpf_ktime_get_boot_ns(), *last, *quiet, *lost;

	bk.cgroup_id = bpf_get_current_cgroup_id();
	bk.inode = e->inode;
	bk.action = action;
	last = bpf_map_lookup_elem(&blind_reported, &bk);
	if (last && now - *last < 1000000000ULL) {
		quiet = bpf_map_lookup_elem(&blind_quiet, &zero);
		if (quiet)
			(*quiet)++;
		return deny ? -EPERM_ : 0;
	}
	bpf_map_update_elem(&blind_reported, &bk, &now, BPF_ANY);

	if (c && s) {
		s->seen++;
		if (!fill_hdr(&e->h, c, EVENT_ENFORCE)) {
			s->filtered++;
		} else {
			e->h.flags = flags | ENFORCE_F_BLIND |
				     (deny ? ENFORCE_F_DENIED : 0);
			e->action = action;
			e->path_len = path_len;
			e->_pad = 0;
			total = offsetof(struct enforce_event, path) + path_len;
			if (total > sizeof(*e))
				total = sizeof(*e);
			e->h.size = total;
			if (bpf_ringbuf_output(&tamper_events, e, total, 0)) {
				s->dropped++;
				lost = bpf_map_lookup_elem(&tamper_lost, &kind);
				if (lost)
					(*lost)++;
			} else {
				s->emitted++;
			}
		}
	}
	return deny ? -EPERM_ : 0;
}

static __always_inline struct enforce_event *enforce_event_get(void)
{
	__u32 zero = 0;
	struct enforce_event *e = bpf_map_lookup_elem(&enforce_scratch, &zero);

	if (e) {
		e->inode = 0;
		e->dev = 0;
		e->path[0] = 0;
	}
	return e;
}

/* An action with nothing to describe beyond the task itself. Blind mode
 * goes first: it refuses whatever the enforcement mode. */
static __always_inline int enforce_plain(__u32 action, bool runtime_exempt)
{
	struct blind_cfg *bc = blind_get(action);
	struct enforce_cfg *ec = enforce_get(action);
	__u32 bm = BLIND_OFF, em = ENFORCE_OFF;
	struct enforce_event *e;
	bool deny;

	/* Decided on the modes, never on the two pointers together: clang
	 * turns "!bc && !ec" into an OR of pointers, which the verifier
	 * refuses (5.15: "bitwise operator |= on pointer prohibited"). */
	if (bc)
		bm = bc->mode;
	if (ec && enforce_scope())
		em = ec->mode;
	if (bm == BLIND_OFF && em == ENFORCE_OFF)
		return 0;
	if (runtime_exempt && runtime_at_work(bpf_get_current_task_btf()))
		return 0;
	/* Refused if either says so: blind mode only adds refusals. */
	deny = bm == BLIND_ON || em == ENFORCE_ON;
	e = enforce_event_get();
	if (!e)
		return deny ? -EPERM_ : 0;
	if (bm != BLIND_OFF)
		return blind_report(deny, e, action, 0, 0);
	if (!ec)
		return 0;
	return enforce_report(ec, e, action, 0, 0);
}

/* Runs for the file an execve names and again for each interpreter. The
 * task still runs its old program here. */
SEC("lsm/bprm_check_security")
int BPF_PROG(tephra_lsm_exec, struct linux_binprm *bprm, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct blind_cfg *bmode, *bc;
	struct enforce_cfg *ec;
	struct enforce_event *e;
	struct inode *inode;
	struct task_key k;
	__u32 zero = 0, bm = BLIND_OFF, em = ENFORCE_OFF;
	__u8 one = 1;
	bool deny;

	if (ret)
		return ret;
	ec = bpf_map_lookup_elem(&enforce_cfg, &zero);
	if (ec)
		em = ec->mode;
	/* The runtime is tracked whenever blind mode is on, blind or not, so
	 * that containers still start while the sensor is blind. */
	bmode = bpf_map_lookup_elem(&blind_cfg, &zero);
	if (bmode)
		bm = bmode->mode;
	if (em == ENFORCE_OFF && bm == BLIND_OFF)
		return 0;

	/* A runtime binary executing something is the runtime at work, and
	 * what it starts stays so until that in turn executes the
	 * container's program. runc starts a copy of itself this way, which
	 * has no name on disk. */
	task_key_of(task, &k);
	if (exe_is_runtime(task)) {
		bpf_map_update_elem(&runtime_tasks, &k, &one, BPF_ANY);
		return 0;
	}
	bpf_map_delete_elem(&runtime_tasks, &k);

	inode = BPF_CORE_READ(bprm, file, f_inode);
	if (BPF_CORE_READ(inode, i_nlink) != 0)
		return 0;
	bc = blind_get(ENF_EXEC_UNLINKED);
	bm = BLIND_OFF;
	if (bc)
		bm = bc->mode;
	if (em != ENFORCE_OFF &&
	    (!ec || !(ec->actions & (1U << ENF_EXEC_UNLINKED)) ||
	     !enforce_scope()))
		em = ENFORCE_OFF;
	if (bm == BLIND_OFF && em == ENFORCE_OFF)
		return 0;
	deny = bm == BLIND_ON || em == ENFORCE_ON;
	e = enforce_event_get();
	if (!e)
		return deny ? -EPERM_ : 0;
	e->inode = BPF_CORE_READ(inode, i_ino);
	e->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	if (bm != BLIND_OFF)
		return blind_report(deny, e, ENF_EXEC_UNLINKED, 0, 0);
	if (!ec)
		return 0;
	return enforce_report(ec, e, ENF_EXEC_UNLINKED, 0, 0);
}

/* Opens for writing of files marked WATCH_BLOCK, found the same three ways
 * as watched files: by identity, by name, by path. While the sensor is
 * blind, also opens of files marked WATCH_BLIND_WRITE or WATCH_BLIND_READ.
 * Anything else leaves at once. */
SEC("lsm/file_open")
int BPF_PROG(tephra_lsm_file_open, struct file *file, int ret)
{
	struct enforce_cfg *ec = NULL;
	struct blind_cfg *bc;
	struct enforce_event *e;
	struct inode_key ik = {};
	struct name_key nk = {};
	struct path_key pk;
	struct inode *inode;
	__u32 flags, *bits, n, all = 0, blind_bit, action;
	__u32 bm = BLIND_OFF, em = ENFORCE_OFF;
	bool write, deny;
	long len;

	if (ret)
		return ret;
	flags = BPF_CORE_READ(file, f_flags);
	write = flags & (O_ACCMODE | O_TRUNC);
	action = write ? ENF_FILE_WRITE : ENF_FILE_READ;
	blind_bit = write ? WATCH_BLIND_WRITE : WATCH_BLIND_READ;
	bc = blind_get(action);
	if (bc)
		bm = bc->mode;
	if (write) {
		ec = enforce_get(ENF_FILE_WRITE);
		if (ec && enforce_scope())
			em = ec->mode;
	}
	if (bm == BLIND_OFF && em == ENFORCE_OFF)
		return 0;

	inode = BPF_CORE_READ(file, f_inode);
	ik.inode = BPF_CORE_READ(inode, i_ino);
	ik.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	bits = bpf_map_lookup_elem(&inode_watch, &ik);
	if (bits)
		all |= *bits;
	bpf_probe_read_kernel_str(
	    nk.name, sizeof(nk.name),
	    BPF_CORE_READ(file, f_path.dentry, d_name.name));
	bits = bpf_map_lookup_elem(&name_watch, &nk);
	if (bits)
		all |= *bits;

	e = enforce_event_get();
	if (e) {
		len =
		    bpf_d_path((void *)&file->f_path, e->path, sizeof(e->path));
		if (len <= 0 || len > PATH_LEN)
			len = 0;
		if (len) {
			n = len;
			if (n > WATCH_PATH_LEN)
				n = WATCH_PATH_LEN;
			pk.prefixlen = n * 8;
			__builtin_memcpy(pk.path, e->path, WATCH_PATH_LEN);
			bits = bpf_map_lookup_elem(&path_watch, &pk);
			if (bits)
				all |= *bits;
		}
		e->inode = ik.inode;
		e->dev = ik.dev;
	} else {
		len = 0;
	}

	if (!(all & blind_bit))
		bm = BLIND_OFF;
	if (!(all & WATCH_BLOCK))
		em = ENFORCE_OFF;
	if (bm == BLIND_OFF && em == ENFORCE_OFF)
		return 0;
	/* Refused if either says so: blind mode only adds refusals. */
	deny = bm == BLIND_ON || em == ENFORCE_ON;
	if (!e)
		return deny ? -EPERM_ : 0;
	if (bm != BLIND_OFF)
		return blind_report(deny, e, action, len,
				    len ? 0 : ENFORCE_F_NO_PATH);
	if (!ec)
		return 0;
	return enforce_report(ec, e, ENF_FILE_WRITE, len,
			      len ? 0 : ENFORCE_F_NO_PATH);
}

/* Attach-level access to another process: ptrace(2), and also writing its
 * memory through /proc or process_vm_writev. */
SEC("lsm/ptrace_access_check")
int BPF_PROG(tephra_lsm_ptrace, struct task_struct *child, unsigned int mode,
	     int ret)
{
	if (ret)
		return ret;
	if (!(mode & PTRACE_MODE_ATTACH_))
		return 0;
	return enforce_plain(ENF_PTRACE, false);
}

/* The runtime mounts a container's filesystems from inside its cgroup, so
 * it is let through. */
SEC("lsm/sb_mount")
int BPF_PROG(tephra_lsm_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data, int ret)
{
	if (ret)
		return ret;
	return enforce_plain(ENF_MOUNT, true);
}

/* finit_module reads the module from a file; init_module hands it over from
 * memory. The two arrive at different hooks. */
SEC("lsm/kernel_read_file")
int BPF_PROG(tephra_lsm_read_file, struct file *file,
	     enum kernel_read_file_id id, bool contents, int ret)
{
	if (ret)
		return ret;
	/* Kernels with in-kernel module decompression (6.4 and later) read a
	 * compressed module under an ID of its own. */
	if (id !=
		bpf_core_enum_value(enum kernel_read_file_id, READING_MODULE) &&
	    !(bpf_core_enum_value_exists(enum kernel_read_file_id,
					 READING_MODULE_COMPRESSED) &&
	      id == bpf_core_enum_value(enum kernel_read_file_id,
					READING_MODULE_COMPRESSED)))
		return 0;
	return enforce_plain(ENF_MODULE, false);
}

SEC("lsm/kernel_load_data")
int BPF_PROG(tephra_lsm_load_data, enum kernel_load_data_id id, bool contents,
	     int ret)
{
	if (ret)
		return ret;
	if (id !=
		bpf_core_enum_value(enum kernel_load_data_id, LOADING_MODULE) &&
	    !(bpf_core_enum_value_exists(enum kernel_load_data_id,
					 LOADING_MODULE_COMPRESSED) &&
	      id == bpf_core_enum_value(enum kernel_load_data_id,
					LOADING_MODULE_COMPRESSED)))
		return 0;
	return enforce_plain(ENF_MODULE, false);
}
