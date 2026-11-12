// SPDX-License-Identifier: GPL-2.0
/* File opens, filtered in the kernel to watched files. */
#include "common.h"

const struct file_event *__tephra_file_event __attribute__((unused));
const struct denied_event *__tephra_denied_event __attribute__((unused));

/* The LSM hook runs for every open that reaches a file, whichever syscall or
 * io_uring operation asked for it. Unfiltered opens are the highest-volume
 * event on a node, so nothing is emitted unless a watch matches. */
SEC("fentry/security_file_open")
int BPF_PROG(tephra_file_open, struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_FILE_OPEN);
	struct inode_key ik = {};
	struct name_key nk = {};
	struct path_key pk;
	struct file_event *e;
	struct inode *inode;
	__u32 zero = 0, want, *bits, match = 0, watch = 0, flags, total;
	long len;

	if (!c || !s || !event_enabled(c, EVENT_FILE_OPEN))
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

	flags = BPF_CORE_READ(file, f_flags);
	want = (flags & (O_ACCMODE | O_TRUNC)) ? WATCH_WRITE : WATCH_READ;

	/* Identity first: it holds whatever path was used to get here. */
	inode = BPF_CORE_READ(file, f_inode);
	ik.inode = BPF_CORE_READ(inode, i_ino);
	ik.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	bits = bpf_map_lookup_elem(&inode_watch, &ik);
	if (bits && (*bits & want)) {
		match = FILE_F_BY_INODE;
		watch = *bits;
	}

	if (!match) {
		bpf_probe_read_kernel_str(
		    nk.name, sizeof(nk.name),
		    BPF_CORE_READ(file, f_path.dentry, d_name.name));
		bits = bpf_map_lookup_elem(&name_watch, &nk);
		if (bits && (*bits & want)) {
			match = FILE_F_BY_NAME;
			watch = *bits;
		}
	}

	/* The path as the opening process sees it, relative to its root. The
	 * cast only drops const: f_path is const in recent kernels and the
	 * helper's prototype takes a plain pointer in older libbpf headers. */
	len = bpf_d_path((void *)&file->f_path, e->path, sizeof(e->path));
	if (len <= 0 || len > PATH_LEN) {
		len = 0;
		match |= match ? FILE_F_NO_PATH : 0;
	}

	if (!match && len) {
		__u32 n = len;

		if (n > WATCH_PATH_LEN)
			n = WATCH_PATH_LEN;
		pk.prefixlen = n * 8;
		__builtin_memcpy(pk.path, e->path, WATCH_PATH_LEN);
		bits = bpf_map_lookup_elem(&path_watch, &pk);
		if (bits && (*bits & want)) {
			match = FILE_F_BY_PATH;
			watch = *bits;
		}
	}

	if (!match || !fill_hdr(&e->h, c, EVENT_FILE_OPEN)) {
		s->filtered++;
		return 0;
	}
	e->h.flags = match;
	/* Reported, not filtered: the agent uses it to drop the second event
	 * of one overlayfs open, and nothing is hidden here. */
	if (BPF_CORE_READ(task, cred) != BPF_CORE_READ(task, real_cred))
		e->h.flags |= FILE_F_KERNEL_CREDS;
	e->inode = ik.inode;
	e->dev = ik.dev;
	e->open_flags = flags;
	e->watch_bits = watch;
	e->path_len = len;

	total = offsetof(struct file_event, path) + len;
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

/* A watched name can be changed without ever being opened: removed, renamed
 * away, replaced by a rename or created as a link. These hooks report the
 * names such an operation touches, filtered by the same watches as opens. */
static __noinline int report_change(struct dentry *dentry, struct vfsmount *mnt,
				    __u32 op)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_FILE_CHANGE);
	struct inode_key ik = {};
	struct name_key nk = {};
	struct path_key pk;
	struct file_event *e;
	struct inode *inode;
	__u32 zero = 0, *bits, match = 0, watch = 0, len, total;
	bool cut = false;

	if (!c || !s || !event_enabled(c, EVENT_FILE_CHANGE))
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

	/* A name that does not exist yet has no inode. */
	inode = BPF_CORE_READ(dentry, d_inode);
	if (inode) {
		ik.inode = BPF_CORE_READ(inode, i_ino);
		ik.dev = BPF_CORE_READ(inode, i_sb, s_dev);
		bits = bpf_map_lookup_elem(&inode_watch, &ik);
		if (bits && (*bits & WATCH_WRITE)) {
			match = FILE_F_BY_INODE;
			watch = *bits;
		}
	}
	if (!match) {
		bpf_probe_read_kernel_str(nk.name, sizeof(nk.name),
					  BPF_CORE_READ(dentry, d_name.name));
		bits = bpf_map_lookup_elem(&name_watch, &nk);
		if (bits && (*bits & WATCH_WRITE)) {
			match = FILE_F_BY_NAME;
			watch = *bits;
		}
	}

	len = build_path(dentry, mnt, e->path, &cut);
	if (!match && len && !cut) {
		__u32 n = len;

		if (n > WATCH_PATH_LEN)
			n = WATCH_PATH_LEN;
		pk.prefixlen = n * 8;
		__builtin_memcpy(pk.path, e->path, WATCH_PATH_LEN);
		bits = bpf_map_lookup_elem(&path_watch, &pk);
		if (bits && (*bits & WATCH_WRITE)) {
			match = FILE_F_BY_PATH;
			watch = *bits;
		}
	}

	if (!match || !fill_hdr(&e->h, c, EVENT_FILE_CHANGE)) {
		s->filtered++;
		return 0;
	}
	e->h.flags = match;
	if (cut || !len)
		e->h.flags |= FILE_F_NO_PATH;
	e->inode = ik.inode;
	e->dev = ik.dev;
	e->open_flags = op;
	e->watch_bits = watch;
	e->path_len = len;

	total = offsetof(struct file_event, path) + len;
	barrier_var(total);
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

SEC("fentry/security_path_unlink")
int BPF_PROG(tephra_unlink, const struct path *dir, struct dentry *dentry)
{
	return report_change(dentry, BPF_CORE_READ(dir, mnt), FILE_OP_UNLINK);
}

SEC("fentry/security_path_rename")
int BPF_PROG(tephra_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	report_change(old_dentry, BPF_CORE_READ(old_dir, mnt),
		      FILE_OP_RENAME_FROM);
	return report_change(new_dentry, BPF_CORE_READ(new_dir, mnt),
			     FILE_OP_RENAME_TO);
}

SEC("fentry/security_path_link")
int BPF_PROG(tephra_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	return report_change(new_dentry, BPF_CORE_READ(new_dir, mnt),
			     FILE_OP_LINK);
}

SEC("fentry/security_path_symlink")
int BPF_PROG(tephra_symlink, const struct path *dir, struct dentry *dentry)
{
	return report_change(dentry, BPF_CORE_READ(dir, mnt), FILE_OP_SYMLINK);
}

/* truncate(2) only. ftruncate needs a descriptor open for writing, and an
 * open with O_TRUNC is an open: both were reported as a file_open. */
SEC("fentry/vfs_truncate")
int BPF_PROG(tephra_truncate, const struct path *path)
{
	return report_change(BPF_CORE_READ(path, dentry),
			     BPF_CORE_READ(path, mnt), FILE_OP_TRUNCATE);
}

/* Opens the kernel refused never reach security_file_open, or reach it and
 * are refused there. The return of do_filp_open (do_file_open on newer
 * kernels) is where every open ends,
 * whichever check said no. Refusals are rare, so all of them are sent and
 * the agent matches the name against the watches: it has to put a relative
 * name together with the working directory first. */
static __always_inline int open_denied(unsigned long long *ctx, int dfd,
				       struct filename *pathname,
				       const struct open_flags *op)
{
	unsigned long r = 0;
	struct tephra_cfg *c;
	struct stats_val *s;
	struct denied_event *e;
	struct task_struct *task;
	__u32 zero = 0, total;
	bool cut = false;
	long n;

	/* The return value as a number: older verifiers refuse arithmetic on
	 * it while it is typed as a pointer. An error is a pointer in the
	 * last page of the address space. */
	bpf_probe_read_kernel(&r, sizeof(r), &ctx[3]);
	if (r < (unsigned long)-4095)
		return 0;
	r = -r;
	if (r != EACCES && r != EPERM && r != EROFS)
		return 0;

	c = cfg_get();
	s = stats_get(EVENT_FILE_DENIED);
	if (!c || !s || !event_enabled(c, EVENT_FILE_DENIED))
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
	if (!fill_hdr(&e->h, c, EVENT_FILE_DENIED)) {
		s->filtered++;
		return 0;
	}
	e->error = r;
	e->open_flags = BPF_CORE_READ(op, open_flag);
	e->cwd_len = 0;
	e->name[0] = 0;
	n = bpf_probe_read_kernel_str(e->name, sizeof(e->name),
				      BPF_CORE_READ(pathname, name));
	e->name_len = n > 0 ? n : 0;

	if (e->name[0] != '/') {
		if (dfd == AT_FDCWD) {
			task = bpf_get_current_task_btf();
			e->cwd_len = build_path(
			    BPF_CORE_READ(task, fs, pwd.dentry),
			    BPF_CORE_READ(task, fs, pwd.mnt), e->cwd, &cut);
			if (cut)
				e->h.flags |= DENIED_F_CWD_CUT;
		} else {
			e->h.flags |= DENIED_F_NO_CWD;
		}
	}

	total = e->cwd_len ? sizeof(*e) : offsetof(struct denied_event, cwd);
	e->h.size = total;
	if (bpf_ringbuf_output(&events, e, total, 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

SEC("fexit/do_filp_open")
int BPF_PROG(tephra_open_denied, int dfd, struct filename *pathname,
	     const struct open_flags *op, struct file *ret)
{
	return open_denied(ctx, dfd, pathname, op);
}

/* Newer kernels call the same function do_file_open. */
SEC("fexit/do_file_open")
int BPF_PROG(tephra_open_denied_v2, int dfd, struct filename *pathname,
	     const struct open_flags *op, struct file *ret)
{
	return open_denied(ctx, dfd, pathname, op);
}
