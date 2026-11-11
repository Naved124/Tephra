// SPDX-License-Identifier: GPL-2.0
/* File opens, filtered in the kernel to watched files. */
#include "common.h"

const struct file_event *__tephra_file_event __attribute__((unused));

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
