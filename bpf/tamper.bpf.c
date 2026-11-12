// SPDX-License-Identifier: GPL-2.0
/* Things that change what code runs on the node, or that could blind the
 * sensor: anonymous memory files, kernel modules, BPF programs. */
#include "common.h"

const struct memfd_event *__tephra_memfd_event __attribute__((unused));
const struct module_event *__tephra_module_event __attribute__((unused));
const struct bpf_event *__tephra_bpf_event __attribute__((unused));

/* The syscall's own entry function, so only this syscall pays for the hook.
 * Only the flags are read: the name is a user pointer the caller can change
 * under us. */
SEC("fentry/__x64_sys_memfd_create")
int BPF_PROG(tephra_memfd, const struct pt_regs *regs)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_MEMFD);
	struct memfd_event e;

	if (!c || !s || !event_enabled(c, EVENT_MEMFD))
		return 0;
	s->seen++;

	__builtin_memset(&e, 0, sizeof(e));
	if (cgroup_ignored(bpf_get_current_cgroup_id()) ||
	    !fill_hdr(&e.h, c, EVENT_MEMFD)) {
		s->filtered++;
		return 0;
	}
	e.h.size = sizeof(e);
	e.memfd_flags = PT_REGS_PARM2_CORE(regs);

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

/* Fires once a module is loaded, in the task that loaded it. */
SEC("tp_btf/module_load")
int BPF_PROG(tephra_module, struct module *mod)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_MODULE_LOAD);
	struct module_event e;

	if (!c || !s || !event_enabled(c, EVENT_MODULE_LOAD))
		return 0;
	s->seen++;

	__builtin_memset(&e, 0, sizeof(e));
	if (cgroup_ignored(bpf_get_current_cgroup_id()) ||
	    !fill_hdr(&e.h, c, EVENT_MODULE_LOAD)) {
		s->filtered++;
		return 0;
	}
	e.h.size = sizeof(e);
	bpf_probe_read_kernel_str(e.name, sizeof(e.name), mod->name);

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}

/* Every bpf() call passes this check with the kernel's copy of its
 * arguments. Only program loads are reported. The sensor's own loads come
 * from its ignored cgroup. */
SEC("fentry/security_bpf")
int BPF_PROG(tephra_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_BPF_LOAD);
	struct bpf_event e;

	if (!c || !s || cmd != BPF_PROG_LOAD_CMD ||
	    !event_enabled(c, EVENT_BPF_LOAD))
		return 0;
	s->seen++;

	__builtin_memset(&e, 0, sizeof(e));
	if (cgroup_ignored(bpf_get_current_cgroup_id()) ||
	    !fill_hdr(&e.h, c, EVENT_BPF_LOAD)) {
		s->filtered++;
		return 0;
	}
	e.h.size = sizeof(e);
	e.cmd = cmd;
	e.prog_type = BPF_CORE_READ(attr, prog_type);
	/* prog_name was added to the attribute after prog_type; a shorter
	 * attribute from an old caller simply has no name. */
	if (size >= offsetof(union bpf_attr, prog_name) + sizeof(e.name))
		bpf_probe_read_kernel(e.name, sizeof(e.name), &attr->prog_name);
	e.name[sizeof(e.name) - 1] = 0;

	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
	return 0;
}
