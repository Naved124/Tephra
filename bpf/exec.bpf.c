// SPDX-License-Identifier: GPL-2.0
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Fires after a successful exec, once the kernel has resolved the binary.
 * M0 only counts; M1 fills an exec_event from bprm and the task. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(tephra_exec, struct task_struct *p, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct stats_val *s = stats_get(EVENT_EXEC);

	if (s)
		s->seen++;
	return 0;
}
