/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TEPHRA_COMMON_H
#define TEPHRA_COMMON_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Event types. The value is the index into the stats map and, from M1, the
 * type field of the event header. Values are part of the kernel/agent
 * contract: append only, never renumber. */
enum event_type {
	EVENT_EXEC = 1,
	EVENT_FORK = 2,
	EVENT_EXIT = 3,
	EVENT_TYPE_MAX = 32,
};

/* Per-hook counters. Invariant checked in M1: seen == filtered + emitted +
 * dropped. */
struct stats_val {
	__u64 seen;
	__u64 filtered;
	__u64 emitted;
	__u64 dropped;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EVENT_TYPE_MAX);
	__type(key, __u32);
	__type(value, struct stats_val);
} stats SEC(".maps");

static __always_inline struct stats_val *stats_get(__u32 type)
{
	return bpf_map_lookup_elem(&stats, &type);
}

#endif /* TEPHRA_COMMON_H */
