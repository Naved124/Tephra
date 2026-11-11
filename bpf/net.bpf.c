// SPDX-License-Identifier: GPL-2.0
/* Network: outbound connect and inbound accept. */
#include "common.h"

const struct net_event *__tephra_net_event __attribute__((unused));
const struct unix_event *__tephra_unix_event __attribute__((unused));

/* ::ffff:a.b.c.d, an IPv4 peer on an IPv6 socket. */
static __always_inline bool v4_mapped(const __u8 *a)
{
	return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 &&
	       a[5] == 0 && a[6] == 0 && a[7] == 0 && a[8] == 0 && a[9] == 0 &&
	       a[10] == 0xff && a[11] == 0xff;
}

static __always_inline bool v4_ignored(const __u8 *a)
{
	struct ip4_key k = {.prefixlen = 32};

	__builtin_memcpy(k.addr, a, 4);
	return bpf_map_lookup_elem(&net_ignore_v4, &k) != NULL;
}

/* @e->family and @e->raddr are set. */
static __always_inline bool remote_ignored(const struct net_event *e)
{
	struct ip6_key k = {.prefixlen = 128};

	if (e->family == AF_INET)
		return v4_ignored(e->raddr);
	if (v4_mapped(e->raddr))
		return v4_ignored(e->raddr + 12);
	__builtin_memcpy(k.addr, e->raddr, 16);
	return bpf_map_lookup_elem(&net_ignore_v6, &k) != NULL;
}

/* Copies the socket's local or peer address into a 16-byte field. */
static __always_inline void read_addr(__u8 *dst, struct sock *sk, __u16 family,
				      bool local)
{
	if (family == AF_INET) {
		__be32 a = local ? BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr)
				 : BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memcpy(dst, &a, sizeof(a));
	} else {
		struct in6_addr a;

		if (local)
			a = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
		else
			a = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
		__builtin_memcpy(dst, &a, sizeof(a));
	}
}

static __always_inline void net_submit(struct net_event *e,
				       const struct tephra_cfg *c,
				       struct stats_val *s, __u32 type)
{
	if (remote_ignored(e) || !fill_hdr(&e->h, c, type)) {
		s->filtered++;
		return;
	}
	e->h.size = sizeof(*e);
	if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
		s->dropped++;
	else
		s->emitted++;
}

static __always_inline void unix_connect(const struct tephra_cfg *c,
					 struct sockaddr *address, int addrlen)
{
	struct stats_val *s = stats_get(EVENT_UNIX_CONNECT);
	struct unix_event e;
	__u32 len;

	if (!s || !event_enabled(c, EVENT_UNIX_CONNECT))
		return;
	s->seen++;

	/* sun_family is two bytes; the rest of addrlen is the path. */
	if (addrlen <= 2 || cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return;
	}
	len = addrlen - 2;
	if (len > UNIX_PATH_LEN)
		len = UNIX_PATH_LEN;

	__builtin_memset(&e, 0, sizeof(e));
	if (bpf_probe_read_kernel(e.path, len, (void *)address + 2) ||
	    !fill_hdr(&e.h, c, EVENT_UNIX_CONNECT)) {
		s->filtered++;
		return;
	}
	e.path_len = len;
	e.h.size = sizeof(e);
	if (bpf_ringbuf_output(&events, &e, sizeof(e), 0))
		s->dropped++;
	else
		s->emitted++;
}

/* The LSM hook sees the kernel's copy of the address, after the syscall layer
 * has copied it in, so the caller can no longer change what is read here. */
SEC("fentry/security_socket_connect")
int BPF_PROG(tephra_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_CONNECT);
	struct net_event e;
	struct sock *sk;
	__u16 family;

	if (!c || !s)
		return 0;
	family = BPF_CORE_READ(address, sa_family);
	if (family == AF_UNIX) {
		unix_connect(c, address, addrlen);
		return 0;
	}
	if (!event_enabled(c, EVENT_CONNECT))
		return 0;
	if (family != AF_INET && family != AF_INET6)
		return 0;
	s->seen++;

	if (cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return 0;
	}

	__builtin_memset(&e, 0, sizeof(e));
	e.family = family;
	if (family == AF_INET) {
		struct sockaddr_in sin;

		if (addrlen < (int)sizeof(sin) ||
		    bpf_probe_read_kernel(&sin, sizeof(sin), address)) {
			s->filtered++;
			return 0;
		}
		__builtin_memcpy(e.raddr, &sin.sin_addr, 4);
		e.rport = bpf_ntohs(sin.sin_port);
	} else {
		struct sockaddr_in6 sin6;

		/* 24 bytes is the shortest IPv6 address the kernel takes
		 * (SIN6_LEN_RFC2133); the scope ID after it is not read. */
		if (addrlen < 24 || bpf_probe_read_kernel(&sin6, 24, address)) {
			s->filtered++;
			return 0;
		}
		__builtin_memcpy(e.raddr, &sin6.sin6_addr, 16);
		e.rport = bpf_ntohs(sin6.sin6_port);
	}

	sk = BPF_CORE_READ(sock, sk);
	e.proto = BPF_CORE_READ(sk, sk_protocol);
	e.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	read_addr(e.laddr, sk, family, true);

	net_submit(&e, c, s, EVENT_CONNECT);
	return 0;
}

static __always_inline int accept_common(struct sock *newsk)
{
	struct tephra_cfg *c = cfg_get();
	struct stats_val *s = stats_get(EVENT_ACCEPT);
	struct net_event e;

	if (!c || !s || !event_enabled(c, EVENT_ACCEPT))
		return 0;
	s->seen++;

	if (!newsk || cgroup_ignored(bpf_get_current_cgroup_id())) {
		s->filtered++;
		return 0;
	}

	__builtin_memset(&e, 0, sizeof(e));
	e.family = BPF_CORE_READ(newsk, __sk_common.skc_family);
	e.proto = BPF_CORE_READ(newsk, sk_protocol);
	e.lport = BPF_CORE_READ(newsk, __sk_common.skc_num);
	e.rport = bpf_ntohs(BPF_CORE_READ(newsk, __sk_common.skc_dport));
	if (e.family != AF_INET && e.family != AF_INET6) {
		s->filtered++;
		return 0;
	}
	read_addr(e.laddr, newsk, e.family, true);
	read_addr(e.raddr, newsk, e.family, false);

	net_submit(&e, c, s, EVENT_ACCEPT);
	return 0;
}

/* The LSM hook that runs when an accepted socket is handed to its new owner,
 * in the accepting task. It is an entry hook: a server that was already
 * blocked in accept() when the agent attached is still seen, which an exit
 * hook on the accept function would miss for that first connection. */
SEC("fentry/security_sock_graft")
int BPF_PROG(tephra_accept, struct sock *sk, struct socket *parent)
{
	return accept_common(sk);
}

/* Fallback for kernels without security_sock_graft (built without
 * CONFIG_SECURITY_NETWORK). Only the returned socket is read. fexit finds the
 * return value after the last argument, and the argument list changed in 6.10,
 * so there is one program per signature; the loader keeps the one that matches
 * the kernel. */
SEC("fexit/inet_csk_accept")
int BPF_PROG(tephra_accept_v1, struct sock *sk, int flags, int *err, bool kern,
	     struct sock *newsk)
{
	return accept_common(newsk);
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(tephra_accept_v2, struct sock *sk, struct proto_accept_arg *arg,
	     struct sock *newsk)
{
	return accept_common(newsk);
}
