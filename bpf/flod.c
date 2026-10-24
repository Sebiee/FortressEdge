//go:build ignore

#include "xdp.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// TCP SYNs (new connections) are limited per source, but only while all
// sources together send more than FLOOD_BURST at once or FLOOD_NS apart. A
// source address can be forged, and a stranger who spends a source's
// allowance cuts it off: a few forged SYNs a second would do. Below the
// flood rate, syncookies and the visitor limits in userspace protect the
// edge; in a flood, each source is held to its own rate. Established TCP
// and QUIC traffic is never counted.
//
// The per-source rate comes from fortress.yml (limits) through syn_cfg, which
// userspace updates while the program runs. ns 0 means no limit.
struct syn_rate_cfg {
	__u64 ns; // per token
	__u32 burst;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct syn_rate_cfg);
} syn_cfg SEC(".maps");

#define FLOOD_BURST 4096
#define FLOOD_NS 244140ULL // 4096/s

// The bucket all sources' SYNs share.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bucket);
} syn_all SEC(".maps");

// The kernel's default net.ipv4.ip_local_port_range: replies to the edge's
// own connections (ACME, OCSP, DNS) arrive on these ports.
#define EPHEMERAL_LO 32768
#define EPHEMERAL_HI 60999

#define REASON_PASS 0
#define REASON_DROP_BLOCK 1
#define REASON_DROP_PORT 2
#define REASON_DROP_SYNRATE 3
#define REASON_DROP_TRUNCATED 4 // a header cut short, or an IPv4 header length under 20
#define REASON_PASS_ARP 5
#define REASON_PASS_ICMP6 6
#define REASON_PASS_ICMP3 7
#define REASON_PASS_NTP 8
#define REASON_PASS_REPLY 9
#define REASON_PASS_DNS 10
#define REASON_DROP_ETHERTYPE 11 // neither IPv4, IPv6, nor ARP: LLDP, STP, ...
#define REASON_DROP_FRAGMENT 12  // an IPv4 fragment after the first
#define REASON_DROP_PROTO 13     // an IP protocol other than TCP, UDP, ICMP
#define REASON_DROP_ICMP 14      // an ICMPv4 type other than destination unreachable
#define REASON_MAX 15

// LLC marks an IEEE 802.3 frame, whose type field is a length (STP, for one).
#define ETHERTYPE_LLC 0

// The policy's block list. Each map holds twice the prefixes of its family
// a policy may list, so a new list goes in before the old one leaves.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4);
	__type(value, __u8);
} block4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6);
	__type(value, __u8);
} block6 SEC(".maps");

// Bans: each banned source, to the monotonic time its ban ends. Only
// userspace writes here: it bans and deletes ended bans, so the two cannot
// race. A hash, not an LRU, so new bans cannot push out old ones.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct src_key);
	__type(value, __u64);
} bans SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} allow_quic SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct src_key);
	__type(value, struct bucket);
} syn_rate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, REASON_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counts SEC(".maps");

static __always_inline int count(__u32 reason, int action) {
	__u64 *v = bpf_map_lookup_elem(&counts, &reason);
	if (v) {
		*v += 1;
	}
	return action;
}

// Frames dropped for their EtherType, by EtherType (ETHERTYPE_LLC for an
// 802.3 frame): what REASON_DROP_ETHERTYPE is. A type past max_entries is
// counted there only.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, __u64);
} ethertypes SEC(".maps");

static __always_inline int drop_ethertype(__u16 proto_be) {
	__u16 t = bpf_ntohs(proto_be);
	if (t < 0x0600) {
		t = ETHERTYPE_LLC;
	}
	__u64 *v = bpf_map_lookup_elem(&ethertypes, &t);
	if (v) {
		__sync_fetch_and_add(v, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&ethertypes, &t, &one, BPF_NOEXIST);
	}
	return count(REASON_DROP_ETHERTYPE, XDP_DROP);
}

// take spends one of b's tokens, after adding one for every ns_per since
// last_ns, up to burst. The part of an interval not yet worth a token
// carries over, so a steady sender gets the rate, not nothing. Racy across
// CPUs, which can overshoot burst a little; a per-CPU bucket would multiply
// the rate instead.
static __always_inline int take(struct bucket *b, __u32 burst, __u64 ns_per) {
	__u64 now = bpf_ktime_get_ns();
	if (now > b->last_ns) {
		__u64 add = (now - b->last_ns) / ns_per;
		if (add > burst) {
			add = burst;
		}
		__u64 t = b->tokens + add;
		// Full only after adding: a bucket idle for long must not keep an old
		// last_ns, or it would refill on every packet.
		if (t >= burst) {
			t = burst;
			b->last_ns = now;
		} else {
			b->last_ns += add * ns_per;
		}
		b->tokens = t;
	}
	if (b->tokens == 0) {
		return 0;
	}
	b->tokens--;
	return 1;
}

static __always_inline int syn_ok(struct src_key *src) {
	__u32 z = 0;
	struct syn_rate_cfg *cfg = bpf_map_lookup_elem(&syn_cfg, &z);
	if (!cfg || cfg->ns == 0) {
		return 1;
	}
	struct bucket *all = bpf_map_lookup_elem(&syn_all, &z);
	if (all && take(all, FLOOD_BURST, FLOOD_NS)) {
		return 1;
	}
	struct bucket *b = bpf_map_lookup_elem(&syn_rate, src);
	if (!b) {
		struct bucket init = {};
		init.last_ns = bpf_ktime_get_ns();
		init.tokens = cfg->burst - 1;
		bpf_map_update_elem(&syn_rate, src, &init, BPF_ANY);
		return 1;
	}
	return take(b, cfg->burst, cfg->ns);
}

static __always_inline int blocked4(__u32 saddr) {
	struct lpm4 k = {};
	k.prefixlen = 32;
	__builtin_memcpy(&k.addr, &saddr, 4);
	return bpf_map_lookup_elem(&block4, &k) != 0;
}

static __always_inline int blocked6(void *saddr) {
	struct lpm6 k = {};
	k.prefixlen = 128;
	__builtin_memcpy(&k.addr, saddr, 16);
	return bpf_map_lookup_elem(&block6, &k) != 0;
}

static __always_inline int banned(struct src_key *src) {
	__u64 *until = bpf_map_lookup_elem(&bans, src);
	return until && bpf_ktime_get_ns() < *until;
}

static __always_inline int ephemeral(__u16 port_be) {
	__u16 p = bpf_ntohs(port_be);
	return p >= EPHEMERAL_LO && p <= EPHEMERAL_HI;
}

// awaited says whether a socket of the edge's takes this datagram: the
// reply to a query it sent from a random port. A stranger must guess the
// port, as it must to forge the reply at all.
static __always_inline int awaited(struct xdp_md *ctx, void *iph, struct udphdr *udp, __u32 family) {
	struct bpf_sock_tuple t = {};
	struct bpf_sock *sk;
	if (family == 4) {
		struct iphdr *ip = iph;
		t.ipv4.saddr = ip->saddr;
		t.ipv4.daddr = ip->daddr;
		t.ipv4.sport = udp->source;
		t.ipv4.dport = udp->dest;
		sk = bpf_sk_lookup_udp(ctx, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0);
	} else {
		struct ipv6hdr *ip6 = iph;
		__builtin_memcpy(t.ipv6.saddr, ip6->saddr, 16);
		__builtin_memcpy(t.ipv6.daddr, ip6->daddr, 16);
		t.ipv6.sport = udp->source;
		t.ipv6.dport = udp->dest;
		sk = bpf_sk_lookup_udp(ctx, &t, sizeof(t.ipv6), BPF_F_CURRENT_NETNS, 0);
	}
	if (!sk) {
		return 0;
	}
	bpf_sk_release(sk);
	return 1;
}

static __always_inline int filter_tcp(struct tcphdr *tcp, void *data_end, struct src_key *src) {
	if ((void *)(tcp + 1) > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	// ponytail: stateless. Any ACK to an ephemeral port passes, not only a
	// reply; the kernel answers a stray one with RST. A conntrack map filled
	// from a TC egress hook would pass replies only. A bare SYN never passes.
	if ((tcp->flags & TCP_ACK) && ephemeral(tcp->dest)) {
		return count(REASON_PASS_REPLY, XDP_PASS);
	}
	if (tcp->dest != bpf_htons(PORT_HTTP) && tcp->dest != bpf_htons(PORT_HTTPS)) {
		return count(REASON_DROP_PORT, XDP_DROP);
	}
	if ((tcp->flags & (TCP_SYN | TCP_ACK)) == TCP_SYN && !syn_ok(src)) {
		return count(REASON_DROP_SYNRATE, XDP_DROP);
	}
	return count(REASON_PASS, XDP_PASS);
}

static __always_inline int filter_udp(struct xdp_md *ctx, void *iph, struct udphdr *udp, void *data_end, __u32 family) {
	if ((void *)(udp + 1) > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	if (udp->dest == bpf_htons(PORT_HTTPS)) {
		__u32 z = 0;
		__u8 *on = bpf_map_lookup_elem(&allow_quic, &z);
		if (on && *on) {
			return count(REASON_PASS, XDP_PASS);
		}
	}
	if (udp->source == bpf_htons(PORT_NTP) || udp->source == bpf_htons(PORT_DNS)) {
		if (!awaited(ctx, iph, udp, family)) {
			return count(REASON_DROP_PORT, XDP_DROP);
		}
		return count(udp->source == bpf_htons(PORT_NTP) ? REASON_PASS_NTP : REASON_PASS_DNS, XDP_PASS);
	}
	return count(REASON_DROP_PORT, XDP_DROP);
}

// family is a constant from handle_v4 or handle_v6, never read back from
// memory: the verifier must know which header iph points at.
static __always_inline int filter_l4(struct xdp_md *ctx, void *iph, __u32 family, void *l4, void *data_end, __u8 proto, struct src_key *src) {
	if (proto == IPPROTO_TCP) {
		return filter_tcp(l4, data_end, src);
	}
	if (proto == IPPROTO_UDP) {
		return filter_udp(ctx, iph, l4, data_end, family);
	}
	return count(REASON_DROP_PROTO, XDP_DROP);
}

static __always_inline int handle_v6(struct xdp_md *ctx, void *nh, void *data_end) {
	struct ipv6hdr *ip6 = nh;
	if ((void *)(ip6 + 1) > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	// One IPv6 user usually holds a whole /64, so limits and bans count per /64.
	struct src_key src = {};
	src.family = 6;
	__builtin_memcpy(&src.ip, &ip6->saddr, 8);
	if (blocked6(&ip6->saddr) || banned(&src)) {
		return count(REASON_DROP_BLOCK, XDP_DROP);
	}
	if (ip6->nexthdr == IPPROTO_ICMPV6) {
		return count(REASON_PASS_ICMP6, XDP_PASS);
	}
	return filter_l4(ctx, ip6, 6, ip6 + 1, data_end, ip6->nexthdr, &src);
}

static __always_inline int handle_v4(struct xdp_md *ctx, void *nh, void *data_end) {
	struct iphdr *ip = nh;
	if ((void *)(ip + 1) > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	if (ip->ihl < 5) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	struct src_key src = {};
	src.family = 4;
	__builtin_memcpy(&src.ip, &ip->saddr, 4);
	if (blocked4(ip->saddr) || banned(&src)) {
		return count(REASON_DROP_BLOCK, XDP_DROP);
	}
	if (bpf_ntohs(ip->frag_off) & IP_OFFMASK) {
		return count(REASON_DROP_FRAGMENT, XDP_DROP);
	}
	void *l4 = (void *)ip + ip->ihl * 4;
	if (l4 > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	if (ip->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp = l4;
		if ((void *)(icmp + 1) > data_end) {
			return count(REASON_DROP_TRUNCATED, XDP_DROP);
		}
		if (icmp->type == ICMP_DEST_UNREACH) {
			return count(REASON_PASS_ICMP3, XDP_PASS);
		}
		return count(REASON_DROP_ICMP, XDP_DROP);
	}
	return filter_l4(ctx, ip, 4, l4, data_end, ip->protocol, &src);
}

SEC("xdp")
int flod(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}

	__u16 eth_proto = eth->h_proto;
	void *nh = eth + 1;
	if (eth_proto == bpf_htons(ETH_P_8021Q)) {
		struct vlanhdr *vlan = nh;
		if ((void *)(vlan + 1) > data_end) {
			return count(REASON_DROP_TRUNCATED, XDP_DROP);
		}
		eth_proto = vlan->h_proto;
		nh = vlan + 1;
	}

	if (eth_proto == bpf_htons(ETH_P_ARP)) {
		return count(REASON_PASS_ARP, XDP_PASS);
	}
	if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		return handle_v6(ctx, nh, data_end);
	}
	if (eth_proto == bpf_htons(ETH_P_IP)) {
		return handle_v4(ctx, nh, data_end);
	}
	return drop_ethertype(eth_proto);
}
