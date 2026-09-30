//go:build ignore

#include "xdp.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Token buckets per source: TCP SYNs (new connections), QUIC long-header
// packets (connection setup), NTP and DNS replies. Established TCP and
// QUIC traffic is never counted.
//
// The SYN rate comes from fortress.yml (limits) through syn_cfg, which
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

// Only dark nodes speak QUIC to the edge. A handshake is a few long-header
// packets; after it, data rides short-header packets, which pass freely.
#define QUIC_BURST 1024
#define QUIC_NS 1953125ULL // 512/s
#define NTP_BURST 8
#define NTP_NS 250000000ULL // 4/s
#define DNS_BURST 64
#define DNS_NS 15625000ULL // 64/s

// The kernel's default net.ipv4.ip_local_port_range: replies to the edge's
// own connections (ACME, OCSP, DNS) arrive on these ports.
#define EPHEMERAL_LO 32768
#define EPHEMERAL_HI 60999

#define REASON_PASS 0
#define REASON_DROP_BLOCK 1
#define REASON_DROP_PORT 2
#define REASON_DROP_SYNRATE 3
#define REASON_DROP_NTPRATE 4
#define REASON_DROP_TRUNCATED 5 // a header cut short, or an IPv4 header length under 20
#define REASON_PASS_ARP 6
#define REASON_PASS_ICMP6 7
#define REASON_PASS_ICMP3 8
#define REASON_PASS_NTP 9
#define REASON_PASS_REPLY 10
#define REASON_PASS_DNS 11
#define REASON_DROP_DNSRATE 12
#define REASON_DROP_ETHERTYPE 13 // neither IPv4, IPv6, nor ARP: LLDP, STP, ...
#define REASON_DROP_FRAGMENT 14  // an IPv4 fragment after the first
#define REASON_DROP_PROTO 15     // an IP protocol other than TCP, UDP, ICMP
#define REASON_DROP_ICMP 16      // an ICMPv4 type other than destination unreachable
#define REASON_MAX 17

// LLC marks an IEEE 802.3 frame, whose type field is a length (STP, for one).
#define ETHERTYPE_LLC 0

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4);
	__type(value, struct blockval);
} block4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6);
	__type(value, struct blockval);
} block6 SEC(".maps");

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
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct src_key);
	__type(value, struct bucket);
} quic_rate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct src_key);
	__type(value, struct bucket);
} ntp_rate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct src_key);
	__type(value, struct bucket);
} dns_rate SEC(".maps");

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

// ponytail: racy per-IP bucket (nCPU can overshoot burst); atomic add if it shows in drops.
static __always_inline int take_token(void *map, struct src_key *key, __u32 burst, __u64 ns_per) {
	if (ns_per == 0) {
		return 1;
	}
	__u64 now = bpf_ktime_get_ns();
	struct bucket *b = bpf_map_lookup_elem(map, key);
	if (!b) {
		struct bucket init = {};
		init.last_ns = now;
		init.tokens = burst - 1;
		bpf_map_update_elem(map, key, &init, BPF_ANY);
		return 1;
	}
	if (now > b->last_ns) {
		__u64 add = (now - b->last_ns) / ns_per;
		if (add > burst) {
			add = burst;
		}
		__u32 t = b->tokens + (__u32)add;
		if (t > burst) {
			t = burst;
		}
		b->tokens = t;
		b->last_ns = now;
	}
	if (b->tokens == 0) {
		return 0;
	}
	b->tokens--;
	return 1;
}

static __always_inline int blocked4(__u32 saddr) {
	struct lpm4 k = {};
	k.prefixlen = 32;
	__builtin_memcpy(&k.addr, &saddr, 4);
	struct blockval *v = bpf_map_lookup_elem(&block4, &k);
	if (!v) {
		return 0;
	}
	if (v->expire_ns == 0 || bpf_ktime_get_ns() < v->expire_ns) {
		return 1;
	}
	// Exact /32 ban key. A covering config prefix is expire 0 and never reaches here.
	bpf_map_delete_elem(&block4, &k);
	return 0;
}

static __always_inline int blocked6(void *saddr) {
	struct lpm6 k = {};
	k.prefixlen = 128;
	__builtin_memcpy(&k.addr, saddr, 16);
	struct blockval *v = bpf_map_lookup_elem(&block6, &k);
	if (!v) {
		return 0;
	}
	if (v->expire_ns == 0 || bpf_ktime_get_ns() < v->expire_ns) {
		return 1;
	}
	// Bans on IPv6 are the source's /64.
	k.prefixlen = 64;
	__builtin_memset(&k.addr[8], 0, 8);
	bpf_map_delete_elem(&block6, &k);
	return 0;
}

static __always_inline int ephemeral(__u16 port_be) {
	__u16 p = bpf_ntohs(port_be);
	return p >= EPHEMERAL_LO && p <= EPHEMERAL_HI;
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
	if ((tcp->flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
		__u32 z = 0;
		struct syn_rate_cfg *cfg = bpf_map_lookup_elem(&syn_cfg, &z);
		if (cfg && !take_token(&syn_rate, src, cfg->burst, cfg->ns)) {
			return count(REASON_DROP_SYNRATE, XDP_DROP);
		}
	}
	return count(REASON_PASS, XDP_PASS);
}

static __always_inline int filter_udp(struct udphdr *udp, void *data_end, struct src_key *src) {
	if ((void *)(udp + 1) > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	if (udp->dest == bpf_htons(PORT_HTTPS)) {
		__u32 z = 0;
		__u8 *on = bpf_map_lookup_elem(&allow_quic, &z);
		if (on && *on) {
			__u8 *first = (void *)(udp + 1);
			if ((void *)(first + 1) > data_end) {
				return count(REASON_DROP_TRUNCATED, XDP_DROP);
			}
			// Long header (first bit set): Initial, 0-RTT, Handshake, Retry.
			if ((*first & 0x80) && !take_token(&quic_rate, src, QUIC_BURST, QUIC_NS)) {
				return count(REASON_DROP_SYNRATE, XDP_DROP);
			}
			return count(REASON_PASS, XDP_PASS);
		}
	}
	if (udp->source == bpf_htons(PORT_NTP)) {
		if (!take_token(&ntp_rate, src, NTP_BURST, NTP_NS)) {
			return count(REASON_DROP_NTPRATE, XDP_DROP);
		}
		return count(REASON_PASS_NTP, XDP_PASS);
	}
	if (udp->source == bpf_htons(PORT_DNS) && ephemeral(udp->dest)) {
		if (!take_token(&dns_rate, src, DNS_BURST, DNS_NS)) {
			return count(REASON_DROP_DNSRATE, XDP_DROP);
		}
		return count(REASON_PASS_DNS, XDP_PASS);
	}
	return count(REASON_DROP_PORT, XDP_DROP);
}

static __always_inline int filter_l4(void *l4, void *data_end, __u8 proto, struct src_key *src) {
	if (proto == IPPROTO_TCP) {
		return filter_tcp(l4, data_end, src);
	}
	if (proto == IPPROTO_UDP) {
		return filter_udp(l4, data_end, src);
	}
	return count(REASON_DROP_PROTO, XDP_DROP);
}

static __always_inline int handle_v6(void *nh, void *data_end) {
	struct ipv6hdr *ip6 = nh;
	if ((void *)(ip6 + 1) > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	if (blocked6(&ip6->saddr)) {
		return count(REASON_DROP_BLOCK, XDP_DROP);
	}
	if (ip6->nexthdr == IPPROTO_ICMPV6) {
		return count(REASON_PASS_ICMP6, XDP_PASS);
	}
	// One IPv6 user usually holds a whole /64, so rate limits count per /64.
	struct src_key src = {};
	src.family = 6;
	__builtin_memcpy(&src.ip, &ip6->saddr, 8);
	return filter_l4(ip6 + 1, data_end, ip6->nexthdr, &src);
}

static __always_inline int handle_v4(void *nh, void *data_end) {
	struct iphdr *ip = nh;
	if ((void *)(ip + 1) > data_end) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	if (ip->ihl < 5) {
		return count(REASON_DROP_TRUNCATED, XDP_DROP);
	}
	if (blocked4(ip->saddr)) {
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
	struct src_key src = {};
	src.family = 4;
	__builtin_memcpy(&src.ip, &ip->saddr, 4);
	return filter_l4(l4, data_end, ip->protocol, &src);
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
		return handle_v6(nh, data_end);
	}
	if (eth_proto == bpf_htons(ETH_P_IP)) {
		return handle_v4(nh, data_end);
	}
	return drop_ethertype(eth_proto);
}
