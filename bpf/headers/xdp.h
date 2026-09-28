#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP = 1,
	XDP_PASS = 2,
};

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LPM_TRIE = 11,
};

#define BPF_F_NO_PREALLOC 1
#define BPF_ANY 0

struct xdp_md {
	__u32 data;
	__u32 data_end;
};

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__u16 h_proto;
} __attribute__((packed));

struct vlanhdr {
	__u16 tci;
	__u16 h_proto;
} __attribute__((packed));

struct iphdr {
	__u8 ihl : 4;
	__u8 version : 4;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));

struct ipv6hdr {
	__u8 prio : 4;
	__u8 version : 4;
	__u8 flow_lbl[3];
	__u16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u32 saddr[4];
	__u32 daddr[4];
} __attribute__((packed));

struct tcphdr {
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
	__u8 off;
	__u8 flags;
} __attribute__((packed));

struct udphdr {
	__u16 source;
	__u16 dest;
} __attribute__((packed));

struct icmphdr {
	__u8 type;
	__u8 code;
} __attribute__((packed));

struct lpm4 {
	__u32 prefixlen;
	__u8 addr[4];
} __attribute__((packed));

struct lpm6 {
	__u32 prefixlen;
	__u8 addr[16];
} __attribute__((packed));

struct blockval {
	__u64 expire_ns; // 0 = forever (config); non-zero = monotonic deadline (WAF ban)
};

struct src_key {
	__u32 family; // 4 or 6
	__u8 ip[16];
};

struct bucket {
	__u64 last_ns;
	__u32 tokens;
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#endif

#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_NTP 123
#define PORT_DNS 53

#define TCP_SYN 0x02
#define TCP_ACK 0x10

#define ICMP_DEST_UNREACH 3
#define IP_OFFMASK 0x1fff
