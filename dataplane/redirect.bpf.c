//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_DST_OFF  (ETH_HLEN + __builtin_offsetof(struct iphdr, daddr))
#define IP_SRC_OFF  (ETH_HLEN + __builtin_offsetof(struct iphdr, saddr))
#define IP_CSUM_OFF (ETH_HLEN + __builtin_offsetof(struct iphdr, check))
#define ETH_DST_OFF (__builtin_offsetof(struct ethhdr, h_dest))

struct target {
	__u32 new_daddr;      // honeypot ip, network order
	__u32 ifindex;        // host side veth
	__u8  new_dmac[6];    // eth0 discards frames not addressed to it
	__u8  _pad[2];        // explicit, C and Go must agree byte for byte
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);   // attacker source ip, network order
	__type(value, struct target);
	__uint(max_entries, 1024);
} redirect_targets SEC(".maps");

struct stats {
	__u64 ns;
	__u64 pkts;
};

// per-cpu so the counters need no atomics
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct stats);
	__uint(max_entries, 1);
} redirect_stats SEC(".maps");

#define FLOW_IDLE_NS (120ULL * 1000000000ULL)

struct flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  proto;
	__u8  _pad[3];        // explicit and zeroed. keys compare as raw bytes
};

struct flow {
	__u32 addr;           // fwd honeypot. rev decoy
	__u32 ifindex;        // fwd only
	__u8  dmac[6];        // fwd only
	__u8  _pad[2];
	__u64 seen;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow);
	__uint(max_entries, 8192);
} flow_fwd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow);
	__uint(max_entries, 8192);
} flow_rev SEC(".maps");

SEC("tc")
int tc_redirect(struct __sk_buff *skb)
{
	__u64 t0 = bpf_ktime_get_ns();
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;
	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	__u32 ihl = ip->ihl * 4;
	if (ihl < sizeof(struct iphdr) || ihl > 60)
		return TC_ACT_OK;

	struct tcphdr *tcp = (void *)ip + ihl;
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_OK;

	struct flow_key fk = {
		.saddr = ip->saddr,
		.daddr = ip->daddr,
		.sport = tcp->source,
		.dport = tcp->dest,
		.proto = IPPROTO_TCP,
	};

	struct flow *fl = bpf_map_lookup_elem(&flow_fwd, &fk);
	if (fl && t0 - fl->seen > FLOW_IDLE_NS) {
		bpf_map_delete_elem(&flow_fwd, &fk);
		fl = NULL;
	}

	// only a syn opens a flow. anything else without one passes untouched
	if (!fl) {
		if (!tcp->syn || tcp->ack)
			return TC_ACT_OK;
		__u32 saddr = ip->saddr;
		struct target *t = bpf_map_lookup_elem(&redirect_targets, &saddr);
		if (!t || t->new_daddr == ip->daddr)
			return TC_ACT_OK;

		struct flow nf = { .addr = t->new_daddr, .ifindex = t->ifindex, .seen = t0 };
		__builtin_memcpy(nf.dmac, t->new_dmac, 6);
		bpf_map_update_elem(&flow_fwd, &fk, &nf, BPF_ANY);

		struct flow_key rk = {
			.saddr = t->new_daddr,
			.daddr = ip->saddr,
			.sport = tcp->dest,
			.dport = tcp->source,
			.proto = IPPROTO_TCP,
		};
		struct flow rf = { .addr = ip->daddr, .seen = t0 };
		bpf_map_update_elem(&flow_rev, &rk, &rf, BPF_ANY);

		fl = bpf_map_lookup_elem(&flow_fwd, &fk);
		if (!fl)
			return TC_ACT_OK;
	}
	fl->seen = t0;

	// read everything out before mutating. store_bytes may reallocate
	__u32 old_daddr = ip->daddr;
	__u32 new_daddr = fl->addr;
	__u32 ifindex = fl->ifindex;
	__u8 dmac[6];
	__builtin_memcpy(dmac, fl->dmac, 6);
	__u32 tcp_csum_off = ETH_HLEN + ihl + __builtin_offsetof(struct tcphdr, check);

	// checksums first. both need the old value still in the packet
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_daddr, new_daddr, sizeof(new_daddr));
	bpf_l4_csum_replace(skb, tcp_csum_off, old_daddr, new_daddr,
			    BPF_F_PSEUDO_HDR | sizeof(new_daddr));

	bpf_skb_store_bytes(skb, IP_DST_OFF, &new_daddr, sizeof(new_daddr), 0);
	bpf_skb_store_bytes(skb, ETH_DST_OFF, dmac, 6, 0);

	__u32 zero = 0;
	struct stats *st = bpf_map_lookup_elem(&redirect_stats, &zero);
	if (st) {
		st->ns += bpf_ktime_get_ns() - t0;
		st->pkts += 1;
	}

	// flags 0 is egress of that interface which delivers into the container
	return bpf_redirect(ifindex, 0);
}

struct dark_key {
	__u32 prefixlen;
	__u8  addr[4];
};

// lpm trie needs no_prealloc or the load fails
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct dark_key);
	__type(value, __u8);
	__uint(max_entries, 64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} darknet SEC(".maps");

#define REASON_DARK 1

struct flag {
	__u64 ns;             // first seen
	__u32 reason;         // 1 darknet
	__u32 _pad;           // explicit. C and Go must agree byte for byte
};

// lru evicts the least recently used row so the table stays bounded
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);   // source ip, network order
	__type(value, struct flag);
	__uint(max_entries, 4096);
} flagged SEC(".maps");

struct event {
	__u64 ns;
	__u32 saddr;          // flagged source, network order
	__u32 daddr;          // address it touched, network order
	__u32 reason;
	__u32 _pad;           // explicit. C and Go must agree byte for byte
};

// size in bytes not rows. power of two page multiple
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

// puts struct event in btf so bpf2go emits it
const struct event *unused_event __attribute__((unused));

// set from userspace before load. still constants to the verifier
volatile const __u32 scan_ports = 10;
volatile const __u64 scan_window_ns = 10000000000ULL;

#define REASON_SCAN 2

// one flag per source. later touches return early
static __always_inline void flag_source(__u32 saddr, __u32 daddr, __u32 reason)
{
	if (bpf_map_lookup_elem(&flagged, &saddr))
		return;

	__u64 now = bpf_ktime_get_ns();
	struct flag f = { .ns = now, .reason = reason };
	bpf_map_update_elem(&flagged, &saddr, &f, BPF_ANY);

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->ns = now;
	e->saddr = saddr;
	e->daddr = daddr;
	e->reason = reason;
	e->_pad = 0;
	bpf_ringbuf_submit(e, 0);
}


struct scan {
	__u64 first_ns;
	__u64 ports;          // bit per dport % 64. distinct saturates at 64
	__u32 syns;
	__u32 distinct;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);   // source ip, network order
	__type(value, struct scan);
	__uint(max_entries, 4096);
} scanners SEC(".maps");

static __always_inline void count_syn(__u32 saddr, __u32 daddr, __u16 dport)
{
	__u64 now = bpf_ktime_get_ns();
	__u64 bit = 1ULL << (bpf_ntohs(dport) & 63);

	struct scan *s = bpf_map_lookup_elem(&scanners, &saddr);
	if (!s) {
		struct scan ns = { .first_ns = now, .ports = bit, .syns = 1, .distinct = 1 };
		bpf_map_update_elem(&scanners, &saddr, &ns, BPF_ANY);
		return;
	}
	// window expired. start again from this packet
	if (now - s->first_ns > scan_window_ns) {
		s->first_ns = now;
		s->ports = bit;
		s->syns = 1;
		s->distinct = 1;
		return;
	}
	if (!(s->ports & bit))
		s->distinct += 1;
	s->ports |= bit;
	s->syns += 1;

	if (s->distinct >= scan_ports)
		flag_source(saddr, daddr, REASON_SCAN);
}

SEC("tc")
int tc_darknet(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	struct dark_key key = { .prefixlen = 32 };
	__builtin_memcpy(key.addr, &ip->daddr, 4);

	if (ip->protocol == IPPROTO_TCP) {
		__u32 ihl = ip->ihl * 4;
		if (ihl >= sizeof(struct iphdr) && ihl <= 60) {
			struct tcphdr *tcp = (void *)ip + ihl;
			if ((void *)(tcp + 1) <= data_end && tcp->syn && !tcp->ack)
				count_syn(ip->saddr, ip->daddr, tcp->dest);
		}
	}
	if (!bpf_map_lookup_elem(&darknet, &key))
		return TC_ACT_OK;

	flag_source(ip->saddr, ip->daddr, REASON_DARK);
	return TC_ACT_OK;
}

SEC("tc")
int tc_return(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;
	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	__u32 ihl = ip->ihl * 4;
	if (ihl < sizeof(struct iphdr) || ihl > 60)
		return TC_ACT_OK;

	struct tcphdr *tcp = (void *)ip + ihl;
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_OK;

	struct flow_key fk = {
		.saddr = ip->saddr,
		.daddr = ip->daddr,
		.sport = tcp->source,
		.dport = tcp->dest,
		.proto = IPPROTO_TCP,
	};

	struct flow *fl = bpf_map_lookup_elem(&flow_rev, &fk);
	if (!fl)
		return TC_ACT_OK;

	__u64 t0 = bpf_ktime_get_ns();
	if (t0 - fl->seen > FLOW_IDLE_NS) {
		bpf_map_delete_elem(&flow_rev, &fk);
		return TC_ACT_OK;
	}
	fl->seen = t0;

	__u32 old_saddr = ip->saddr;
	__u32 new_saddr = fl->addr;
	__u32 tcp_csum_off = ETH_HLEN + ihl + __builtin_offsetof(struct tcphdr, check);

	// the source sits in the tcp pseudo header so both checksums move
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_saddr, new_saddr, sizeof(new_saddr));
	bpf_l4_csum_replace(skb, tcp_csum_off, old_saddr, new_saddr,
			    BPF_F_PSEUDO_HDR | sizeof(new_saddr));

	bpf_skb_store_bytes(skb, IP_SRC_OFF, &new_saddr, sizeof(new_saddr), 0);

	// normal processing. the host routes it to the attacker
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
