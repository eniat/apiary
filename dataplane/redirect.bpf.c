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

	__u32 saddr = ip->saddr;
	struct target *t = bpf_map_lookup_elem(&redirect_targets, &saddr);
	if (!t)
		return TC_ACT_OK;

	// read everything out before mutating, store_bytes may reallocate
	__u32 old_daddr = ip->daddr;
	__u32 new_daddr = t->new_daddr;
	__u32 ifindex = t->ifindex;
	if (old_daddr == new_daddr)
		return TC_ACT_OK;

	__u8 dmac[6];
	__builtin_memcpy(dmac, t->new_dmac, 6);
	__u32 tcp_csum_off = ETH_HLEN + ihl + __builtin_offsetof(struct tcphdr, check);

	// checksums first, both need the old value still in the packet
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_daddr, new_daddr, sizeof(new_daddr));
	bpf_l4_csum_replace(skb, tcp_csum_off, old_daddr, new_daddr,
			    BPF_F_PSEUDO_HDR | sizeof(new_daddr));

	bpf_skb_store_bytes(skb, IP_DST_OFF, &new_daddr, sizeof(new_daddr), 0);
	bpf_skb_store_bytes(skb, ETH_DST_OFF, dmac, 6, 0);

	bpf_printk("daddr %x to %x ifindex %d", bpf_ntohl(old_daddr),
		   bpf_ntohl(new_daddr), ifindex);

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
	if (!bpf_map_lookup_elem(&darknet, &key))
		return TC_ACT_OK;

	__u32 saddr = ip->saddr;
	if (bpf_map_lookup_elem(&flagged, &saddr))
		return TC_ACT_OK;

	struct flag f = { .ns = bpf_ktime_get_ns(), .reason = REASON_DARK };
	bpf_map_update_elem(&flagged, &saddr, &f, BPF_ANY);
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return TC_ACT_OK;
	e->ns = f.ns;
	e->saddr = saddr;
	e->daddr = ip->daddr;
	e->reason = REASON_DARK;
	e->_pad = 0;
	bpf_ringbuf_submit(e, 0);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
