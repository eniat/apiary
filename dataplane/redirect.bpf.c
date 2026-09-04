//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

SEC("tc")
int tc_redirect(struct __sk_buff *skb)
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

	bpf_printk("saddr=%x dport=%d syn=%d",
		   bpf_ntohl(ip->saddr), bpf_ntohs(tcp->dest), tcp->syn);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
