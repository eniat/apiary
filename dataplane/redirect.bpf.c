//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_redirect(struct __sk_buff *skb)
{
	bpf_printk("apiary: len=%d", skb->len);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
