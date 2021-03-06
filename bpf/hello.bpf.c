// +build ignore

#include "vmlinux.h"
#include<bpf_helpers.h>
// #include <bpf/bpf_helpers.h>
// #include <linux/if_ether.h>
// #include<stdio.h>

#define MAX_MAP_ENTRIES 1024
/*
* DEPRECATED
struct bpf_map_def SEC("maps") my_map = {
      .type = BPF_MAP_TYPE_ARRAY,
      .key_size = sizeof(u32),
      .value_size = sizeof(long),
      .max_entries = MAX_MAP_ENTRIES
};
*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, u32);
    __type(value, long);
} my_map SEC(".maps");


char __license[] SEC("license") = "Dual MIT/GPL";

// struct bpf_map_def SEC("maps") kprobe_map = {
// 	.type        = BPF_MAP_TYPE_ARRAY,
// 	.key_size    = sizeof(u32),
// 	.value_size  = sizeof(u64),
// 	.max_entries = 1,
// };

SEC("kprobe/sys_execve")
int hello(void *ctx)
{
	char fmt[100] = "[KPROBE] %s\n";
	char c_cmd[100];
	bpf_get_current_comm(c_cmd, 100);
	bpf_trace_printk(fmt, sizeof(fmt), c_cmd);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int tcpconnect(void *ctx) {
	char strng[100] = "[tcpconnect]\n";
  	bpf_trace_printk(strng, sizeof(strng));
  	return 0;
}

SEC("socket")
int socket_filter(struct __sk_buff *skb) {
	char strng[100] = "[SOCKET]:%d\n";
  	bpf_trace_printk(strng, sizeof(strng), skb->protocol);
 	return 0;
}

SEC("xdp")
int xdp_block(struct xdp_md *ctx) {
	
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	// if (data + sizeof(struct ethhdr) > data_end)
	// 	return XDP_DROP;
	
	// struct iphdr *iph = data + sizeof(struct ethhdr);
	// if (data + sizeof( struct ethhdr) + sizeof(struct iphdr) > data_end)
	// 	return XDP_DROP;

	// char strng[100] = "[XDP]:%s\n";
	// char strng[100] = "[XDP]:Source addr %d.%d\n";
	// char strng2[100] = "[XDP]:Source addr2 %d.%d\n";
	char strng3[100] = "[XDP]:ethhdr source : %d\n";
	
  	// bpf_trace_printk(strng, sizeof(strng), (iph->saddr >> 24) & 0xFF, (iph->saddr >> 16) & 0xFF);
  	// bpf_trace_printk(strng2, sizeof(strng2), (iph->saddr >> 8) & 0xFF, (iph->saddr) & 0xFF);

	
  	bpf_trace_printk(strng3, sizeof(strng3),  ntohs(eth->h_proto));
 	return XDP_PASS;
}