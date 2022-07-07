// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// #include<stdio.h>



char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

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
	char strng[100] = "[XDP]:%d\n";
  	bpf_trace_printk(strng, sizeof(strng), ctx->ingress_ifindex);
 	return XDP_DROP;
}