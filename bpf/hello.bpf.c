// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


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
	char fmt[100] = "HELLOOOOOOOOOOOOOOOOO %s\n";

	// bpf_get_current_comm(fmt, 100);
	bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int tcpconnect(void *ctx) {
	char strng[100] = "[tcpconnect]\n";
  	bpf_trace_printk(strng, sizeof(strng));
  	return 0;
}

int socket_filter(struct __sk_buff *skb) {
 
	char strng[100] = "[SOCKET]\n";
  	bpf_trace_printk(strng, sizeof(strng));
 
 	return 0;
}