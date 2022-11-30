// +build ignore

#include "vmlinux.h"
#include<bpf_helpers.h>
#include<bpf_endian.h>
// #include<linux/bpf.h>
// #include<bcc/proto.h>
// #include <bpf/bpf_helpers.h>
// #include <linux/if_ether.h>
// #include<stdio.h>

#define MAX_MAP_ENTRIES 1024

#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

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


char __license[] SEC("license") = "GPL";

// struct bpf_map_def SEC("maps") kprobe_map = {
// 	.type        = BPF_MAP_TYPE_ARRAY,
// 	.key_size    = sizeof(u32),
// 	.value_size  = sizeof(u64),
// 	.max_entries = 1,
// };

unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");

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
	struct ethhdr *eth_header;
	struct iphdr *ip_header;
	char strng[100] = "[SOCKET]:%d\n";
	unsigned char destination[6]; 
	bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), &destination, sizeof(destination));
  	bpf_trace_printk(strng, sizeof(strng), destination);
	return 0;


}

SEC("xdp")
int xdp_block(struct xdp_md *ctx) {
	
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_DROP;
	
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return XDP_DROP;

	char strng[100] = "[XDP-NET]:%u\n";
	// char strng[100] = "[XDP-NET]:Source addr %d.%d\n";
	char strng2[100] = "[XDP-NET]:Source eth addr2 %d:%d\n";
	char strng3[100] = "[XDP-NET]: IP addr2: %d-%d , Dest ip addr: %d\n";
	// char strng3[100] = "[XDP-NET]:ethhdr source : %u\n";
  	// bpf_trace_printk(strng2, sizeof(strng2), (iph->saddr >> 24) & 0xFF, (iph->saddr >> 16) & 0xFF);
  	// bpf_trace_printk(strng2, sizeof(strng2), (iph->saddr >> 8) & 0xFF, (iph->saddr) & 0xFF);

	// bpf_trace_printk(strng, sizeof(strng), bpf_ntohs(eth->h_proto));
	// 
	// bpf_trace_printk(strng2, sizeof(strng2), eth->h_dest[0], eth->h_dest[1], eth->h_dest[4]);
// 
	bpf_trace_printk(strng3, sizeof(strng3), (iph->saddr >> 24) & 0xFF, (iph->saddr) & 0xFF);
 	
	return XDP_PASS;
}