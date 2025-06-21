// FILE: services/security-service/ebpf/kernel/xdp_ip_blocker.c
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") ip_blocklist_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u8),
	.max_entries = 10240,
	.map_flags = 0,
};

SEC("xdp_blocker")
int xdp_ip_blocker_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return XDP_PASS;
    __u32 source_ip_nbo = iph->saddr;
    __u8 *value_ptr = (__u8 *)bpf_map_lookup_elem(&ip_blocklist_map, &source_ip_nbo);
    if (value_ptr && *value_ptr == 1) return XDP_DROP;
    return XDP_PASS;
}
