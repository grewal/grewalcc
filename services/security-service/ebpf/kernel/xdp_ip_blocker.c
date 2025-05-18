// File: services/security-service/ebpf/kernel/xdp_ip_blocker.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // For bpf_ntohs, bpf_htonl etc.
#include <linux/if_ether.h> // For struct ethhdr and ETH_P_IP
#include <linux/ip.h>       // For struct iphdr
#include <linux/in.h>       // For IPPROTO_TCP, IPPROTO_UDP etc.

struct map_value {
    __u8 found;
};

// eBPF map definition for the IP blocklist
// Key: Source IP address in network byte order (__u32)
// Value: struct map_value (indicate presence)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // Max number of IPs to block
    __type(key, __u32);         // Source IP address
    __type(value, struct map_value);
} ip_blocklist_map SEC(".maps");


SEC("xdp_blocker")
int xdp_ip_blocker_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // Declare headers
    struct ethhdr *eth;
    struct iphdr *iph;

    // Parse Ethernet header
    eth = data;
    // Check if the packet is large enough to contain an Ethernet header
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    // Check if it's an IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; // Not an IPv4 packet
    }

    // Parse IP header
    iph = data + sizeof(*eth);
    // Check if the packet is large enough to contain an IP header
    if ((void *)iph + sizeof(*iph) > data_end) {
        return XDP_PASS;
    }

    // Get the source IP address from the IP header.
    __u32 source_ip = iph->saddr;

    // Look up source IP in blocklist map
    void *value_ptr = bpf_map_lookup_elem(&ip_blocklist_map, &source_ip);

    if (value_ptr) {
        // IP is found in the blocklist map, drop the packet
        return XDP_DROP;
    }

    // IP is not in the blocklist, allow it to pass.
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
