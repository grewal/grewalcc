// File: services/security-service/ebpf/kernel/xdp_ip_blocker.c
// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025 Yadwinder Grewal
 * eBPF XDP Program for Dynamic IP Blocking
 */

#include <linux/bpf.h>       // Core BPF definitions
#include <bpf/bpf_helpers.h> // SEC() macro, bpf_printk, bpf_map_lookup_elem
#include <bpf/bpf_endian.h>  // bpf_htons

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h> // For IPPROTO_TCP
#include <stddef.h>

// eBPF Map Definition for IP Blocklist
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);         // Key: Source IPv4 address (Network Byte Order)
    __type(value, __u8);        // Value: 1 if blocked
} ip_blocklist_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

#define XDP_PROGRAM_VERSION "XDP_GrewalNetGuard_vFINAL_DYN_1.0"

SEC("xdp_blocker")
int xdp_ip_blocker_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u32 source_ip_nbo;
    __u8 *value_ptr;

    // 1. Basic bounds check for Ethernet header
    if ((void *)eth + sizeof(*eth) > data_end) {
        // bpf_printk(XDP_PROGRAM_VERSION ": Packet too short for Ethernet header. Action: XDP_PASS.");
        return XDP_PASS;
    }

    // 2. Filter for IPv4 packets.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 3. Calculate IP header start and perform bounds check
    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) {
        // bpf_printk(XDP_PROGRAM_VERSION ": Packet too short for IP header. Action: XDP_PASS.");
        return XDP_PASS;
    }

    // 4. Extract the source IP address. iph->saddr is already in Network Byte Order.
    source_ip_nbo = iph->saddr;

    // Optional: Minimal logging for performance.
    // bpf_printk(XDP_PROGRAM_VERSION ": Checking SrcIP_NBO_hex: 0x%x", source_ip_nbo);

    // 5. Look up the extracted source IP in the blocklist map
    value_ptr = (__u8 *)bpf_map_lookup_elem(&ip_blocklist_map, &source_ip_nbo);

    // 6. Decision Logic
    if (value_ptr) {
        // Key (source_ip_nbo) was found in the map.
        if (*value_ptr == 1) { // Check if the flag is 1 (blocked)
            // bpf_printk(XDP_PROGRAM_VERSION ": SrcIP_NBO_hex 0x%x FOUND, Value is 1. Action: XDP_DROP.", source_ip_nbo);
            return XDP_DROP;
        }
        // bpf_printk(XDP_PROGRAM_VERSION ": SrcIP_NBO_hex 0x%x FOUND, Value is %u (not 1). Action: XDP_PASS.", source_ip_nbo, *value_ptr);
        return XDP_PASS; // Pass if found but value isn't the block flag
    } else {
        // Key (source_ip_nbo) was NOT found in the map.
        // bpf_printk(XDP_PROGRAM_VERSION ": SrcIP_NBO_hex 0x%x NOT FOUND. Action: XDP_PASS.", source_ip_nbo);
        return XDP_PASS;
    }
}
