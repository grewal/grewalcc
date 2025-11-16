// FILE: services/authorization/go/kernel/firewall.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

char LICENSE[] SEC("license") = "GPL";

// --- Configuration & Constants ---
#define MIN_PACKET_SIZE 64
#define MAX_PACKET_SIZE 4096
#define ACTION_DROP 1

enum {
        STATS_KEY_PASS = 0,
        STATS_KEY_DROP = 1,
};

// --- Data Structures & Maps ---

struct policy_entry {
        __u64 expiry_ns;
        __u8 action;
        __u8 pad[7];
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 100000);
        __type(key, __u32);
        __type(value, struct policy_entry);
} ip_policy_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 16);
        __type(key, __u16);
        __type(value, __u8);
} port_whitelist_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 2);
        __type(key, __u32);
        __type(value, __u64);
} xdp_stats_map SEC(".maps");

static __always_inline void record_stat(__u32 key) {
        __u64 *counter = bpf_map_lookup_elem(&xdp_stats_map, &key);
        if (counter) {
                __sync_fetch_and_add(counter, 1);
        }
}

// --- XDP Program Entrypoint ---
SEC("xdp_firewall")
int firewall_prog(struct xdp_md *ctx) {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        __u32 ip_header_size = 0;

        // --- Gate Zero: Packet Size Validation ---
        __u32 packet_len = data_end - data;
        if (packet_len < MIN_PACKET_SIZE || packet_len > MAX_PACKET_SIZE) {
                record_stat(STATS_KEY_DROP);
                return XDP_DROP;
        }

        // --- L2 Header Parsing (Ethernet) ---
        struct ethhdr *eth = data;

        if ((void *)eth + sizeof(*eth) > data_end) {
                record_stat(STATS_KEY_DROP);
                return XDP_DROP;
        }

        if (eth->h_proto != bpf_htons(ETH_P_IP)) {
                record_stat(STATS_KEY_PASS);
                return XDP_PASS;
        }

        // --- L3 Header Parsing (IPv4) ---
        struct iphdr *iph = (void *)eth + sizeof(*eth);

        if ((void *)iph + sizeof(*iph) > data_end) {
                record_stat(STATS_KEY_DROP);
                return XDP_DROP;
        }

        ip_header_size = iph->ihl * 4;
        if (ip_header_size < sizeof(struct iphdr)) {
                record_stat(STATS_KEY_DROP);
                return XDP_DROP;
        }

        if ((void *)iph + ip_header_size > data_end) {
                record_stat(STATS_KEY_DROP);
                return XDP_DROP;
        }

        // --- Gate 1: IP Policy Map Lookup ---
        __u32 source_ip = iph->saddr;
        struct policy_entry *policy = bpf_map_lookup_elem(&ip_policy_map, &source_ip);

        if (policy) {
                __u64 now_ns = bpf_ktime_get_ns();

                if (policy->action == ACTION_DROP &&
                    (policy->expiry_ns == 0 || now_ns < policy->expiry_ns)) {
                        record_stat(STATS_KEY_DROP);
                        return XDP_DROP;
                }
        }

        // --- Gate 2: L4 Protocol Check ---
        if (iph->protocol != IPPROTO_TCP) {
                record_stat(STATS_KEY_PASS);
                return XDP_PASS;
        }

        // --- L4 Header Parsing (TCP) ---
        struct tcphdr *tcph = (void *)iph + ip_header_size;

        if ((void *)tcph + sizeof(*tcph) > data_end) {
                record_stat(STATS_KEY_DROP);
                return XDP_DROP;
        }

        // --- Gate 3: Port Whitelist Check ---
        if (!bpf_map_lookup_elem(&port_whitelist_map, &tcph->dest)) {
                record_stat(STATS_KEY_DROP);
                return XDP_DROP;
        }

        record_stat(STATS_KEY_PASS);
        return XDP_PASS;
}
