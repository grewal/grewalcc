/* 
 * KERNELWALL V30.0 "PORT PARALLEL"
 * Data Plane: Port-Parallel Execution Chains
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

volatile const __u32 CONFIG_MAX_CPUS = 0;

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(max_entries, ARENA_PAGES);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(map_extra, 0x7F0000000000);
} arena_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shard_meta);
} shard_meta_map SEC(".maps");

SEC("xdp")
int xdp_warp_sentinel(struct xdp_md *ctx) {
    /* 
     * SILICON WARM-UP
     * Triggers STLB walker immediately.
     */
    void __arena *base = (void __arena *)(long)&arena_map;
    volatile char trigger = *(volatile char __arena *)base;
    (void)trigger;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- PHASE 1: INGRESS --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* --- PHASE 2: IDENTITY --- */
    __u32 cpu_id = bpf_get_smp_processor_id();
    if (cpu_id >= CONFIG_MAX_CPUS) return XDP_PASS;

    __u32 key = 0;
    struct shard_meta *meta = bpf_map_lookup_elem(&shard_meta_map, &key);
    if (!meta) return XDP_PASS;

    /* --- PHASE 3: PORT-PARALLEL CHAINS --- */
    __u64 pkt_count = meta->total_packets++;
    
    if ((pkt_count & 0x7F) == 0) {
        
        /* 
         * OPTIMIZATION: Front-load LEA (Port 1)
         * We compute the address chain BEFORE the clock tax starts.
         */
        __u32 shard_offset = cpu_id << 19;     // Port 1: LEA
        __u32 idx = meta->write_idx & 0x1FFF;  // Port 0: AND
        __u64 sample_offset = (__u64)idx << 6; // Port 1: LEA
        
        struct latency_sample __arena *s = 
            (struct latency_sample __arena *)((char __arena *)base + shard_offset + METADATA_SIZE + sample_offset);

        /* HARDWARE PREFETCH: Port 2/3 (Load AGU) - No contention with Port 0/1 */
        __builtin_prefetch(s, 1, 3);

        /* THE CLOCK TAX: Port 0/5 busy for 14ns */
        __u64 timestamp = bpf_ktime_get_ns();
        __u8 entropy = (__u8)(timestamp & 0x1);

        /* --- PHASE 4: ARENA COMMIT --- */
        if (meta->canary != 0xC0FFEE01FACADE42ULL) {
            meta->canary = 0xC0FFEE01FACADE42ULL;
        }

        s->tsc = timestamp;
        s->cpu_id = cpu_id;
        s->tsc_lsb = entropy;
        s->seq = pkt_count;
        s->packet_len = (__u32)(data_end - data);
        
        meta->write_idx = idx + 1;
        meta->sampled_packets++;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
