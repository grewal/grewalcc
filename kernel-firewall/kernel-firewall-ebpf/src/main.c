/* 
 * KERNELWALL - V25.5 "WARP SENTINEL" 
 * Liveness Check: Bypass MAC Gate to verify Arena plumbing.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(max_entries, ARENA_PAGES);
    __uint(map_flags, BPF_F_MMAPABLE);
} arena_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shard_meta);
} shard_meta_map SEC(".maps");

SEC("xdp")
int xdp_warp_sentinel(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- PHASE 1: BOUNDS CHECK ONLY --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* --- PHASE 2: METADATA --- */
    __u32 cpu_id = bpf_get_smp_processor_id();
    if (cpu_id >= 2) return XDP_PASS;

    __u32 key = 0;
    struct shard_meta *meta = bpf_map_lookup_elem(&shard_meta_map, &key);
    if (!meta) return XDP_PASS;

    /* --- PHASE 3: ADAPTIVE SAMPLING --- */
    __u64 pkt_count = __sync_fetch_and_add(&meta->total_packets, 1);
    
    /* Sample 1 in 128 packets of ANY traffic */
    if ((pkt_count & 0x3) != 0) {
        return XDP_PASS;
    }

    /* --- PHASE 4: ARENA TELEMETRY --- */
    void __arena *arena_base = (void __arena *)(long)&arena_map;
    if (!arena_base) return XDP_PASS;

    if (meta->canary != 0xC0FFEE01FACADE42ULL) {
        meta->canary = 0xC0FFEE01FACADE42ULL;
    }

    __u32 sample_offset = METADATA_LIMIT + (cpu_id * SAMPLES_PER_SHARD * sizeof(struct latency_sample));
    struct latency_sample __arena *samples = 
        (struct latency_sample __arena *)((char __arena *)arena_base + sample_offset);
    
    __u32 idx = __sync_fetch_and_add(&meta->write_idx, 1) & (SAMPLES_PER_SHARD - 1);
    struct latency_sample __arena *s = &samples[idx];
    
    s->tsc = bpf_ktime_get_ns();
    s->packet_len = (__u32)(data_end - data);
    s->cpu_id = cpu_id;
    s->seq = pkt_count;
    s->flags = 0;
    
    __sync_fetch_and_add(&meta->sampled_packets, 1);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
