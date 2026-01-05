/* 
 * KERNELWALL - V25.6 "ATOMIC-FREE FIREWALL" 
 * Data Plane: Physical Sharding (No Atomics)
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

    /* --- PHASE 1: INGRESS (3ns) --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* --- PHASE 2: IDENTITY --- */
    __u32 cpu_id = bpf_get_smp_processor_id();
    if (cpu_id >= 2) return XDP_PASS;

    __u32 key = 0;
    struct shard_meta *meta = bpf_map_lookup_elem(&shard_meta_map, &key);
    if (!meta) return XDP_PASS;

    /* --- PHASE 3: SAMPLING (Non-Atomic) --- */
    /* Standard increment: CPU core owns this memory, no LOCK needed */
    __u64 pkt_count = meta->total_packets++;
    
    if ((pkt_count & 0x7F) != 0) {
        return XDP_PASS;
    }

    /* --- PHASE 4: ARENA COMMIT (Lockless) --- */
    void __arena *arena_base = (void __arena *)(long)&arena_map;
    if (!arena_base) return XDP_PASS;

    if (meta->canary != 0xC0FFEE01FACADE42ULL) {
        meta->canary = 0xC0FFEE01FACADE42ULL;
    }

    /* Hardware-Locked Sharding: Direct 512KB jump per CPU */
    __u32 shard_offset = cpu_id * SHARD_SIZE_BYTES;
    struct latency_sample __arena *samples = 
        (struct latency_sample __arena *)((char __arena *)arena_base + shard_offset + METADATA_LIMIT);
    
    /* Lockless Ring Management */
    __u32 idx = meta->write_idx & (SAMPLES_PER_SHARD - 1);
    struct latency_sample __arena *s = &samples[idx];
    
    /* Direct Assignment */
    s->tsc = bpf_ktime_get_ns();
    s->packet_len = (__u32)(data_end - data);
    s->cpu_id = cpu_id;
    s->seq = pkt_count;
    s->flags = 0;
    
    /* Update local pointers for next round */
    meta->write_idx = idx + 1;
    meta->sampled_packets++;
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
