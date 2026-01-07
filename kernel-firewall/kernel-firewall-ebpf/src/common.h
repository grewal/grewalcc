/* 
 * KERNELWALL V27.1
 * 
 * OPTIMIZATION GOALS:
 * - Zero cache line waste (100% density)
 * - Exact L1 cache line multiples (64 bytes)
 */

#ifndef __KERNELWALL_COMMON_H
#define __KERNELWALL_COMMON_H

#include <linux/types.h>

#define KW_ABI_MAGIC    0x53484457
#define KW_ABI_VERSION  27

/* 
 * ARENA GEOMETRY: 1MB Total, Perfectly Sharded
 */
#define ARENA_PAGES        256
#define ARENA_SIZE_BYTES   (ARENA_PAGES * 4096)
#define SHARD_SIZE_BYTES   (512 * 1024)

#define SAMPLES_PER_SHARD  8192
#define SAMPLE_SIZE        64      /* Exact L1 cache line */
#define METADATA_SIZE      64      /* Exact L1 cache line (Replaces METADATA_LIMIT) */

#define __arena __attribute__((address_space(1)))

/* 
 * LATENCY SAMPLE: 64-byte cache line aligned
 */
struct latency_sample {
    __u64 tsc;              /* [0-7]   Hardware timestamp */
    __u64 seq;              /* [8-15]  Monotonic packet counter */
    __u32 cpu_id;           /* [16-19] Core identity */
    __u32 packet_len;       /* [20-23] Frame size */
    __u8  tsc_lsb;          /* [24]    Hardware entropy bit */
    __u8  flags;            /* [25]    Reserved for DDoS markers */
    __u16 _reserved1;       /* [26-27] Alignment */
    __u32 src_ip;           /* [28-31] Future: Source IPv4 */
    __u32 dst_ip;           /* [32-35] Future: Dest IPv4 */
    __u16 src_port;         /* [36-37] Future: Source port */
    __u16 dst_port;         /* [38-39] Future: Dest port */
    __u8  proto;            /* [40]    Future: TCP/UDP/ICMP */
    __u8  _reserved2[23];   /* [41-63] Future expansion */
} __attribute__((aligned(64)));

/* 
 * SHARD METADATA: 64-byte cache line aligned
 */
struct shard_meta {
    __u64 canary;           /* [0-7]   Magic validation */
    __u64 total_packets;    /* [8-15]  All packets seen */
    __u64 sampled_packets;  /* [16-23] 1/128 sampled */
    __u32 write_idx;        /* [24-27] Ring buffer cursor */
    __u32 max_cpu_count;    /* [28-31] Patched constant from userspace */
    __u64 last_balloon_ns;  /* [32-39] Future: Adaptive sampling */
    __u64 cusum_positive;   /* [40-47] Future: Anomaly detection */
    __u8  _reserved[16];    /* [48-63] Future expansion */
} __attribute__((aligned(64)));

/* COMPILE-TIME ASSERTIONS */
_Static_assert(sizeof(struct latency_sample) == 64, "Structure size drift: latency_sample");
_Static_assert(sizeof(struct shard_meta) == 64, "Structure size drift: shard_meta");

#endif
