/* 
 * KERNELWALL - V25.6 "ATOMIC-FREE FIREWALL" 
 */

#ifndef __KERNELWALL_COMMON_H
#define __KERNELWALL_COMMON_H

#include <linux/types.h>

#define KW_ABI_MAGIC    0x53484457
#define KW_ABI_VERSION  26

/* 
 * ARENA GEOMETRY: 1MB Total
 * Split exactly into two 512KB "Hegemonies" 
 */
#define ARENA_PAGES        256
#define ARENA_SIZE_BYTES   (ARENA_PAGES * 4096)
#define SHARD_SIZE_BYTES   (512 * 1024) 

#define SAMPLES_PER_SHARD  8192
#define SAMPLE_SIZE        64
#define METADATA_LIMIT     256

#define __arena __attribute__((address_space(1)))

static const unsigned char TARGET_MAC[] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x02};

struct latency_sample {
    __u64 tsc;
    __u32 packet_len;
    __u32 cpu_id;
    __u64 seq;
    __u8  flags;
    __u8  _padding[39];
} __attribute__((aligned(64)));

struct shard_meta {
    __u64 canary;
    __u64 total_packets;
    __u64 sampled_packets;
    __u32 write_idx;
    __u32 sample_rate;
    __u64 last_balloon_ns;
    __u64 cusum_positive;
    __u8  _padding[72];
} __attribute__((aligned(128)));

#endif
