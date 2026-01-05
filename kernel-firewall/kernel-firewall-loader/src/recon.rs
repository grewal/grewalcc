/* 
 * KERNELWALL - Sovereign Environmental Reconnaissance
 * Probes hardware topology and memory-mapped BPF Arenas.
 */

use std::fs;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone)]
pub struct HardwareContext {
    pub online_cpus: u32,
    pub l1_cache_line_size: u32,
    pub arena_base_addr: u64,
}

impl HardwareContext {
    pub fn sweep() -> Self {
        let online_cpus = Self::probe_online_cpus();
        let l1_cache_line_size = Self::probe_cache_line_size();
        let arena_base_addr = Self::find_arena_map_address();

        Self {
            online_cpus,
            l1_cache_line_size,
            arena_base_addr,
        }
    }

    /// Probes /sys/devices/system/cpu/online to determine core count (supports 1-96)
    fn probe_online_cpus() -> u32 {
        fs::read_to_string("/sys/devices/system/cpu/online")
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .split(',')
            .flat_map(|range| {
                let parts: Vec<&str> = range.split('-').collect();
                if parts.len() == 2 {
                    let start: u32 = parts[0].parse().unwrap_or(0);
                    let end: u32 = parts[1].parse().unwrap_or(0);
                    (start..=end).collect::<Vec<u32>>()
                } else {
                    vec![range.parse().unwrap_or(0)]
                }
            })
            .count() as u32
    }

    /// Determines cache line size for instruction sled alignment and sharding
    fn probe_cache_line_size() -> u32 {
        fs::read_to_string("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(64) // Fallback to standard x86 cache line
    }

    /// DISCOVERY: Identifies the BPF Arena mmap region
    /// Logic: Search /proc/self/maps for the 'anon_inode:bpf-map' tag.
    fn find_arena_map_address() -> u64 {
        let file = fs::File::open("/proc/self/maps").expect("Failed to open /proc/self/maps");
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let l = line.expect("Failed to read line from /proc/self/maps");
            if l.contains("anon_inode:bpf-map") {
                // Format: 7fb076ebc000-7fb076fbc000 rw-s 00000000 00:01 1234 anon_inode:bpf-map
                if let Some(addr_str) = l.split('-').next() {
                    return u64::from_str_radix(addr_str, 16).unwrap_or(0);
                }
            }
        }
        0
    }
}
