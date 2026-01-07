/* 
 * KERNELWALL V27.0 - Hardware Reconnaissance Module
 * CPU/Cache Topology Detection
 */

use std::fs;

#[derive(Debug, Clone)]
pub struct HardwareContext {
    pub online_cpus: u32,
    pub l1_cache_line_size: usize,
    pub l2_cache_size_kb: Option<usize>,
    pub arena_base_addr: u64,
}

impl HardwareContext {
    pub fn sweep() -> Self {
        let online_cpus = Self::detect_online_cpus();
        let l1_cache_line_size = Self::detect_l1_cache_line_size();
        let l2_cache_size_kb = Self::detect_l2_cache_size();
        let arena_base_addr = Self::detect_arena_base();

        Self {
            online_cpus,
            l1_cache_line_size,
            l2_cache_size_kb,
            arena_base_addr,
        }
    }

    /// Identifies the core count to enable physical sharding boundaries
    fn detect_online_cpus() -> u32 {
        let content = fs::read_to_string("/sys/devices/system/cpu/online")
            .unwrap_or_else(|_| "0".to_string());
        
        // Parse formats like "0-1" or "0,1"
        let trimmed = content.trim();
        if trimmed.contains('-') {
            let parts: Vec<&str> = trimmed.split('-').collect();
            if parts.len() == 2 {
                let start = parts[0].parse::<u32>().unwrap_or(0);
                let end = parts[1].parse::<u32>().unwrap_or(0);
                return (end - start) + 1;
            }
        }
        trimmed.split(',').count() as u32
    }

    /// Probes the L1 coherency line size to prevent MESI-protocol false sharing
    fn detect_l1_cache_line_size() -> usize {
        let path = "/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size";
        fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(64) // Default fallback for Broadwell x86_64
    }

    /// Probes L2 size to calculate telemetry buffer pressure
    fn detect_l2_cache_size() -> Option<usize> {
        let path = "/sys/devices/system/cpu/cpu0/cache/index2/size";
        fs::read_to_string(path)
            .ok()
            .and_then(|s| {
                let trimmed = s.trim().trim_end_matches('K');
                trimmed.parse::<usize>().ok()
            })
    }

    /// Locates the anonymous BPF Arena mapping
    fn detect_arena_base() -> u64 {
        let maps = fs::read_to_string("/proc/self/maps").unwrap_or_default();
        
        for line in maps.lines() {
            // Logic: Find the 1MB shared-writable mapping with no file backing (anon)
            // Format: "7f...-7f... rw-s 00000000 00:0f 12345"
            if line.contains("rw-s") && !line.contains("/") && !line.contains("[") {
                if let Some(addr_str) = line.split('-').next() {
                    if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                        // Validate address range for x86_64 userspace
                        if addr > 0x700000000000 {
                            return addr;
                        }
                    }
                }
            }
        }
        0
    }
}
