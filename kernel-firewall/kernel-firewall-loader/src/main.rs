/* 
 * KERNELWALL - V25.6 "ATOMIC-FREE FIREWALL" 
 * Control Plane: Sovereign Loader & Hardware Recon
 */

use anyhow::{Context, Result};
use libbpf_rs::MapCore;
use std::os::unix::io::{AsFd, AsRawFd};
use std::thread;
use std::time::Duration;

mod recon;
use recon::HardwareContext;

const ARENA_SIZE_BYTES: usize = 1024 * 1024;
const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct LatencySample {
    tsc: u64,
    packet_len: u32,
    cpu_id: u32,
    seq: u64,
    flags: u8,
    _padding: [u8; 39],
}

#[repr(C, align(128))]
struct ShardMeta {
    canary: u64,
    total_packets: u64,
    sampled_packets: u64,
    write_idx: u32,
    sample_rate: u32,
    last_balloon_ns: u64,
    cusum_positive: u64,
    _padding: [u8; 72],
}

fn main() -> Result<()> {
    println!("--- KernelWall Liveness Debugger V25.6 ---");

    // Phase 1: Environmental Reconnaissance
    let hw_ctx = HardwareContext::sweep();
    println!(
        "[RECON] Cores: {} | L1 Line: {} bytes | Arena Base Target: 0x{:X}",
        hw_ctx.online_cpus, hw_ctx.l1_cache_line_size, hw_ctx.arena_base_addr
    );

    if hw_ctx.arena_base_addr == 0 {
        println!("[!] Warning: BPF Arena not yet mapped in /proc/self/maps. Loading object to trigger kernel mapping...");
    }

    // Phase 2: BPF Object Loading
    let mut skel_builder = libbpf_rs::ObjectBuilder::default();
    let open_obj = skel_builder.open_file("kernel-firewall-ebpf/src/main.o")?;
    let loaded_obj = open_obj.load().context("BPF Load Failed")?;

    // Phase 3: Interface Attachment
    let ifindex = nix::net::if_::if_nametoindex("ens4")?;
    let prog = loaded_obj.progs().next().context("No XDP prog found in object")?;
    let prog_fd = prog.as_fd().as_raw_fd();

    /* Force re-attach for a clean state */
    unsafe { 
        libbpf_rs::libbpf_sys::bpf_xdp_detach(ifindex as i32, XDP_FLAGS_SKB_MODE, std::ptr::null()); 
    }
    let ret = unsafe { 
        libbpf_rs::libbpf_sys::bpf_xdp_attach(ifindex as i32, prog_fd, XDP_FLAGS_SKB_MODE, std::ptr::null()) 
    };
    if ret != 0 { 
        return Err(anyhow::anyhow!("XDP Attach failed with error code: {}", ret)); 
    }
    
    // Phase 4: Shared Memory Synchronization
    // Re-sweep now that the map is loaded to confirm the kernel-assigned address
    let hw_ctx_final = HardwareContext::sweep();
    if hw_ctx_final.arena_base_addr == 0 {
        return Err(anyhow::anyhow!("Sovereign Discovery failed: Arena address not found after load."));
    }
    println!("✓ Sentinel Live on ens4 at Arena: 0x{:X}", hw_ctx_final.arena_base_addr);

    let meta_map = loaded_obj.maps().find(|m| m.name() == "shard_meta_map").context("shard_meta_map not found")?;

    // Phase 5: Monitoring Loop
    loop {
        let key = 0u32.to_ne_bytes();
        if let Some(meta_bytes) = meta_map.lookup_percpu(&key, libbpf_rs::MapFlags::empty())? {
            for (cpu_id, raw_meta) in meta_bytes.iter().enumerate() {
                // Safety: We ensure ShardMeta alignment matches the BPF side (128-byte)
                let meta: &ShardMeta = unsafe { &*(raw_meta.as_ptr() as *const ShardMeta) };
                
                if meta.total_packets > 0 {
                    println!(
                        "[CPU {}] Pkts: {} | Sampled: {} | Canary: 0x{:X}",
                        cpu_id, meta.total_packets, meta.sampled_packets, meta.canary
                    );
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}
