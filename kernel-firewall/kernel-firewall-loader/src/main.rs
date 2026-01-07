/* 
 * KERNELWALL
 */

use anyhow::{Context, Result};
use libbpf_rs::MapCore;
use std::os::unix::io::{AsFd, AsRawFd};
use std::thread;
use std::time::Duration;
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;

mod recon;
use recon::HardwareContext;

const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct LatencySample {
    tsc: u64,
    seq: u64,
    cpu_id: u32,
    packet_len: u32,
    tsc_lsb: u8,
    flags: u8,
    _reserved1: u16,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    _reserved2: [u8; 23],
}

#[repr(C, align(64))]
struct ShardMeta {
    canary: u64,
    total_packets: u64,
    sampled_packets: u64,
    write_idx: u32,
    max_cpu_count: u32,
    last_balloon_ns: u64,
    cusum_positive: u64,
    _padding: [u8; 16],
}

fn main() -> Result<()> {
    println!("--- KernelWall Liveness Debugger V28.1 ---");

    // PHASE 1: SILICON SEPARATION
    let mut cpu_set = CpuSet::new();
    cpu_set.set(0).context("Failed to select CPU 0")?;
    sched_setaffinity(Pid::from_raw(0), &cpu_set).context("Failed to pin loader to CPU 0")?;
    println!("[KernelWall] Control Plane pinned to CPU 0");

    // PHASE 2: HARDWARE RECON
    let hw_ctx = HardwareContext::sweep();
    println!(
        "[RECON] Cores: {} | L1: {}B | L2: {:?}KB",
        hw_ctx.online_cpus, hw_ctx.l1_cache_line_size, 
        hw_ctx.l2_cache_size_kb.unwrap_or(0)
    );

    // PHASE 3: BESPOKE BPF PATCHING
    let mut skel_builder = libbpf_rs::ObjectBuilder::default();
    let mut open_obj = skel_builder.open_file("kernel-firewall-ebpf/src/main.o")?;

    {
        let mut maps = open_obj.maps_mut();
        let mut rodata_map = maps.find(|m| {
            m.name().to_str().map(|s| s.contains("rodata")).unwrap_or(false)
        }).context("Failed to find .rodata section")?;
        
        let data = rodata_map.initial_value_mut().context("No initial value buffer")?;

        // Patch CONFIG_MAX_CPUS (u32 at offset 0)
        let cpu_bytes = hw_ctx.online_cpus.to_ne_bytes();
        if data.len() >= 4 {
            data[0..4].copy_from_slice(&cpu_bytes);
            println!("[KernWall] Patched CONFIG_MAX_CPUS with {}", hw_ctx.online_cpus);
        }
    }

    let loaded_obj = open_obj.load().context("BPF Load Failed")?;

    // PHASE 4: INTERFACE ATTACHMENT
    let ifindex = nix::net::if_::if_nametoindex("ens4")?;
    let prog = loaded_obj.progs().next().context("No XDP prog found")?;
    let prog_fd = prog.as_fd().as_raw_fd();

    unsafe { 
        libbpf_rs::libbpf_sys::bpf_xdp_detach(ifindex as i32, XDP_FLAGS_SKB_MODE, std::ptr::null()); 
        libbpf_rs::libbpf_sys::bpf_xdp_attach(ifindex as i32, prog_fd, XDP_FLAGS_SKB_MODE, std::ptr::null());
    }

    // PHASE 5: HUGE PAGE PROMOTION
    // Re-sweep to find where the kernel placed the Arena
    let hw_ctx_final = HardwareContext::sweep();
    let mapped_addr = hw_ctx_final.arena_base_addr;

    if mapped_addr != 0 {
        unsafe {
            // madvise(addr, length, MADV_HUGEPAGE)
            // Tells the MMU to use a 2MB translation entry for this 1MB region.
            let res = libc::madvise(mapped_addr as *mut libc::c_void, 1024 * 1024, libc::MADV_HUGEPAGE);
            if res == 0 {
                println!("✓  Arena promoted to 2MB Huge Page at 0x{:X}", mapped_addr);
            } else {
                println!("[!] Huge Page promotion failed. Proceeding with standard 4KB pages.");
            }
        }
    } else {
        println!("[!] Warning: Arena not discovered. Performance will be sub-optimal.");
    }

    println!("✓ Sentinel Live on ens4");

    let meta_map = loaded_obj.maps().find(|m| m.name() == "shard_meta_map").context("Map not found")?;

    // PHASE 6: TELEMETRY & SHADOW WARMING
    loop {
        let key = 0u32.to_ne_bytes();
        if let Some(meta_bytes) = meta_map.lookup_percpu(&key, libbpf_rs::MapFlags::empty())? {
            for (cpu_id, raw_meta) in meta_bytes.iter().enumerate() {
                let meta: &ShardMeta = unsafe { &*(raw_meta.as_ptr() as *const ShardMeta) };
                
                if meta.total_packets > 0 {
                    // SHADOW WARM: Touch the memory coordinate to keep STLB entries warm
                    if mapped_addr != 0 {
                        let canary_ptr = (mapped_addr + (cpu_id as u64 * 512 * 1024)) as *const u64;
                        let _hot_canary = unsafe { std::ptr::read_volatile(canary_ptr) };
                    }

                    println!(
                        "[CPU {}] Pkts: {} | Sampled: {} | TLB-Warm Canary: 0x{:X}",
                        cpu_id, meta.total_packets, meta.sampled_packets, meta.canary
                    );
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}
