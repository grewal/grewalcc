use anyhow::{Context, Result};
use libbpf_rs::MapCore;
use std::os::unix::io::{AsFd, AsRawFd};
use std::thread;
use std::time::Duration;
use std::fs::File;
use std::io::{BufRead, BufReader};

const ARENA_SIZE_BYTES: usize = 1024 * 1024;
const SAMPLES_PER_SHARD: usize = 8192;
const SAMPLE_SIZE: usize = 64;
const METADATA_LIMIT: usize = 256;
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

fn discover_arena_base() -> Result<*const u8> {
    let file = File::open("/proc/self/maps")?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if line.contains("rw-s") && (line.contains("anon_inode:bpf-map") || line.contains("bpf-map")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let range: Vec<&str> = parts[0].split('-').collect();
            let start = usize::from_str_radix(range[0], 16)?;
            let end = usize::from_str_radix(range[1], 16)?;
            if end - start == ARENA_SIZE_BYTES { return Ok(start as *const u8); }
        }
    }
    Err(anyhow::anyhow!("Arena not found in /proc/self/maps"))
}

fn main() -> Result<()> {
    println!("--- KernelWall Liveness Debugger V25.5 ---");

    let mut skel_builder = libbpf_rs::ObjectBuilder::default();
    let open_obj = skel_builder.open_file("kernel-firewall-ebpf/src/main.o")?;
    let loaded_obj = open_obj.load().context("BPF Load Failed")?;

    let ifindex = nix::net::if_::if_nametoindex("ens4")?;
    let prog = loaded_obj.progs().next().context("No XDP prog")?;
    let prog_fd = prog.as_fd().as_raw_fd();

    /* Force re-attach */
    unsafe { libbpf_rs::libbpf_sys::bpf_xdp_detach(ifindex as i32, XDP_FLAGS_SKB_MODE, std::ptr::null()); }
    let ret = unsafe { libbpf_rs::libbpf_sys::bpf_xdp_attach(ifindex as i32, prog_fd, XDP_FLAGS_SKB_MODE, std::ptr::null()) };
    if ret != 0 { return Err(anyhow::anyhow!("Attach failed: {}", ret)); }
    
    let arena_base = discover_arena_base()?;
    let meta_map = loaded_obj.maps().find(|m| m.name() == "shard_meta_map").context("Map not found")?;

    println!("✓ Sentinel Live on ens4. Monitoring raw counters...");

    loop {
        let key = 0u32.to_ne_bytes();
        if let Some(meta_bytes) = meta_map.lookup_percpu(&key, libbpf_rs::MapFlags::empty())? {
            for (cpu_id, raw_meta) in meta_bytes.iter().enumerate() {
                let meta: &ShardMeta = unsafe { &*(raw_meta.as_ptr() as *const ShardMeta) };
                
                /* DEBUG PRINT: Always show counters even if zero */
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
