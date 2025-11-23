use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
    Ebpf
};
use clap::Parser;
use tokio::{signal, task, time::{interval, Duration}};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct AuditEvent {
    timestamp_ns: u64,
    eth_proto: u16,
    ip_proto: u8,
    src_port: u16,
    dst_port: u16,
    action: u8,
    _padding: [u8; 4],
}

#[derive(Parser, Debug)]
struct Opt {
    #[clap(short, long, default_value = "ens4")]
    iface: String,

    #[clap(long, default_value = "100")]
    poll_interval_ms: u64,

    #[clap(long)]
    verbose: bool,
}

struct Stats {
    packets_logged: AtomicU64,
    bytes_processed: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let opt = Opt::parse();

    // Load embedded bytecode
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/debug/initlock_ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/release/initlock_ebpf"
    ))?;

    // Attach XDP
    let program: &mut Xdp = bpf.program_mut("initlock_xdp").unwrap().try_into()?;
    program.load()?;
    // ** THE FIX IS HERE: We now explicitly request SKB_MODE for compatibility **
    program.attach(&opt.iface, XdpFlags::SKB_MODE)?;

    println!("✓ XDP program attached to {}", opt.iface);

    // Setup RingBuffer using the correct try_from method
    let mut ring_buf = RingBuf::try_from(bpf.take_map("PACKET_LOG").unwrap())?;

    let stats = Arc::new(Stats {
        packets_logged: AtomicU64::new(0),
        bytes_processed: AtomicU64::new(0),
    });

    // Spawn async task for ring buffer polling
    let stats_clone = Arc::clone(&stats);
    let verbose = opt.verbose;
    let poll_interval_ms = opt.poll_interval_ms;

    let poll_task = task::spawn(async move {
        let mut interval = interval(Duration::from_millis(poll_interval_ms));

        loop {
            interval.tick().await;

            // Process all available events using the simplified .next() API
            while let Some(data) = ring_buf.next() {
                if data.len() == std::mem::size_of::<AuditEvent>() {
                    let event = unsafe {
                        std::ptr::read_unaligned(data.as_ptr() as *const AuditEvent)
                    };

                    stats_clone.packets_logged.fetch_add(1, Ordering::Relaxed);
                    stats_clone.bytes_processed.fetch_add(data.len() as u64, Ordering::Relaxed);

                    if verbose {
                        print_event(&event);
                    }
                }
            }
        }
    });

    // Statistics printer
    let stats_printer = {
        let stats = Arc::clone(&stats);
        task::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let packets = stats.packets_logged.load(Ordering::Relaxed);
                let bytes = stats.bytes_processed.load(Ordering::Relaxed);
                println!("📊 Stats: {} packets logged, {} bytes processed", packets, bytes);
            }
        })
    };

    println!("🔍 Monitoring active. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    signal::ctrl_c().await?;

    println!("\n🛑 Shutting down...");
    poll_task.abort();
    stats_printer.abort();

    let final_packets = stats.packets_logged.load(Ordering::Relaxed);
    println!("✓ Total packets logged: {}", final_packets);

    Ok(())
}

fn print_event(event: &AuditEvent) {
    let proto_name = match u16::from_be(event.eth_proto) {
        0x0800 => "IPv4",
        0x86DD => "IPv6",
        0x0806 => "ARP",
        _ => return, // Skip non-IP for brevity
    };

    let ip_proto_name = match event.ip_proto {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => "OTHER",
    };

    if event.src_port > 0 || event.dst_port > 0 {
        println!(
            "[{}] {} {} {} -> {}",
            event.timestamp_ns / 1_000_000,
            proto_name,
            ip_proto_name,
            event.src_port, // Already in host byte order from eBPF program
            event.dst_port  // Already in host byte order from eBPF program
        );
    } else {
        println!(
            "[{}] {} {}",
            event.timestamp_ns / 1_000_000,
            proto_name,
            ip_proto_name
        );
    }
}
