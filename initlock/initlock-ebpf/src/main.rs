#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;
use vmlinux::{ethhdr, iphdr};

// Ethernet protocol types (big-endian)
const ETH_P_IP: u16 = 0x0008;   // IPv4
const ETH_P_IPV6: u16 = 0xDD86; // IPv6

// IP protocol numbers
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
struct AuditEvent {
    timestamp_ns: u64,
    eth_proto: u16,
    ip_proto: u8,
    src_port: u16,
    dst_port: u16,
    action: u8,
    _padding: [u8; 4], // Align to 8 bytes
}

// 512KB Ring Buffer (0.05% of 1GB RAM)
#[map]
static PACKET_LOG: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

#[xdp]
pub fn initlock_xdp(ctx: XdpContext) -> u32 {
    match try_initlock_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS, // Fail open for audit mode
    }
}
fn try_initlock_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    
    // Bounds check: Ethernet header
    if data + core::mem::size_of::<ethhdr>() > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    
    let eth = unsafe { &*(data as *const ethhdr) };
    let eth_proto = unsafe { core::ptr::read_unaligned(&eth.h_proto) };
    
    let mut event = AuditEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        eth_proto,
        ip_proto: 0,
        src_port: 0,
        dst_port: 0,
        action: xdp_action::XDP_PASS as u8,
        _padding: [0; 4],
    };
    
    // Parse IP layer if present
    if eth_proto == ETH_P_IP {
        let ip_offset = data + core::mem::size_of::<ethhdr>();
        if ip_offset + core::mem::size_of::<iphdr>() <= data_end {
            let iph = unsafe { &*(ip_offset as *const iphdr) };
            event.ip_proto = unsafe { core::ptr::read_unaligned(&iph.protocol) };
            
            // FIX: Handle Bitfield Safely
            // _bitfield_1 is a BindgenBitfieldUnit. accessing it directly is hard.
            // But standard IPv4 header length (IHL) is the lower 4 bits of the first byte.
            // We can just read the byte directly.
            let ver_ihl = unsafe { *(ip_offset as *const u8) };
            let ihl = (ver_ihl & 0x0F) as usize * 4;
            
            let l4_offset = ip_offset + ihl;
            
            if l4_offset + 4 <= data_end { 
                match event.ip_proto {
                    IPPROTO_TCP | IPPROTO_UDP => {
                        let ports = unsafe { &*(l4_offset as *const [u16; 2]) };
                        event.src_port = u16::from_be(unsafe { core::ptr::read_unaligned(&ports[0]) });
                        event.dst_port = u16::from_be(unsafe { core::ptr::read_unaligned(&ports[1]) });
                    }
                    _ => {}
                }
            }
        }
    }
    
    if let Some(mut entry) = PACKET_LOG.reserve::<AuditEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
    
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
