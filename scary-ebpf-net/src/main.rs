#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[derive(Default)]
#[repr(C)]
struct ConnectionInfo {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u32,
}

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr = unsafe { ptr_at::<EthHdr>(&ctx, 0)?.as_ref() }.ok_or(())?;

    match (*ethhdr).ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?.as_ref() }.ok_or(())?;
    let source_ip = u32::from_be(ipv4hdr.src_addr);
    let dest_ip = u32::from_be(ipv4hdr.dst_addr);
    let protocol = ipv4hdr.proto;

    let mut conn_info = ConnectionInfo {
        src_ip: source_ip,
        dst_ip: dest_ip,
        src_port: 0,
        dst_port: 0,
        protocol: protocol as u8,
        action: xdp_action::XDP_PASS,
    };

    let transport_header_offset = EthHdr::LEN + mem::size_of::<Ipv4Hdr>();

    match protocol {
        IpProto::Tcp => {
            if let Ok(tcphdr) = ptr_at::<TcpHdr>(&ctx, transport_header_offset) {
                conn_info.src_port = u16::from_be(unsafe { (*tcphdr).source });
                conn_info.dst_port = u16::from_be(unsafe { (*tcphdr).dest });
            }
        }
        IpProto::Udp => {
            if let Ok(udphdr) = ptr_at::<UdpHdr>(&ctx, transport_header_offset) {
                conn_info.src_port = u16::from_be(unsafe { (*udphdr).source });
                conn_info.dst_port = u16::from_be(unsafe { (*udphdr).dest });
            }
        }
        _ => {}
    }

    conn_info.action = if block_ip(source_ip) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    log_connection_info(&ctx, &conn_info);
    Ok(conn_info.action)
}

const fn ip_to_array(ip: u32) -> [u8; 4] {
    [
        (ip >> 24) as u8,
        (ip >> 16) as u8,
        (ip >> 8) as u8,
        ip as u8,
    ]
}

fn log_connection_info(ctx: &XdpContext, info: &ConnectionInfo) {
    let src_ip = ip_to_array(info.src_ip);
    let dst_ip = ip_to_array(info.dst_ip);
    info!(
        ctx,
        "{{\"src_ip\": \"{}.{}.{}.{}\", \"dst_ip\": \"{}.{}.{}.{}\", \"src_port\": {}, \"dst_port\": {}, \"protocol\": {}, \"action\": {}}}",
        src_ip[0], src_ip[1], src_ip[2], src_ip[3],
        dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
        info.src_port,
        info.dst_port,
        info.protocol,
        info.action
    );
}

#[cfg_attr(not(test), panic_handler)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
