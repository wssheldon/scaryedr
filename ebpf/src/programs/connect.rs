use aya_ebpf::{
    helpers::bpf_probe_read_user,
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;

use crate::{
    events::{
        connect::{ConnectData, ConnectEvent, IpAddr},
        Type,
    },
    maps::send,
};
use scary_ebpf_common::bindings::{sa_family_t, sockaddr, sockaddr_in};

const AF_INET: i32 = 2;

#[kprobe(function = "__sys_connect")]
pub fn net_enter_sys_connect(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_connect(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_enter_sys_connect(ctx: &ProbeContext) -> Result<(), i32> {
    let sockfd = ctx.arg::<i32>(0).ok_or(1)?;
    let sockaddr_ptr: *const sockaddr = ctx.arg::<*const sockaddr>(1).ok_or(1)?;

    unsafe {
        // Convert error to i32
        let sa_family = match bpf_probe_read_user(&(*sockaddr_ptr).sa_family) {
            Ok(family) => family,
            Err(_) => return Err(1),
        };

        if sa_family as i32 != AF_INET {
            return Ok(());
        }

        // Convert error to i32
        let addr_in = match bpf_probe_read_user(sockaddr_ptr as *const sockaddr_in) {
            Ok(addr) => addr,
            Err(_) => return Err(1),
        };

        let addr = u32::from_be(addr_in.sin_addr.s_addr);
        let port = u16::from_be(addr_in.sin_port);

        // Log for debugging
        info!(
            ctx,
            "CONNECT: addr={}.{}.{}.{} port={}",
            (addr >> 24) & 0xff,
            (addr >> 16) & 0xff,
            (addr >> 8) & 0xff,
            addr & 0xff,
            port
        );

        let mut data = ConnectData::new(sockfd, sa_family as u16);
        data.dst_addr = IpAddr::from_be_u32(addr);
        data.dst_port = port;

        // Create and send event
        let event = ConnectEvent::new(Type::Network, data);
        send(ctx, &event);
    }

    Ok(())
}

#[kretprobe(function = "__sys_connect")]
pub fn net_exit_sys_connect(ctx: RetProbeContext) -> u32 {
    match try_net_exit_sys_connect(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_exit_sys_connect(ctx: &RetProbeContext) -> Result<(), i32> {
    let _rc = ctx.ret().unwrap_or(-1);
    Ok(())
}
