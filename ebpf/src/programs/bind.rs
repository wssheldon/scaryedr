use aya_ebpf::{
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};

use crate::{
    events::{
        bind::{BindData, BindEvent},
        Type,
    },
    maps::send,
};
use scary_ebpf_common::bindings::sockaddr;

#[kprobe(function = "__sys_bind")]
pub fn net_enter_sys_bind(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_bind(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_net_enter_sys_bind(ctx: &ProbeContext) -> Result<(), i64> {
    // Get syscall arguments
    let sock_fd = ctx.arg(0).ok_or(-1)?;
    let sockaddr_ptr: *const sockaddr = ctx.arg(1).ok_or(-1)?;

    // Initialize bind data
    let mut data = BindData::new(sock_fd);
    data.socket_mut().read_sockaddr(sockaddr_ptr)?;

    // Create and send event
    let event = BindEvent::new(Type::Network, data);
    send(ctx, &event);

    Ok(())
}

#[kretprobe(function = "__sys_bind")]
pub fn net_exit_sys_bind(ctx: RetProbeContext) -> u32 {
    match try_net_exit_sys_bind(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_exit_sys_bind(ctx: &RetProbeContext) -> Result<(), i32> {
    let _rc = ctx.ret().unwrap_or(-1);
    Ok(())
}
