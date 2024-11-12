use aya_ebpf::{
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};

use crate::{
    events::{
        listen::{ListenData, ListenEvent},
        Type,
    },
    maps::send,
};

#[kprobe(function = "__sys_listen")]
pub fn net_enter_sys_listen(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_listen(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_enter_sys_listen(ctx: &ProbeContext) -> Result<(), i32> {
    let sockfd = ctx.arg::<i32>(0).ok_or(1)?;
    let backlog = ctx.arg::<i32>(1).ok_or(1)?;

    let data = ListenData::new(sockfd, backlog);
    let event = ListenEvent::new(Type::Network, data);
    send(ctx, &event);

    Ok(())
}

#[kretprobe(function = "__sys_listen")]
pub fn net_exit_sys_listen(ctx: RetProbeContext) -> u32 {
    match try_net_exit_sys_listen(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_exit_sys_listen(ctx: &RetProbeContext) -> Result<(), i32> {
    let _rc = ctx.ret().unwrap_or(-1);
    Ok(())
}
