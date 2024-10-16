#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{lsm, map},
    maps::PerfEventArray,
    programs::LsmContext,
};
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::file;

const COMM_SIZE: usize = 16;

#[repr(C)]
pub struct Event {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: [u8; COMM_SIZE],
    inode_number: u64,
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[lsm(hook = "monitor_file_open")]
pub fn monitor_file_open(ctx: LsmContext) -> i32 {
    match unsafe { try_monitor_file_open(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_monitor_file_open(ctx: &LsmContext) -> Result<i32, i32> {
    let file_ptr: *const file = ctx.arg::<*const file>(0);
    if file_ptr.is_null() {
        info!(ctx, "File pointer is null, skipping...");
        return Err(1);
    }
    let inode_ptr = (*file_ptr).f_inode;

    if inode_ptr.is_null() {
        info!(ctx, "Inode pointer is null, skipping...");
        return Ok(0);
    }

    let inode_number = (*inode_ptr).i_ino;
    info!(ctx, "Inode number: {}", inode_number);

    // Replace with the actual inode number of the file you want to monitor
    const TARGET_INODE_NUMBER: u64 = 3621;

    if inode_number != TARGET_INODE_NUMBER {
        info!(ctx, "Not monitoring this inode: {}", inode_number);
        return Ok(0);
    }

    let mut event = Event {
        pid: 0,
        uid: 0,
        gid: 0,
        comm: [0; COMM_SIZE],
        inode_number,
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

    match bpf_get_current_comm() {
        Ok(comm) => event.comm = comm,
        Err(_) => {
            info!(ctx, "Failed to get current comm");
            return Err(1);
        }
    }

    info!(
        ctx,
        "Event: pid={}, uid={}, gid={}, inode={}",
        event.pid,
        event.uid,
        event.gid,
        event.inode_number
    );

    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

#[cfg_attr(not(test), panic_handler)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Safety: In eBPF programs, we can mark unreachable code paths using `unreachable_unchecked`.
    unsafe { core::hint::unreachable_unchecked() }
}
