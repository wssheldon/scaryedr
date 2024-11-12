#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use scary_ebpf_common::bindings::{dentry, file, inode, qstr};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct dentry_struct {
    pub d_inode: *const inode,
    pub d_name: qstr,
    pub d_parent: *const dentry,
}

#[map]
static mut WATCHED_INODES: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(1024, 0);

#[kprobe(function = "security_file_open")]
pub fn monitor_file_open(ctx: ProbeContext) -> u32 {
    match try_monitor_file_open(ctx) {
        Ok(_) => 0,
        Err(_) => 0, // Always return 0 to allow the syscall to proceed
    }
}

#[inline(always)]
fn get_comm_str(comm: &[u8; 16]) -> &[u8] {
    let mut len = 0;
    // Find null terminator or end of array
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    &comm[..len]
}

#[inline(always)]
fn check_inode(ctx: &ProbeContext, inode_number: u64, from_dentry: bool) -> Result<bool, i64> {
    // Create descriptive message for logging context
    let context_msg = if from_dentry { " (from dentry)" } else { "" };

    // Get current command name
    let comm = match bpf_get_current_comm() {
        Ok(comm_bytes) => comm_bytes,
        Err(_) => {
            info!(ctx, "Failed to read current comm");
            [0u8; 16]
        }
    };
    let comm_str = get_comm_str(&comm);

    // Check if inode is watched - this is safe since HashMap access is already safe in Aya
    if unsafe { WATCHED_INODES.get(&inode_number).is_some() } {
        // Get current PID/TGID - this helper is already safe
        let pid = bpf_get_current_pid_tgid() >> 32;

        info!(
            ctx,
            "File access detected {} - pid={}, inode={}", context_msg, pid, inode_number, comm_str
        );
        Ok(true)
    } else {
        Ok(false)
    }
}

#[inline(always)]
unsafe fn process_dentry(ctx: &ProbeContext, dentry_ptr: *mut dentry) -> Result<bool, i64> {
    if dentry_ptr.is_null() {
        info!(ctx, "Dentry pointer is NULL.");
        return Ok(false);
    }

    // Read d_inode from dentry
    let d_inode_ptr: *mut inode = bpf_probe_read_kernel(&(*dentry_ptr).d_inode)?;
    if d_inode_ptr.is_null() {
        info!(ctx, "d_inode pointer is NULL in dentry.");
        return Ok(false);
    }

    // Read i_ino from inode
    let inode_number = bpf_probe_read_kernel(&(*d_inode_ptr).i_ino)?;

    // Log the inode number extracted from dentry
    // info!(ctx, "Extracted inode number from dentry: {}", inode_number);

    check_inode(ctx, inode_number, true)
}

fn try_monitor_file_open(ctx: ProbeContext) -> Result<(), i64> {
    let file_ptr = ctx.arg::<*const file>(0).ok_or(1)?;
    if file_ptr.is_null() {
        info!(&ctx, "file_ptr is NULL.");
        return Err(1);
    }

    unsafe {
        // Read the file structure's f_inode pointer
        let f_inode_ptr: *const inode = bpf_probe_read_kernel(&(*file_ptr).f_inode)?;
        if f_inode_ptr.is_null() {
            info!(&ctx, "f_inode_ptr is NULL.");
        } else {
            // Read i_ino from f_inode
            let inode_number = bpf_probe_read_kernel(&(*f_inode_ptr).i_ino)?;

            // Log the inode_number extracted from f_inode
            // info!(
            //     &ctx,
            //     "Extracted inode_number from f_inode: {}", inode_number
            // );

            if check_inode(&ctx, inode_number, false)? {
                return Ok(());
            }
        }

        // Read dentry pointer from f_path.dentry
        let dentry_ptr: *mut dentry = bpf_probe_read_kernel(&(*file_ptr).f_path.dentry)?;
        if dentry_ptr.is_null() {
            info!(&ctx, "f_path.dentry is NULL.");
        } else {
            if process_dentry(&ctx, dentry_ptr)? {
                return Ok(());
            }
        }
    }

    Ok(())
}

#[allow(dead_code)]
#[cfg_attr(not(test), panic_handler)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
