use crate::events::ssl::{SslData, SslEvent, MAX_BUF_SIZE};
use crate::maps::send;
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray},
    programs::{ProbeContext, RetProbeContext},
};

#[map]
static mut STORAGE: PerCpuArray<SslEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut BUFFERS: HashMap<u32, *const u8> = HashMap::with_max_entries(1024, 0);

#[uprobe]
pub fn ssl_read(ctx: ProbeContext) -> u32 {
    match try_ssl_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match try_ssl_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) -> u32 {
    match try_ssl_exit(ctx, 0) {
        // 0 = read
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_write_ret(ctx: RetProbeContext) -> u32 {
    match try_ssl_exit(ctx, 1) {
        // 1 = write
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_entry(ctx: ProbeContext) -> Result<u32, u32> {
    // Get the thread group ID and buffer pointer
    let tgid = bpf_get_current_pid_tgid() as u32;
    let buf_ptr: *const u8 = match ctx.arg(1) {
        Some(ptr) => ptr,
        None => return Err(1),
    };

    unsafe {
        match BUFFERS.insert(&tgid, &buf_ptr, 0) {
            Ok(_) => Ok(0),
            Err(_) => Err(2),
        }
    }
}

fn try_ssl_exit(ctx: RetProbeContext, kind: u32) -> Result<u32, u32> {
    let bytes: i32 = match ctx.ret() {
        Some(b) => b,
        None => return Err(1),
    };

    if bytes <= 0 {
        return Ok(0);
    }

    let tgid = bpf_get_current_pid_tgid() as u32;

    let buf_ptr = unsafe {
        match BUFFERS.get(&tgid) {
            Some(ptr) => *ptr,
            None => return Ok(0),
        }
    };

    let event = unsafe {
        match STORAGE.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return Err(2),
        }
    };

    // Initialize the data portion
    let data = &mut event.data;
    data.kind = kind;
    data.len = bytes;
    data.comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => return Err(3),
    };

    // Read the SSL data
    let read_len = if bytes > MAX_BUF_SIZE as i32 {
        MAX_BUF_SIZE as u32
    } else {
        bytes as u32
    };

    unsafe {
        match bpf_probe_read_user(buf_ptr as *const [u8; MAX_BUF_SIZE]) {
            Ok(buf) => data.buf = buf,
            Err(_) => return Err(4),
        }

        // Clean up the saved buffer pointer
        match BUFFERS.remove(&tgid) {
            Ok(_) => (),
            Err(_) => return Err(5),
        }

        // Send event using the new send function
        send(&ctx, event);
    }

    Ok(0)
}
