#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    EbpfContext,
};

const COMM_SIZE: usize = 16;
const FILENAME_SIZE: usize = 256;

#[repr(C)]
pub struct Event {
    pid: u32,
    comm: [u8; COMM_SIZE],
    filename: [u8; FILENAME_SIZE],
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[tracepoint(name = "sys_enter_openat")]
pub fn tracepoint_open(ctx: TracePointContext) -> u32 {
    match unsafe { try_tracepoint_open(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_tracepoint_open(ctx: &TracePointContext) -> Result<u32, u32> {
    // Prepare event structure
    let mut event = Event {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        comm: [0; COMM_SIZE],
        filename: [0; FILENAME_SIZE],
    };

    // Read the command name (comm) of the current process
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm.copy_from_slice(&comm);
    }

    // Read the filename from the system call arguments (second argument is the filename pointer)
    let filename_ptr = ctx.read_at::<*const u8>(1).map_err(|_| 1u32)?;
    if let Ok(filename) = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) {
        event.filename[..filename.len()].copy_from_slice(&filename);
    }

    // Output the event to the user-space perf event array
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

#[cfg_attr(not(test), panic_handler)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
