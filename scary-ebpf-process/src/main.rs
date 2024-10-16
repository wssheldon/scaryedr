#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, PerCpuHashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};

use scary_ebpf_common::bindings::task_struct;
use scary_ebpf_common::{Event, COMM_SIZE};

const MAX_ARGS: usize = 10;
const ARG_BUF_SIZE: usize = 64;

#[repr(C)]
pub struct SysEnterExecveArgs {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub __syscall_nr: i32,
    pub filename: *const u8,
    pub argv: *const *const u8,
    pub envp: *const *const u8,
}

#[repr(C)]
pub struct EventData {
    pub event: Event,
    pub args: [[u8; ARG_BUF_SIZE]; MAX_ARGS],
    pub args_read_result: i32,
}

impl Default for EventData {
    fn default() -> Self {
        EventData {
            event: Event::default(),
            args: [[0; ARG_BUF_SIZE]; MAX_ARGS],
            args_read_result: 0,
        }
    }
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<EventData> = PerfEventArray::new(0);

#[map(name = "DATA_HEAP")]
static mut DATA_HEAP: PerCpuArray<EventData> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "PROCESS_CACHE")]
static mut PROCESS_CACHE: PerCpuHashMap<u32, Event> = PerCpuHashMap::with_max_entries(1024, 0);

#[tracepoint(name = "handle_exec", category = "syscalls")]
pub fn handle_exec(ctx: TracePointContext) -> u32 {
    match try_handle_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_handle_exec(ctx: &TracePointContext) -> Result<(), u32> {
    // Get a mutable reference to EventData from the PerCpuArray
    let data = unsafe {
        match DATA_HEAP.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return Err(1),
        }
    };

    // Initialize EventData
    initialize_event_data(data);

    get_process_info(&mut data.event)?;

    // Read filename and arguments
    let args = ctx.as_ptr() as *const SysEnterExecveArgs;
    if read_filename(args, &mut data.event).is_err() {
        return Err(1);
    }
    if read_arguments(args, &mut data.args, &mut data.args_read_result).is_err() {
        return Err(1);
    }

    // Output the event data to user space
    unsafe {
        EVENTS.output(ctx, data, 0);
    }

    Ok(())
}

fn initialize_event_data(data: &mut EventData) {
    data.event = Event::default();
    data.args_read_result = 0;
    for arg in data.args.iter_mut() {
        *arg = [0; ARG_BUF_SIZE];
    }
}

/// Get process IDs and parent PID
///
/// Kernel Structure:
/// ```
///  +-----------------+
///  |   task_struct   |
///  +-----------------+
///  | pid             | <-- bpf_get_current_pid_tgid()
///  | tgid            | <-- bpf_get_current_pid_tgid()
///  | uid             | <-- bpf_get_current_uid_gid()
///  | gid             | <-- bpf_get_current_uid_gid()
///  | parent  --------|---> +-----------------+
///  | comm            |     |   task_struct   |
///  +-----------------+     +-----------------+
///                          | tgid            | <-- Parent PID
///                          +-----------------+
/// ```
#[inline(always)]
fn get_process_info(event: &mut Event) -> Result<(), u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if let Some(cached_event) = unsafe { PROCESS_CACHE.get(&pid) } {
        *event = *cached_event;
        return Ok(());
    }

    let uid_gid = bpf_get_current_uid_gid();
    event.pid = pid;
    event.tid = pid_tgid as u32;
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

    let task = unsafe { bpf_get_current_task() as *const task_struct };
    event.ppid = get_parent_pid(task)?;
    read_comm(task, &mut event.comm)?;

    unsafe {
        let _ = PROCESS_CACHE.insert(&pid, event, 0);
    };
    Ok(())
}

/// Read the parent PID
///
/// Kernel Structure:
/// ```
///  +-----------------+
///  |   task_struct   |
///  +-----------------+
///  | parent  --------|---> +-----------------+
///  +-----------------+     |   task_struct   |
///                          +-----------------+
///                          | tgid            | <-- We read this value
///                          +-----------------+
/// ```
#[inline(always)]
fn get_parent_pid(task: *const task_struct) -> Result<u32, u32> {
    unsafe {
        let parent = bpf_probe_read_kernel(&(*task).parent).map_err(|_| 1u32)?;
        let tgid = bpf_probe_read_kernel(&(*parent).tgid).map_err(|_| 1u32)?;
        Ok(tgid as u32)
    }
}

/// Read the process name (comm)
///
/// Kernel Structure:
/// ```
///  +-----------------+
///  |   task_struct   |
///  +-----------------+
///  | comm            | <-- We read this array
///  | [0..16]         |
///  +-----------------+
/// ```
#[inline(always)]
fn read_comm(_task: *const task_struct, comm: &mut [u8; COMM_SIZE]) -> Result<(), u32> {
    match bpf_get_current_comm() {
        Ok(current_comm) => {
            comm.copy_from_slice(&current_comm);
            Ok(())
        }
        Err(_) => Err(1),
    }
}

/// Read the filename from user space
///
/// Syscall Arguments Structure:
/// ```
///  +------------------------+
///  |   SysEnterExecveArgs   |
///  +------------------------+
///  | filename   ------------|---> +-------------------+
///  | argv                   |     | User space memory |
///  | envp                   |     +-------------------+
///  +------------------------+     | filename string   | <-- We read this
///                                 +-------------------+
/// ```
#[inline(always)]
fn read_filename(args: *const SysEnterExecveArgs, event: &mut Event) -> Result<(), u32> {
    let filename_ptr = unsafe { (*args).filename };

    let filename_read_result =
        unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };

    event.filename_read_result = match filename_read_result {
        Ok(slice) => slice.len() as i64,
        Err(e) => e,
    };
    Ok(())
}

/// Read the arguments from user space
///
/// Syscall Arguments Structure:
/// ```
///  +------------------------+
///  |   SysEnterExecveArgs   |
///  +------------------------+
///  | filename               |
///  | argv         ----------|---> +-------------------+
///  | envp                   |     | User space memory |
///  +------------------------+     +-------------------+
///                                 | arg0 ptr   -------|---> "arg0 string"
///                                 | arg1 ptr   -------|---> "arg1 string"
///                                 | arg2 ptr   -------|---> "arg2 string"
///                                 | ...               |
///                                 +-------------------+
/// ```
#[inline(always)]
fn read_arguments(
    args: *const SysEnterExecveArgs,
    data_args: &mut [[u8; ARG_BUF_SIZE]; MAX_ARGS],
    args_read_result: &mut i32,
) -> Result<(), u32> {
    let argv_ptr = unsafe { (*args).argv };
    let mut total_len = 0;

    for (i, arg_buf) in data_args.iter_mut().enumerate() {
        let arg_ptr_ptr = unsafe { argv_ptr.add(i) };
        let arg_ptr = match unsafe { bpf_probe_read_user(arg_ptr_ptr) } {
            Ok(ptr) => ptr,
            Err(_) => break,
        };
        if arg_ptr.is_null() {
            break;
        }
        match unsafe { bpf_probe_read_user_str_bytes(arg_ptr, arg_buf) } {
            Ok(slice) => {
                total_len += slice.len();
            }
            Err(_) => break,
        }
    }
    *args_read_result = total_len as i32;
    Ok(())
}

#[cfg_attr(not(test), panic_handler)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Safety: In eBPF programs, we can mark unreachable code paths using `unreachable_unchecked`.
    unsafe { core::hint::unreachable_unchecked() }
}
