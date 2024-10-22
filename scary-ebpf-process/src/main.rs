#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::cty::c_void;
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_loop, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{btf_tracepoint, map, tracepoint},
    maps::{PerCpuArray, PerCpuHashMap, PerfEventArray, ProgramArray},
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use scary_ebpf_common::{
    bindings::{dentry, fs_struct, mount, qstr, task_struct},
    ArgBuffer, Event, EventData, SysEnterExecveArgs, ARGSBUFFER, COMM_SIZE, EVENT_DATA_ARGS,
    EVENT_ERROR_ARGS, EVENT_ERROR_CWD, MAXARGLENGTH, MAXARGS,
};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<EventData> = PerfEventArray::new(0);

#[map(name = "DATA_HEAP")]
static mut DATA_HEAP: PerCpuArray<EventData> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "PROCESS_CACHE")]
static mut PROCESS_CACHE: PerCpuHashMap<u32, Event> = PerCpuHashMap::with_max_entries(1024, 0);

#[map(name = "ARG_BUFFER")]
static mut ARG_BUFFER: PerCpuArray<ArgBuffer> = PerCpuArray::with_max_entries(1, 0);

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

    // Pass ctx to get_process_info for logging
    get_process_info(ctx, &mut data.event)?;

    // Read filename and arguments
    let args = ctx.as_ptr() as *const SysEnterExecveArgs;
    read_filename(ctx, args, &mut data.event)?;
    let _args_size = read_arguments(ctx, data)?;

    // Read current working directory
    match unsafe { read_cwd(&mut data.event.cwd) } {
        Ok(len) => {
            data.event.cwd_len = len as u32;
        }
        Err(_) => {
            data.event.flags |= EVENT_ERROR_CWD;
            data.event.cwd[0] = b'/';
            data.event.cwd_len = 1;
        }
    }

    unsafe {
        EVENTS.output(ctx, data, 0);
    }

    Ok(())
}

fn initialize_event_data(data: &mut EventData) {
    data.event = Event::default();
    data.args_read_result = 0;
    data.args.fill(0);
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
fn get_process_info(ctx: &TracePointContext, event: &mut Event) -> Result<(), u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.tid = pid_tgid as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

    let task = unsafe { bpf_get_current_task() as *const task_struct };
    event.ppid = get_parent_pid(task)?;

    if let Ok(current_comm) = bpf_get_current_comm() {
        event.comm.copy_from_slice(&current_comm);
    }

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
fn read_comm(
    ctx: &TracePointContext,
    _task: *const task_struct,
    comm: &mut [u8; COMM_SIZE],
) -> Result<(), u32> {
    match bpf_get_current_comm() {
        Ok(current_comm) => {
            comm.copy_from_slice(&current_comm);
            info!(ctx, "Command read via bpf_get_current_comm");
            for i in 0..COMM_SIZE {
                if comm[i] == 0 {
                    break;
                }
                info!(ctx, "byte[{}] = {}", i, comm[i]);
            }
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
fn read_filename(
    ctx: &TracePointContext,
    args: *const SysEnterExecveArgs,
    event: &mut Event,
) -> Result<(), u32> {
    let filename_ptr = unsafe { bpf_probe_read_kernel(&(*args).filename).map_err(|_| 1u32)? };

    let read_result = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };

    event.filename_read_result = match read_result {
        Ok(s) => {
            info!(ctx, "Read filename of length {}", s.len());
            s.len() as i64
        }
        Err(e) => {
            info!(ctx, "Failed to read filename: error {}", e);
            e
        }
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
fn read_arguments(ctx: &TracePointContext, data: &mut EventData) -> Result<u32, u32> {
    let args = ctx.as_ptr() as *const SysEnterExecveArgs;
    let argv_ptr = unsafe { bpf_probe_read_kernel(&(*args).argv).map_err(|_| 1u32)? };
    let mut total_size = 0;
    let mut arg_count = 0;

    for i in 0..MAXARGS {
        if total_size >= ARGSBUFFER - MAXARGLENGTH {
            info!(
                ctx,
                "total size {} is greater than args buffer - maxarglength {} {}",
                total_size,
                ARGSBUFFER,
                MAXARGLENGTH,
            );
            break;
        }

        let arg_ptr_ptr = unsafe { argv_ptr.add(i) };
        let arg_ptr = match unsafe { bpf_probe_read_user(arg_ptr_ptr) } {
            Ok(ptr) => ptr,
            Err(e) => {
                info!(ctx, "Failed to read arg_ptr_ptr[{}]: error {}", i, e);
                break;
            }
        };

        if arg_ptr.is_null() {
            info!(ctx, "arg_ptr_ptr[{}] is NULL, breaking", i);
            break;
        }

        let max_read_len = MAXARGLENGTH.min(ARGSBUFFER - total_size);

        // Add a null byte separator if this is not the first argument
        if arg_count > 0 {
            data.args[total_size] = 0;
            total_size += 1;
        }

        let dest_slice = &mut data.args[total_size..total_size + max_read_len];

        let read_result =
            unsafe { bpf_probe_read_user_str_bytes(arg_ptr as *const u8, dest_slice) };

        match read_result {
            Ok(s) => {
                let arg_len = s.len();
                info!(ctx, "Read arg[{}] of length {}", i, arg_len);
                if arg_len == 0 {
                    break;
                }
                total_size += arg_len;
                arg_count += 1;
            }
            Err(e) => {
                info!(ctx, "Failed to read arg[{}]: error {}", i, e);
                data.event.flags |= EVENT_ERROR_ARGS;
                break;
            }
        }
    }

    data.event.args_size = total_size as u32;
    data.args_read_result = total_size as i32;

    if arg_count == MAXARGS {
        data.event.flags |= EVENT_DATA_ARGS;
    }

    info!(
        ctx,
        "Total args read: {}, total size: {}", arg_count, total_size
    );

    Ok(total_size as u32)
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PathData {
    dentry: *mut dentry,
    buffer: *mut u8,
    offset: usize,
    max_len: usize,
}

#[no_mangle]
#[link_section = "classifier"]
static PROCESS_DENTRY: unsafe extern "C" fn(u32, *mut c_void) -> i32 = _process_dentry;

const MAX_NAME_LEN: usize = 32;

/// Process a single dentry in the path traversal
///
/// This function is called repeatedly by `bpf_loop` to traverse the directory structure
/// from the current working directory up to the root, building the full path along the way.
///
/// Kernel Directory Structure:
///
/// ```
///  +--------+     +--------+     +--------+
///  | dentry | --> | dentry | --> | dentry | --> ... --> (root)
///  +--------+     +--------+     +--------+
///      |              |              |
///      v              v              v
///   d_name         d_name         d_name
///   (file)         (dir2)         (dir1)
/// ```
///
/// Path Construction Process:
///
/// 1. Start from the deepest dentry (current directory)
/// 2. Read the name of the current dentry
/// 3. Prepend the name to the path buffer
/// 4. Move to the parent dentry
/// 5. Repeat steps 2-4 until reaching the root
///
/// Final Path Buffer:
///
/// ```
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// | / |dir1| / |dir2| / |file|    |   |   |   |   |   |   |   |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// ```
#[inline(always)]
unsafe extern "C" fn _process_dentry(idx: u32, data: *mut c_void) -> i32 {
    let path_data = &mut *(data as *mut PathData);

    if path_data.dentry.is_null() || path_data.offset >= path_data.max_len {
        return 1; // Stop loop
    }

    // Read the dentry's d_name
    let name = match bpf_probe_read_kernel(&(*path_data.dentry).d_name).map_err(|_| 1u32) {
        Ok(name) => name,
        Err(_) => return 1, // Stop on error
    };

    // Access the len field correctly
    let len_struct = name.__bindgen_anon_1.__bindgen_anon_1;
    let len = len_struct.len as usize;
    let len = len.min(MAX_NAME_LEN);

    let name_ptr = name.name;

    if len > 0 && path_data.offset + len + 1 <= path_data.max_len {
        // Add separator if not at the root
        if path_data.offset > 1 {
            *path_data.buffer.add(path_data.offset) = b'/';
            path_data.offset += 1;
        }

        // Read the directory name directly into the path buffer
        let dest_ptr = path_data.buffer.add(path_data.offset);

        // Use bpf_probe_read_kernel_buf to read into the buffer
        match bpf_probe_read_kernel_buf(name_ptr, core::slice::from_raw_parts_mut(dest_ptr, len)) {
            Ok(()) => {
                path_data.offset += len;
            }
            Err(_) => return 1, // Stop on error
        }
    }

    // Move to parent dentry
    let parent = match bpf_probe_read_kernel(&(*path_data.dentry).d_parent) {
        Ok(parent) => parent,
        Err(_) => return 1,
    };

    if parent as *const _ == path_data.dentry as *const _ {
        return 1; // Reached root, stop loop
    }

    path_data.dentry = parent;
    0 // Continue loop
}

/// Read the current working directory (CWD) of the process
///
/// This function traverses the directory structure from the current working directory
/// up to the root, building the full path along the way.
///
/// Kernel Structure and Path Traversal:
///
/// ```
///  +-------------+
///  | task_struct |
///  +-------------+
///  | fs    -------|---> +-----------+
///  +-------------+      | fs_struct |
///                       +-----------+
///                       | pwd       |
///                       +-----------+
///                             |
///                             v
///                        +---------+     +---------+     +---------+
///                        | dentry  | --> | dentry  | --> | dentry  | --> (root)
///                        +---------+     +---------+     +---------+
///                            |              |              |
///                            v              v              v
///                         d_name         d_name         d_name
///                         (file)         (dir2)         (dir1)
/// ```
///
/// Path Construction Process:
///
/// 1. Initialize the buffer with a root slash '/'
/// 2. Retrieve the current task's fs_struct
/// 3. Get the pwd (present working directory) dentry from fs_struct
/// 4. Use bpf_loop to call _process_dentry repeatedly, traversing up the directory structure
/// 5. Each iteration prepends the current directory name to the path
/// 6. Continue until reaching the root directory
///
/// Final Path Buffer:
///
/// ```
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// | / |dir1| / |dir2| / |file|    |   |   |   |   |   |   |   |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// ```
///
#[inline(always)]
unsafe fn read_cwd(buffer: &mut [u8]) -> Result<usize, i64> {
    // Start with root slash
    buffer[0] = b'/';
    let offset = 1;

    // Get current task and fs
    let task = bpf_get_current_task() as *const task_struct;
    let fs = bpf_probe_read_kernel(&(*task).fs)?;
    if fs.is_null() {
        return Ok(1);
    }

    // Get pwd dentry
    let dentry = bpf_probe_read_kernel(&(*fs).pwd.dentry)?;
    if dentry.is_null() {
        return Ok(1);
    }

    let mut path_data = PathData {
        dentry: dentry as *mut _,
        buffer: buffer.as_mut_ptr(),
        offset,
        max_len: buffer.len(),
    };

    // Use static function pointer
    let fn_ptr = _process_dentry as *mut c_void;
    let ret = bpf_loop(32, fn_ptr, &mut path_data as *mut _ as *mut c_void, 0);

    if ret < 0 {
        Err(ret)
    } else {
        Ok(path_data.offset)
    }
}

#[allow(dead_code)]
#[cfg_attr(not(test), panic_handler)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Safety: In eBPF programs, we can mark unreachable code paths using `unreachable_unchecked`.
    unsafe { core::hint::unreachable_unchecked() }
}
