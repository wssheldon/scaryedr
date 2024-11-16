use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_loop, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::kprobe,
    programs::ProbeContext,
};
use core::ffi::c_void;
use scary_ebpf_common::bindings::{dentry, task_struct};

use crate::{
    events::{
        execve::{ExecveData, ExecveEvent},
        Type,
    },
    maps::send,
};

// #[kprobe(function = "__do_execve")]
// pub fn exec_enter(ctx: ProbeContext) -> u32 {
//     match try_exec_enter(&ctx) {
//         Ok(_) => 0,
//         Err(_) => 1,
//     }
// }

// #[inline(always)]
// fn try_exec_enter(ctx: &ProbeContext) -> Result<(), i64> {
//     // Get syscall arguments
//     let filename_ptr: *const u8 = ctx.arg(0).ok_or(-1)?;
//     let argv_ptr: *const *const u8 = ctx.arg(1).ok_or(-1)?;

//     // Initialize execve data
//     let mut data = ExecveData::new();

//     // Get process info
//     get_process_info(&mut data)?;

//     // Read filename and args
//     read_filename(filename_ptr, &mut data)?;
//     read_arguments(argv_ptr, &mut data)?;

//     // Create and send event
//     let _ = ExecveEvent::new(Type::Process, data);
//     // send(ctx, &event);

//     Ok(())
// }

#[inline(always)]
fn get_process_info(data: &mut ExecveData) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    data.pid = (pid_tgid >> 32) as u32;
    data.tid = pid_tgid as u32;

    let uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid as u32;
    data.gid = (uid_gid >> 32) as u32;

    // Get parent PID
    let task = unsafe { bpf_get_current_task() as *const task_struct };
    let parent = unsafe { bpf_probe_read_kernel(&(*task).parent).map_err(|e| e)? };
    data.ppid = unsafe { bpf_probe_read_kernel(&(*parent).tgid).map_err(|e| e)? } as u32;

    // Get comm
    if let Ok(current_comm) = bpf_get_current_comm() {
        data.comm.copy_from_slice(&current_comm);
    }

    Ok(())
}

#[inline(always)]
fn read_filename(filename_ptr: *const u8, data: &mut ExecveData) -> Result<(), i64> {
    unsafe {
        let filename_bytes = bpf_probe_read_user_str_bytes(filename_ptr, &mut data.filename)?;
        data.filename_len = filename_bytes.len() as u32;
    }
    Ok(())
}

#[inline(always)]
fn read_arguments(argv_ptr: *const *const u8, data: &mut ExecveData) -> Result<(), i64> {
    let mut offset = 0;
    const MAX_ARGS: usize = 20;

    // Skip first arg (binary name)
    for i in 1..MAX_ARGS {
        if offset >= data.args.len() - 256 {
            data.truncated = true;
            break;
        }

        let arg_ptr = unsafe {
            let ptr_ptr = argv_ptr.add(i);
            bpf_probe_read_user(ptr_ptr).map_err(|e| e)?
        };

        if arg_ptr.is_null() {
            break;
        }

        // Add separator if not first arg
        if i > 1 {
            data.args[offset] = b' ';
            offset += 1;
        }

        // Read argument
        let bytes = unsafe {
            let dest = &mut data.args[offset..];
            bpf_probe_read_user_str_bytes(arg_ptr, dest)?
        };

        offset += bytes.len();
        data.args_count += 1;
    }

    data.args_len = offset as u32;
    Ok(())
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PathData {
    dentry: *mut dentry,
    buffer: *mut u8,
    offset: usize,
    max_len: usize,
}

// #[no_mangle]
// #[link_section = "classifier"]
// static PROCESS_DENTRY: unsafe extern "C" fn(u32, *mut c_void) -> i32 = _process_dentry;

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
