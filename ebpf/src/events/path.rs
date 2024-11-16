use aya_ebpf::helpers::{bpf_loop, bpf_probe_read_kernel, bpf_probe_read_kernel_buf};
use core::ffi::c_void;
use scary_ebpf_common::bindings::dentry;

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

#[inline(always)]
unsafe extern "C" fn _process_dentry(idx: u32, data: *mut c_void) -> i32 {
    let path_data = &mut *(data as *mut PathData);

    // Early bounds check
    if path_data.dentry.is_null() || path_data.offset >= path_data.max_len {
        return 1;
    }

    // Read dentry name
    let name = match bpf_probe_read_kernel(&(*path_data.dentry).d_name) {
        Ok(name) => name,
        Err(_) => return 1,
    };

    let len_struct = name.__bindgen_anon_1.__bindgen_anon_1;
    let component_len = (len_struct.len as usize).min(MAX_NAME_LEN);

    // Bounds check for component length
    if component_len == 0 || path_data.offset + component_len + 1 > path_data.max_len {
        return 1;
    }

    // Add separator if not at root
    if path_data.offset > 1 {
        *path_data.buffer.add(path_data.offset) = b'/';
        path_data.offset += 1;
    }

    // Copy component name
    if let Ok(()) = bpf_probe_read_kernel_buf(
        name.name,
        core::slice::from_raw_parts_mut(path_data.buffer.add(path_data.offset), component_len),
    ) {
        path_data.offset += component_len;
    } else {
        return 1;
    }

    // Move to parent
    let parent = match bpf_probe_read_kernel(&(*path_data.dentry).d_parent) {
        Ok(parent) => parent,
        Err(_) => return 1,
    };

    // Check if we've reached root
    if parent as *const _ == path_data.dentry as *const _ {
        return 1;
    }

    path_data.dentry = parent;
    0
}

pub struct PathBuilder;

impl PathBuilder {
    #[inline(always)]
    pub unsafe fn build_path(dentry: *mut dentry, buffer: &mut [u8]) -> Result<usize, i64> {
        if buffer.len() < 2 {
            return Ok(0);
        }

        // Initialize buffer with root slash
        buffer[0] = b'/';

        let mut path_data = PathData {
            dentry,
            buffer: buffer.as_mut_ptr(),
            offset: 1,
            max_len: buffer.len().min(128),
        };

        // Use a const 32-bit value for max iterations
        const MAX_ITERATIONS: u32 = 16;
        let fn_ptr = _process_dentry as *mut c_void;
        let ret = bpf_loop(
            MAX_ITERATIONS,
            fn_ptr,
            &mut path_data as *mut _ as *mut c_void,
            0,
        );

        if ret < 0 {
            Err(ret)
        } else {
            Ok(path_data.offset)
        }
    }
}
