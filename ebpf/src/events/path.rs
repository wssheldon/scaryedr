use aya_ebpf::{
    check_bounds_signed,
    helpers::{
        bpf_loop, bpf_probe_read_kernel, bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes,
    },
};
use core::ffi::c_void;
use scary_ebpf_common::bindings::dentry;

#[repr(C)]
#[derive(Copy, Clone)]
struct PathData {
    dentry: *mut dentry,
    buffer: *mut u8,
    offset: u16,  // Changed to u16 for better bounds tracking
    max_len: u16, // Changed to u16 for better bounds tracking
}

const MAX_NAME_LEN: usize = 32;

#[repr(C)]
pub struct PathInfo {
    data: [u8; 64],
    len: u16,
}

impl PathInfo {
    #[inline(always)]
    pub fn empty() -> Self {
        Self {
            data: [0; 64],
            len: 0,
        }
    }

    #[inline(always)]
    pub fn copy_to_slice(&self, dest: &mut [u8]) -> u16 {
        let len = (self.len as usize).min(dest.len()).min(64);

        // Copy in fixed 16-byte chunks
        let chunks = len / 16;
        for i in 0..4 {
            // Max 4 chunks (64 bytes total)
            if i >= chunks {
                break;
            }
            let offset = i * 16;
            if offset + 16 <= len {
                dest[offset..offset + 16].copy_from_slice(&self.data[offset..offset + 16]);
            }
        }

        len as u16
    }
}

#[no_mangle]
#[link_section = "classifier"]
static PROCESS_DENTRY: unsafe extern "C" fn(u32, *mut c_void) -> i32 = _process_dentry;

#[inline(always)]
unsafe extern "C" fn _process_dentry(idx: u32, data: *mut c_void) -> i32 {
    let path_data = &mut *(data as *mut PathData);

    // Early bounds check
    if path_data.dentry.is_null()
        || !check_bounds_signed(path_data.offset as i64, 0, path_data.max_len as i64)
    {
        return 1;
    }

    // Read dentry name
    let name = match bpf_probe_read_kernel(&(*path_data.dentry).d_name) {
        Ok(name) => name,
        Err(_) => return 1,
    };

    let len_struct = name.__bindgen_anon_1.__bindgen_anon_1;
    let component_len = (len_struct.len as u16).min(32);

    // Bounds check
    if component_len == 0
        || !check_bounds_signed(
            (path_data.offset + component_len + 1) as i64,
            0,
            path_data.max_len as i64,
        )
    {
        return 1;
    }

    // Add separator if not at root
    if path_data.offset > 1 {
        *path_data.buffer.add(path_data.offset as usize) = b'/';
        path_data.offset += 1;
    }

    // Copy name in small chunks
    let mut copied: u16 = 0;
    while copied < component_len {
        let chunk_size = (component_len - copied).min(4);
        if let Ok(()) = bpf_probe_read_kernel_buf(
            name.name.add(copied as usize),
            core::slice::from_raw_parts_mut(
                path_data.buffer.add((path_data.offset + copied) as usize),
                chunk_size as usize,
            ),
        ) {
            copied += chunk_size;
        } else {
            return 1;
        }
    }

    path_data.offset += component_len;

    // Move to parent
    let parent = match bpf_probe_read_kernel(&(*path_data.dentry).d_parent) {
        Ok(parent) => parent,
        Err(_) => return 1,
    };

    if parent as *const _ == path_data.dentry as *const _ {
        return 1;
    }

    path_data.dentry = parent;
    0
}

pub struct PathBuilder;

impl PathBuilder {
    #[inline(always)]
    pub unsafe fn build_path(dentry: *mut dentry) -> Result<PathInfo, i64> {
        let mut path_info = PathInfo::empty();

        // Initialize with root slash
        path_info.data[0] = b'/';
        path_info.len = 1;

        let mut current = dentry;

        // Limited depth to keep program small
        for depth in 0..3 {
            if current.is_null() {
                break;
            }

            let name = match bpf_probe_read_kernel(&(*current).d_name) {
                Ok(name) => name,
                Err(_) => break,
            };

            // Read component with fixed size
            let mut temp_buf = [0u8; 16];
            if let Ok(component) = bpf_probe_read_kernel_str_bytes(name.name, &mut temp_buf) {
                if component.is_empty() {
                    break;
                }

                // Conservative length limit
                let comp_len = component.len().min(16);
                if path_info.len as usize + comp_len + 1 >= 63 {
                    break;
                }

                // Add separator
                if path_info.len > 1 {
                    path_info.data[path_info.len as usize] = b'/';
                    path_info.len += 1;
                }

                // Copy in fixed 8-byte chunks
                let chunks = (comp_len + 7) / 8;
                for i in 0..2 {
                    // Max 2 chunks (16 bytes)
                    if i >= chunks {
                        break;
                    }
                    let src_off = i * 8;
                    let dst_off = path_info.len as usize;
                    let remaining = comp_len - src_off;
                    let chunk_size = remaining.min(8);

                    if dst_off + chunk_size < 64 {
                        path_info.data[dst_off..dst_off + chunk_size]
                            .copy_from_slice(&component[src_off..src_off + chunk_size]);
                        path_info.len += chunk_size as u16;
                    }
                }
            }

            let parent = bpf_probe_read_kernel(&(*current).d_parent)?;
            if parent.is_null() || parent as *const _ == current as *const _ {
                break;
            }
            current = parent;
        }

        Ok(path_info)
    }
}
