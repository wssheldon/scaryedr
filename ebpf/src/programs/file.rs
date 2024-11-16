use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{kprobe, map},
    maps::{LruHashMap, PerCpuArray},
    programs::ProbeContext,
};

use crate::{
    events::{file::FileData, path::PathBuilder, Event, Type},
    maps::send,
};

use scary_ebpf_common::bindings::{dentry, file, inode};

#[map(name = "INODE_TRACKING")]
static mut INODE_TRACKING: LruHashMap<u64, u32> = LruHashMap::with_max_entries(0x1ffff, 0);

#[map(name = "FILE_EVENT_BUFFER")]
static mut FILE_EVENT_BUFFER: PerCpuArray<Event<FileData>> = PerCpuArray::with_max_entries(1, 0);

#[repr(transparent)]
struct FileRef(*const file);

impl FileRef {
    #[inline(always)]
    fn from_context(ctx: &ProbeContext) -> Result<Option<Self>, i64> {
        let file_ptr = ctx.arg::<*const file>(0).ok_or(1)?;
        if file_ptr.is_null() {
            return Ok(None);
        }
        Ok(Some(Self(file_ptr)))
    }

    #[inline(always)]
    fn get_inode(&self) -> Result<Option<InodeRef>, i64> {
        let f_inode_ptr: *const inode = unsafe { bpf_probe_read_kernel(&(*self.0).f_inode)? };
        if f_inode_ptr.is_null() {
            return Ok(None);
        }
        Ok(Some(InodeRef(f_inode_ptr)))
    }

    #[inline(always)]
    fn track_inode(&self, inode: u64) -> Result<bool, i64> {
        let tracking = &raw mut INODE_TRACKING;
        unsafe {
            if let Some(_) = (*tracking).get(&inode) {
                Ok(true)
            } else {
                (*tracking)
                    .insert(&inode, &1, 0) // Use 1 as a simple flag
                    .map(|_| true)
                    .map_err(|_| -1)
            }
        }
    }

    #[inline(always)]
    fn get_dentry_inode(&self) -> Result<Option<InodeRef>, i64> {
        unsafe {
            let dentry_ptr: *const dentry = bpf_probe_read_kernel(&(*self.0).f_path.dentry)?;
            if dentry_ptr.is_null() {
                return Ok(None);
            }

            let d_inode_ptr: *const inode = bpf_probe_read_kernel(&(*dentry_ptr).d_inode)?;
            if d_inode_ptr.is_null() {
                return Ok(None);
            }

            Ok(Some(InodeRef(d_inode_ptr)))
        }
    }

    #[inline(always)]
    fn get_path(&self, buffer: &mut [u8]) -> Result<usize, i64> {
        unsafe {
            let dentry = bpf_probe_read_kernel(&(*self.0).f_path.dentry)?;
            if dentry.is_null() {
                return Ok(0);
            }
            PathBuilder::build_path(dentry, buffer)
        }
    }
}

#[repr(transparent)]
struct InodeRef(*const inode);

impl InodeRef {
    #[inline(always)]
    fn get_number(&self) -> Result<u64, i64> {
        unsafe { bpf_probe_read_kernel(&(*self.0).i_ino) }
    }
}

#[inline(always)]
fn create_file_event(ctx: &ProbeContext, file: &FileRef, inode: u64) -> Result<(), i64> {
    let event_buf = unsafe { FILE_EVENT_BUFFER.get_ptr_mut(0) }.ok_or(-1)?;

    unsafe {
        (*event_buf) = Event::new(Type::File, FileData::new(inode));

        if let Ok(len) = file.get_path(&mut (*event_buf).data.path) {
            (*event_buf).data.path_len = (len as u16).min(255);
        }

        send(ctx, &*event_buf);
    }

    Ok(())
}

#[kprobe(function = "security_file_open")]
pub fn monitor_file_open(ctx: ProbeContext) -> u32 {
    match try_monitor_file_open(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_monitor_file_open(ctx: &ProbeContext) -> Result<(), i64> {
    // Get file reference
    let file = match FileRef::from_context(ctx)? {
        Some(f) => f,
        None => return Ok(()),
    };

    // Try primary inode lookup
    if let Some(inode_ref) = file.get_inode()? {
        let inode_number = inode_ref.get_number()?;
        if file.track_inode(inode_number)? {
            return create_file_event(ctx, &file, inode_number);
        }
    }

    // Fallback to dentry inode lookup
    if let Some(inode_ref) = file.get_dentry_inode()? {
        let inode_number = inode_ref.get_number()?;
        if file.track_inode(inode_number)? {
            return create_file_event(ctx, &file, inode_number);
        }
    }

    Ok(())
}
