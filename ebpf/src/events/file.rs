use crate::stack_struct;

pub type FileEvent = super::Event<FileData>;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileKey {
    pub inode: u64,
    pub task_id: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileFlags {
    pub flags: u8,
    pub _pad: [u8; 7],
}

impl FileFlags {
    pub const WATCHED: u8 = 0b00000001;
    pub const MODIFIED: u8 = 0b00000010;

    #[inline(always)]
    pub fn new() -> Self {
        Self {
            flags: 0,
            _pad: [0; 7],
        }
    }

    #[inline(always)]
    pub fn is_watched(&self) -> bool {
        self.flags & Self::WATCHED != 0
    }

    #[inline(always)]
    pub fn set_watched(&mut self) {
        self.flags |= Self::WATCHED;
    }
}

#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct FileData {
    pub inode: u64,
    pub pid: u32,
    pub operation: u8,
    pub _pad: [u8; 3],
    pub comm: [u8; 16],
    pub path: [u8; 64], // Reduced from 128 to help verifier
    pub path_len: u16,
}

impl FileData {
    pub fn new(inode: u64) -> Self {
        Self {
            inode,
            pid: 0,
            operation: 0,
            _pad: [0; 3],
            comm: [0; 16],
            path: [0; 64],
            path_len: 0,
        }
    }

    #[inline(always)]
    pub fn set_comm(&mut self, comm: &[u8]) {
        let len = comm.len().min(15);
        // Copy in small chunks
        for i in 0..(len / 4) {
            let start = i * 4;
            let chunk = &comm[start..start + 4.min(len - start)];
            self.comm[start..start + chunk.len()].copy_from_slice(chunk);
        }
        self.comm[len] = 0;
    }
}
