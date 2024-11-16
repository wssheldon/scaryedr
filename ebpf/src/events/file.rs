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
    pub operation: u8, // READ = 1, WRITE = 2, OPEN = 3, etc.
    pub _pad: [u8; 3],
    pub comm: [u8; 16],
    pub path: [u8; 128],
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
            path: [0; 128],
            path_len: 0,
        }
    }

    #[inline(always)]
    pub fn set_comm(&mut self, comm: &[u8]) {
        let len = comm.len().min(15);
        self.comm[..len].copy_from_slice(&comm[..len]);
        self.comm[len] = 0;
    }

    #[inline(always)]
    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(127);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path[len] = 0;
        self.path_len = len as u16;
    }
}
