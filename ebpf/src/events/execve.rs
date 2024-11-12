pub type ExecveEvent = super::Event<ExecveData>;

const MAX_PATH_LEN: usize = 256;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExecveData {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub filename: [u8; 256],
    pub filename_len: u32,
    pub args: [u8; 2048],
    pub args_len: u32,
    pub args_count: u32,
    pub truncated: bool,
    pub comm: [u8; 16],
    pub cwd: [u8; MAX_PATH_LEN],
    pub cwd_len: u32,
    pub _pad: [u8; 3],
}

impl ExecveData {
    pub const fn new() -> Self {
        Self {
            pid: 0,
            tid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            filename: [0; 256],
            filename_len: 0,
            args: [0; 2048],
            args_len: 0,
            args_count: 0,
            truncated: false,
            comm: [0; 16],
            cwd: [0; MAX_PATH_LEN],
            cwd_len: 0,
            _pad: [0; 3],
        }
    }
}
