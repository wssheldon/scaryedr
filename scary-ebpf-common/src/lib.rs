#![no_std]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux;

pub mod bindings {
    pub use super::vmlinux::*;
}

// Common data structures
pub const COMM_SIZE: usize = 16;
pub const FILENAME_SIZE: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ppid: u32,
    pub filename: [u8; FILENAME_SIZE],
    pub comm: [u8; COMM_SIZE],
    pub filename_read_result: i64,
}

impl Default for Event {
    fn default() -> Self {
        Event {
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
            ppid: 0,
            filename: [0; FILENAME_SIZE],
            comm: [0; COMM_SIZE],
            filename_read_result: 0,
        }
    }
}
