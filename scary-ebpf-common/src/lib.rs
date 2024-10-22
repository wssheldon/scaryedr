#![no_std]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux;
pub mod bindings {
    pub use super::vmlinux::*;
}

use core::str;

pub const COMM_SIZE: usize = 16;
pub const FILENAME_SIZE: usize = 256;
pub const MAX_CONNECTIONS: usize = 5;
pub const MAXARGS: usize = 20;
pub const MAXARGLENGTH: usize = 256;
pub const BUFFER: usize = 1024;
pub const SIZEOF_EVENT: usize = 56;
pub const CWD_MAX: usize = 256;
pub const PADDED_BUFFER: usize = BUFFER + MAXARGLENGTH + SIZEOF_EVENT + SIZEOF_EVENT + CWD_MAX;
pub const ARGSBUFFER: usize = BUFFER - SIZEOF_EVENT - SIZEOF_EVENT;
pub const EVENT_ERROR_ARGS: u32 = 0x200;
pub const EVENT_DATA_ARGS: u32 = 0x1000000;
pub const EVENT_ERROR_CWD: u32 = 0x400;
pub const EVENT_ROOT_CWD: u32 = 0x800;

// Structures
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NetworkConnection {
    pub local_addr: u32,
    pub local_port: u16,
    pub remote_addr: u32,
    pub remote_port: u16,
    pub protocol: u16,
    pub socket_type: u16,
    pub socket_state: u8,
}

impl Default for NetworkConnection {
    fn default() -> Self {
        NetworkConnection {
            local_addr: 0,
            local_port: 0,
            remote_addr: 0,
            remote_port: 0,
            protocol: 0,
            socket_type: 0,
            socket_state: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ppid: u32,
    pub filename: [u8; FILENAME_SIZE],
    pub comm: [u8; COMM_SIZE],
    pub cwd: [u8; CWD_MAX],
    pub cwd_len: u32,
    pub filename_read_result: i64,
    pub timestamp_ns: u64,
    pub flags: u32,
    pub args_size: u32,
    pub exec_id: [u8; 64],
}

#[repr(C)]
pub struct ArgBuffer {
    pub data: [u8; PADDED_BUFFER],
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
            cwd: [0; CWD_MAX],
            cwd_len: 0,
            filename_read_result: 0,
            timestamp_ns: 0,
            flags: 0,
            args_size: 0,
            exec_id: [0; 64],
        }
    }
}

#[repr(C)]
pub struct EventData {
    pub event: Event,
    pub args: [u8; ARGSBUFFER],
    pub args_read_result: i32,
}

impl Default for EventData {
    fn default() -> Self {
        EventData {
            event: Event::default(),
            args: [0; ARGSBUFFER],
            args_read_result: 0,
        }
    }
}

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
