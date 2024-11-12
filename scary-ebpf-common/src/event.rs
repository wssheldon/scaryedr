use crate::bindings::task_struct;
use crate::error::Error;
use crate::task::TaskInfo;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::{HashMap, PerCpuArray, PerfEventArray};

use core::fmt;

#[derive(Copy, Clone)]
pub struct Event {
    pub event_type: EventType,
    pub timestamp: u64,
    pub task_info: TaskInfo,
    pub payload: EventPayload,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EventType {
    ProcessExec,
    NetworkConnect,
    NetworkBind,
    NetworkListen,
    NetworkAccept,
    FileOpen,
    FileWrite,
    FileRead,
}

#[derive(Copy, Clone)]
pub union EventPayload {
    pub process: ProcessEventData,
    pub network: NetworkEventData,
    pub file: FileEventData,
}

// Manual Debug implementation for EventPayload
impl fmt::Debug for EventPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventPayload{{ ... }}")
    }
}

// Manual Debug implementation for Event
impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Event")
            .field("event_type", &self.event_type)
            .field("timestamp", &self.timestamp)
            .field("task_info", &self.task_info)
            .field("payload", &self.payload)
            .finish()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ProcessEventData {
    pub filename: [u8; 256],
    pub filename_len: u32,
    pub args: [u8; 128],
    pub args_size: u32,
    pub cwd: [u8; 256],
    pub cwd_len: u32,
    pub exec_id: [u8; 64], // Add exec_id field
}

#[derive(Copy, Clone, Debug)]
pub struct NetworkEventData {
    pub addr: u32,
    pub port: u16,
    pub proto: u16,
    pub sock_fd: i32,
}

#[derive(Copy, Clone, Debug)]
pub struct FileEventData {
    pub filename: [u8; 256],
    pub inode: u64,
    pub mode: u32,
}

impl EventPayload {
    pub fn new_process() -> Self {
        Self {
            process: ProcessEventData {
                filename: [0; 256],
                filename_len: 0,
                args: [0; 128],
                args_size: 0,
                cwd: [0; 256],
                cwd_len: 0,
                exec_id: [0; 64],
            },
        }
    }

    pub fn new_network() -> Self {
        Self {
            network: NetworkEventData {
                addr: 0,
                port: 0,
                proto: 0,
                sock_fd: 0,
            },
        }
    }

    pub fn new_file() -> Self {
        Self {
            file: FileEventData {
                filename: [0; 256],
                inode: 0,
                mode: 0,
            },
        }
    }
}

impl Event {
    pub fn new(event_type: EventType) -> Result<Self, Error> {
        let task_info = unsafe { TaskInfo::from_current()? };

        let payload = match event_type {
            EventType::ProcessExec => EventPayload::new_process(),
            EventType::NetworkConnect
            | EventType::NetworkBind
            | EventType::NetworkListen
            | EventType::NetworkAccept => EventPayload::new_network(),
            EventType::FileOpen | EventType::FileWrite | EventType::FileRead => {
                EventPayload::new_file()
            }
        };

        Ok(Self {
            event_type,
            timestamp: unsafe { bpf_ktime_get_ns() },
            task_info,
            payload,
        })
    }

    pub unsafe fn from_task_struct(
        event_type: EventType,
        task: *const task_struct,
    ) -> Result<Self, Error> {
        let task_info = TaskInfo::from_task_struct(task)?;

        let payload = match event_type {
            EventType::ProcessExec => EventPayload::new_process(),
            EventType::NetworkConnect
            | EventType::NetworkBind
            | EventType::NetworkListen
            | EventType::NetworkAccept => EventPayload::new_network(),
            EventType::FileOpen | EventType::FileWrite | EventType::FileRead => {
                EventPayload::new_file()
            }
        };

        Ok(Self {
            event_type,
            timestamp: bpf_ktime_get_ns(),
            task_info,
            payload,
        })
    }
}

pub trait EventBuilder {
    fn build(self) -> Result<Event, Error>;
}

pub struct NetworkEventBuilder {
    event_type: EventType,
    sock_fd: i32,
    addr: Option<u32>,
    port: Option<u16>,
    proto: Option<u16>,
}

impl NetworkEventBuilder {
    pub fn connect(sock_fd: i32) -> Self {
        Self {
            event_type: EventType::NetworkConnect,
            sock_fd,
            addr: None,
            port: None,
            proto: None,
        }
    }

    pub fn listen(sock_fd: i32) -> Self {
        Self {
            event_type: EventType::NetworkListen,
            sock_fd,
            addr: None,
            port: None,
            proto: None,
        }
    }

    pub fn with_addr(mut self, addr: u32) -> Self {
        self.addr = Some(addr);
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_proto(mut self, proto: u16) -> Self {
        self.proto = Some(proto);
        self
    }
}

impl EventBuilder for NetworkEventBuilder {
    fn build(self) -> Result<Event, Error> {
        let mut event = Event::new(self.event_type)?;

        unsafe {
            let network_data = &mut event.payload.network;
            network_data.sock_fd = self.sock_fd;
            if let Some(addr) = self.addr {
                network_data.addr = addr;
            }
            if let Some(port) = self.port {
                network_data.port = port;
            }
            if let Some(proto) = self.proto {
                network_data.proto = proto;
            }
        }

        Ok(event)
    }
}
pub mod context {
    use super::*;
    use aya_ebpf::programs::ProbeContext;

    pub trait BpfContext {
        fn emit_event(&self, event: &Event) -> Result<(), Error>;
    }

    impl BpfContext for ProbeContext {
        fn emit_event(&self, event: &Event) -> Result<(), Error> {
            // Implementation will be in the actual BPF program where we have access to maps
            Ok(())
        }
    }
}
