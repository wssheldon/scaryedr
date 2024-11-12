use zerocopy::{FromBytes, IntoBytes};

pub type ConnectEvent = super::Event<ConnectData>;

/// IP address representation compatible with zero-copy
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, align(8))] // Use packed to avoid padding issues
pub struct IpAddr {
    pub addr: [u8; 4], // IPv4 only for now
    pub _pad: [u8; 4], // Padding for alignment
}

impl IpAddr {
    pub fn from_be_u32(addr: u32) -> Self {
        let mut ip = Self {
            addr: [0; 4],
            _pad: [0; 4],
        };
        ip.addr.copy_from_slice(&addr.to_be_bytes());
        ip
    }
}

/// Connect event data with proper alignment and zero-copy compatibility
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C, align(8))]
pub struct ConnectData {
    pub sock_fd: i32,
    pub proto: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub _pad1: u16, // Explicit padding
    pub connected: u8,
    pub _pad2: [u8; 3], // Explicit padding
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
}

impl ConnectData {
    pub fn new(sock_fd: i32, proto: u16) -> Self {
        Self {
            sock_fd,
            proto,
            src_port: 0,
            dst_port: 0,
            _pad1: 0,
            connected: 0,
            _pad2: [0; 3],
            src_addr: IpAddr {
                addr: [0; 4],
                _pad: [0; 4],
            },
            dst_addr: IpAddr {
                addr: [0; 4],
                _pad: [0; 4],
            },
        }
    }
}
