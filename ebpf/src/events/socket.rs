use aya_ebpf::helpers::bpf_probe_read_user;
use core::result::Result;
use scary_ebpf_common::bindings::{in6_addr, sa_family_t, sockaddr, sockaddr_in};

// Network constants
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const IPPROTO_TCP: u16 = 6;
pub const IPPROTO_UDP: u16 = 17;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressFamily {
    Inet = AF_INET,
    Inet6 = AF_INET6,
    Unknown = 0,
}

impl From<u16> for AddressFamily {
    fn from(value: u16) -> Self {
        match value {
            AF_INET => AddressFamily::Inet,
            AF_INET6 => AddressFamily::Inet6,
            _ => AddressFamily::Unknown,
        }
    }
}

// Add these structures to mirror Linux kernel definitions
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: __be16,
    pub sin6_flowinfo: __be32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

type __be16 = u16;
type __be32 = u32;

/// Represents an IP address (v4 or v6) with proper alignment
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IpAddr {
    pub addr: [u8; 16],
}

impl IpAddr {
    #[inline(always)]
    pub const fn new() -> Self {
        Self { addr: [0; 16] }
    }

    #[inline(always)]
    pub fn from_be_u32(addr: u32) -> Self {
        let mut ip = Self::new();
        ip.addr[..4].copy_from_slice(&addr.to_be_bytes());
        ip
    }

    #[inline(always)]
    pub fn from_ipv6(addr: &[u8; 16]) -> Self {
        let mut ip = Self::new();
        ip.addr.copy_from_slice(addr);
        ip
    }

    #[inline(always)]
    pub fn as_v4_slice(&self) -> &[u8; 4] {
        // Safe because we know the first 4 bytes are IPv4 when used correctly
        unsafe { &*(self.addr[..4].as_ptr() as *const [u8; 4]) }
    }

    #[inline(always)]
    pub fn as_v6_slice(&self) -> &[u8; 16] {
        &self.addr
    }
}

/// Socket connection information with IPv6 support
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SocketInfo {
    pub sock_fd: i32,
    pub proto: u16,
    pub family: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub state: u8,
    pub scope_id: u32, // For IPv6 scope
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
}

impl SocketInfo {
    #[inline(always)]
    pub const fn new(sock_fd: i32) -> Self {
        Self {
            sock_fd,
            proto: 0,
            family: 0,
            src_port: 0,
            dst_port: 0,
            state: 0,
            scope_id: 0,
            src_addr: IpAddr::new(),
            dst_addr: IpAddr::new(),
        }
    }

    /// Reads socket address information safely
    ///
    /// # Safety
    /// Caller must ensure addr points to valid sockaddr structure
    pub fn read_sockaddr(&mut self, addr: *const sockaddr) -> Result<(), i64> {
        // First read the address family
        let sa_family = unsafe { bpf_probe_read_user(&(*addr).sa_family).map_err(|e| e)? };
        self.set_family(sa_family as u16);

        match self.family() {
            AddressFamily::Inet => {
                let addr_in =
                    unsafe { bpf_probe_read_user(addr as *const sockaddr_in).map_err(|e| e)? };
                self.dst_addr = IpAddr::from_be_u32(u32::from_be(addr_in.sin_addr.s_addr));
                self.dst_port = u16::from_be(addr_in.sin_port);
                Ok(())
            }
            AddressFamily::Inet6 => {
                let addr_in6 =
                    unsafe { bpf_probe_read_user(addr as *const sockaddr_in6).map_err(|e| e)? };

                // Read IPv6 address
                let ipv6_addr = unsafe {
                    bpf_probe_read_user(&addr_in6.sin6_addr.in6_u.u6_addr8).map_err(|e| e)?
                };

                self.dst_addr = IpAddr::from_ipv6(&ipv6_addr);
                self.dst_port = u16::from_be(addr_in6.sin6_port);
                self.scope_id = u32::from_be(addr_in6.sin6_scope_id);
                Ok(())
            }
            AddressFamily::Unknown => Ok(()),
        }
    }

    #[inline(always)]
    pub fn sock_fd(&self) -> i32 {
        self.sock_fd
    }

    #[inline(always)]
    pub fn family(&self) -> AddressFamily {
        match self.family {
            AF_INET => AddressFamily::Inet,
            AF_INET6 => AddressFamily::Inet6,
            _ => AddressFamily::Unknown,
        }
    }

    #[inline(always)]
    fn set_family(&mut self, family: u16) {
        self.family = family;
    }

    #[inline(always)]
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    #[inline(always)]
    pub fn dst_addr(&self) -> &IpAddr {
        &self.dst_addr
    }

    #[inline(always)]
    pub fn scope_id(&self) -> u32 {
        self.scope_id
    }
}
