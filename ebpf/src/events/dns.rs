use crate::events::socket::SocketInfo;

pub type DnsEvent = super::Event<DnsData>;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum DnsType {
    Query = 1,
    Response = 2,
    Unknown = 0,
}

#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct DnsData {
    pub socket: SocketInfo,
    pub dns_type: u8,
    pub qr: u8,         // Query (0) or Response (1)
    pub opcode: u8,     // Standard query (0)
    pub rcode: u8,      // Response code
    pub query_len: u16, // Length of the query name
    pub _pad: [u8; 2],
    pub query: [u8; 256], // DNS query name (max length)
    pub qtype: u16,       // Query type (A, AAAA, etc.)
    pub qclass: u16,      // Query class (usually IN)
}

impl DnsData {
    pub fn new(sock_fd: i32) -> Self {
        Self {
            socket: SocketInfo::new(sock_fd),
            dns_type: DnsType::Unknown as u8,
            qr: 0,
            opcode: 0,
            rcode: 0,
            query_len: 0,
            _pad: [0; 2],
            query: [0; 256],
            qtype: 0,
            qclass: 0,
        }
    }

    #[inline(always)]
    pub fn socket(&self) -> &SocketInfo {
        &self.socket
    }

    #[inline(always)]
    pub fn socket_mut(&mut self) -> &mut SocketInfo {
        &mut self.socket
    }

    #[inline(always)]
    pub fn set_query(&mut self, query: &[u8]) {
        let len = query.len().min(255);
        self.query[..len].copy_from_slice(&query[..len]);
        self.query_len = len as u16;
    }
}

// DNS header structure (12 bytes)
#[repr(C, packed)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

// DNS question structure
#[repr(C, packed)]
pub struct DnsQuestion {
    pub qtype: u16,
    pub qclass: u16,
}
