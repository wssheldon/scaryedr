pub type SslEvent = super::Event<SslData>;

pub const MAX_BUF_SIZE: usize = 16384; // Maximum TLS record size (2^14)

#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct SslData {
    pub kind: u32,
    pub len: i32,
    pub comm: [u8; 16],
    pub buf: [u8; MAX_BUF_SIZE],
}

impl SslData {
    pub fn new() -> Self {
        Self {
            kind: 0,
            len: 0,
            comm: [0; 16],
            buf: [0; MAX_BUF_SIZE],
        }
    }
}
