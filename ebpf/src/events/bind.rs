use crate::events::socket::SocketInfo;

pub type BindEvent = super::Event<BindData>;

#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct BindData {
    pub socket: SocketInfo,
    pub bound: u8,
    pub _pad: [u8; 7],
}

impl BindData {
    pub fn new(sock_fd: i32) -> Self {
        Self {
            socket: SocketInfo::new(sock_fd),
            bound: 0,
            _pad: [0; 7],
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
}
