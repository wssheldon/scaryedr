use crate::events::socket::SocketInfo;

pub type ConnectEvent = super::Event<ConnectData>;

#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct ConnectData {
    pub socket: SocketInfo,
    pub connected: u8,
    pub _pad: [u8; 7],
}

impl ConnectData {
    pub fn new(sock_fd: i32) -> Self {
        Self {
            socket: SocketInfo::new(sock_fd),
            connected: 0,
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
