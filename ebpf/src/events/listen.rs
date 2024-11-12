use crate::events::socket::SocketInfo;

pub type ListenEvent = super::Event<ListenData>;

#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct ListenData {
    pub socket: SocketInfo,
    pub backlog: i32,
    pub _pad: [u8; 4],
}

impl ListenData {
    pub fn new(sock_fd: i32, backlog: i32) -> Self {
        Self {
            socket: SocketInfo::new(sock_fd),
            backlog,
            _pad: [0; 4],
        }
    }
}
