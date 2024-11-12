#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user,
    },
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use scary_ebpf_common::{
    bindings::{sa_family_t, sockaddr, sockaddr_in},
    error::Error,
    event::{
        context::BpfContext, Event, EventBuilder, EventPayload, EventType, NetworkEventBuilder,
    },
    task::TaskInfo,
};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct NetworkData {
    pub sockfd: i32,
    pub addr: u32,
    pub port: u16,
    pub proto: u16,
}

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[map(name = "TEMP_DATA")]
static mut TEMP_DATA: PerCpuArray<NetworkData> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "TEMP_EVENTS")]
static mut TEMP_EVENTS: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

pub struct NetworkContext<'a>(&'a ProbeContext);
pub struct NetworkReturnContext<'a>(&'a RetProbeContext);

impl<'a> NetworkContext<'a> {
    pub fn new(ctx: &'a ProbeContext) -> Self {
        Self(ctx)
    }

    pub fn store_data(&self, data: &NetworkData) -> Result<(), Error> {
        unsafe {
            if let Some(storage) = TEMP_DATA.get_ptr_mut(0) {
                *storage = *data;
            }
        }
        Ok(())
    }
}

impl<'a> NetworkReturnContext<'a> {
    pub fn new(ctx: &'a RetProbeContext) -> Self {
        Self(ctx)
    }

    unsafe fn prepare_event(&self, event_type: EventType) -> Result<&mut Event, Error> {
        let event_ptr = TEMP_EVENTS.get_ptr_mut(0).ok_or(Error::Map(-1))?;
        // Need to dereference the pointer to access fields
        let event = &mut *event_ptr;

        // Access fields through the dereferenced pointer
        (*event_ptr).event_type = event_type;
        (*event_ptr).timestamp = bpf_ktime_get_ns();
        (*event_ptr).task_info = TaskInfo::from_current()?;
        (*event_ptr).payload = EventPayload::new_network();

        Ok(event) // Return the mutable reference
    }

    pub fn emit_connect_event(&self) -> Result<(), Error> {
        let data = self.get_stored_data()?;

        unsafe {
            let event = self.prepare_event(EventType::NetworkConnect)?;
            let network_data = &mut event.payload.network;
            network_data.sock_fd = data.sockfd;
            network_data.addr = data.addr;
            network_data.port = data.port;
            network_data.proto = data.proto;

            EVENTS.output(self.0, event, 0);
        }

        Ok(())
    }

    pub fn emit_listen_event(&self) -> Result<(), Error> {
        let data = self.get_stored_data()?;

        unsafe {
            let event = self.prepare_event(EventType::NetworkListen)?;
            let network_data = &mut event.payload.network;
            network_data.sock_fd = data.sockfd;

            EVENTS.output(self.0, event, 0);
        }

        Ok(())
    }

    pub fn emit_bind_event(&self) -> Result<(), Error> {
        let data = self.get_stored_data()?;

        unsafe {
            let event = self.prepare_event(EventType::NetworkBind)?;
            let network_data = &mut event.payload.network;
            network_data.sock_fd = data.sockfd;
            network_data.addr = data.addr;
            network_data.port = data.port;
            network_data.proto = data.proto;

            EVENTS.output(self.0, event, 0);
        }

        Ok(())
    }

    fn get_stored_data(&self) -> Result<NetworkData, Error> {
        unsafe { TEMP_DATA.get_ptr_mut(0).map(|p| *p).ok_or(Error::Map(-1)) }
    }
}

#[kprobe(function = "__sys_connect")]
pub fn net_enter_sys_connect(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_connect(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_enter_sys_connect(ctx: &ProbeContext) -> Result<(), Error> {
    let ctx = NetworkContext::new(ctx);
    let sockfd = ctx.0.arg::<i32>(0).ok_or(Error::Field("sockfd"))?;
    let sockaddr_ptr: *const sockaddr = ctx
        .0
        .arg::<*const sockaddr>(1)
        .ok_or(Error::Field("sockaddr"))?;

    unsafe {
        let sa_family: sa_family_t =
            bpf_probe_read_user(&(*sockaddr_ptr).sa_family).map_err(|e| Error::UserRead(e))?;

        if sa_family as i32 == 2 {
            let addr_in: sockaddr_in = bpf_probe_read_user(sockaddr_ptr as *const sockaddr_in)
                .map_err(|e| Error::UserRead(e))?;

            let addr = u32::from_be(addr_in.sin_addr.s_addr);
            let port = u16::from_be(addr_in.sin_port);

            info!(
                ctx.0,
                "CONNECT: addr={}.{}.{}.{} port={}",
                (addr >> 24) & 0xff,
                (addr >> 16) & 0xff,
                (addr >> 8) & 0xff,
                addr & 0xff,
                port
            );
            let data = NetworkData {
                sockfd,
                addr: u32::from_be(addr_in.sin_addr.s_addr),
                port: u16::from_be(addr_in.sin_port),
                proto: sa_family as u16,
            };

            ctx.store_data(&data)?;
        }
    }

    Ok(())
}

#[kretprobe(function = "__sys_connect")]
pub fn net_exit_sys_connect(ctx: RetProbeContext) -> u32 {
    match try_net_exit_sys_connect(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_exit_sys_connect(ctx: &RetProbeContext) -> Result<(), Error> {
    let ctx = NetworkReturnContext::new(ctx);
    ctx.emit_connect_event()
}

#[kprobe(function = "__sys_listen")]
pub fn net_enter_sys_listen(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_listen(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_enter_sys_listen(ctx: &ProbeContext) -> Result<(), Error> {
    let ctx = NetworkContext::new(ctx);
    let sockfd = ctx.0.arg::<i32>(0).ok_or(Error::Field("sockfd"))?;

    let data = NetworkData {
        sockfd,
        addr: 0,
        port: 0,
        proto: 0,
    };

    ctx.store_data(&data)
}

#[kretprobe(function = "__sys_listen")]
pub fn net_exit_sys_listen(ctx: RetProbeContext) -> u32 {
    match try_net_exit_sys_listen(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_exit_sys_listen(ctx: &RetProbeContext) -> Result<(), Error> {
    let ctx = NetworkReturnContext::new(ctx);
    ctx.emit_listen_event()
}

#[kprobe(function = "__sys_bind")]
pub fn net_enter_sys_bind(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_bind(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[kprobe(function = "__sys_accept4")]
pub fn net_enter_sys_accept(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_accept(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[kprobe(function = "__sys_sendto")]
pub fn net_enter_sys_sendto(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_sendto(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[kprobe(function = "__sys_recvfrom")]
pub fn net_enter_sys_recvfrom(ctx: ProbeContext) -> u32 {
    match try_net_enter_sys_recvfrom(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_enter_sys_bind(ctx: &ProbeContext) -> Result<(), Error> {
    let ctx = NetworkContext::new(ctx);
    let sockfd = ctx.0.arg::<i32>(0).ok_or(Error::Field("sockfd"))?;
    let sockaddr_ptr: *const sockaddr = ctx
        .0
        .arg::<*const sockaddr>(1)
        .ok_or(Error::Field("sockaddr"))?;

    unsafe {
        let sa_family: sa_family_t =
            bpf_probe_read_user(&(*sockaddr_ptr).sa_family).map_err(|e| Error::UserRead(e))?;

        if sa_family as i32 == 2 {
            // AF_INET
            let addr_in: sockaddr_in = bpf_probe_read_user(sockaddr_ptr as *const sockaddr_in)
                .map_err(|e| Error::UserRead(e))?;

            let data = NetworkData {
                sockfd,
                addr: u32::from_be(addr_in.sin_addr.s_addr),
                port: u16::from_be(addr_in.sin_port),
                proto: sa_family as u16,
            };

            ctx.store_data(&data)?;
        }
    }

    Ok(())
}

#[kretprobe(function = "__sys_bind")]
pub fn net_exit_sys_bind(ctx: RetProbeContext) -> u32 {
    match try_net_exit_sys_bind(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_net_exit_sys_bind(ctx: &RetProbeContext) -> Result<(), Error> {
    let ctx = NetworkReturnContext::new(ctx);

    // Create a new method in NetworkReturnContext to handle bind events
    ctx.emit_bind_event()
}

fn try_net_enter_sys_accept(ctx: ProbeContext) -> Result<(), i64> {
    let sockfd = ctx.arg::<i32>(0).ok_or(1)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    // info!(&ctx, "ACCEPT: pid={}", pid_tgid >> 32);
    // info!(&ctx, "ACCEPT: socket_fd={}", sockfd);

    // if let Ok(comm) = bpf_get_current_comm() {
    //     let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    //     info!(&ctx, "ACCEPT: comm={}", comm_str);
    // }

    Ok(())
}

fn try_net_enter_sys_sendto(ctx: ProbeContext) -> Result<(), i64> {
    let sockfd = ctx.arg::<i32>(0).ok_or(1)?;
    let len = ctx.arg::<usize>(2).ok_or(1)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    // info!(&ctx, "SENDTO: pid={}", pid_tgid >> 32);
    // info!(&ctx, "SENDTO: socket_fd={} len={}", sockfd, len);

    // if let Ok(comm) = bpf_get_current_comm() {
    //     let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    //     info!(&ctx, "SENDTO: comm={}", comm_str);
    // }

    Ok(())
}

fn try_net_enter_sys_recvfrom(ctx: ProbeContext) -> Result<(), i64> {
    let sockfd = ctx.arg::<i32>(0).ok_or(1)?;
    let len = ctx.arg::<usize>(2).ok_or(1)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    // info!(&ctx, "RECVFROM: pid={}", pid_tgid >> 32);
    // info!(&ctx, "RECVFROM: socket_fd={} len={}", sockfd, len);

    // if let Ok(comm) = bpf_get_current_comm() {
    //     let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    //     info!(&ctx, "RECVFROM: comm={}", comm_str);
    // }

    Ok(())
}

#[allow(dead_code)]
#[cfg_attr(not(test), panic_handler)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
