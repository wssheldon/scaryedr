use aya_ebpf::{
    helpers::bpf_probe_read_user,
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};

use crate::{
    events::{
        dns::{DnsData, DnsEvent, DnsHeader, DnsQuestion, DnsType},
        Type,
    },
    maps::send,
};

// Constants for DNS parsing
const DNS_HEADER_SIZE: usize = 12;
const MAX_DNS_PACKET_SIZE: usize = 512;
const DNS_FLAG_QR: u16 = 0x8000;
const DNS_FLAG_OPCODE_MASK: u16 = 0x7800;
const DNS_FLAG_RCODE_MASK: u16 = 0x000F;

#[kprobe(function = "__sys_sendto")]
pub fn dns_enter_sendto(ctx: ProbeContext) -> u32 {
    match try_dns_enter_sendto(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_dns_enter_sendto(ctx: &ProbeContext) -> Result<(), i64> {
    let sock_fd: i32 = ctx.arg(0).ok_or(-1)?;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(-1)?;
    let buf_size: usize = ctx.arg(2).ok_or(-1)?;

    // Only process packets of reasonable DNS size
    if buf_size < DNS_HEADER_SIZE || buf_size > MAX_DNS_PACKET_SIZE {
        return Ok(());
    }

    // Initialize DNS data
    let mut data = DnsData::new(sock_fd);

    // Read DNS header
    let mut header = unsafe {
        let header: DnsHeader = core::mem::zeroed();
        bpf_probe_read_user(buf_ptr as *const DnsHeader).map_err(|e| e)?;
        header
    };

    // Convert header fields from network byte order
    header.flags = u16::from_be(header.flags);
    header.qdcount = u16::from_be(header.qdcount);

    // Parse DNS header flags
    let qr = (header.flags & DNS_FLAG_QR) >> 15;
    let opcode = ((header.flags & DNS_FLAG_OPCODE_MASK) >> 11) as u8;
    let rcode = (header.flags & DNS_FLAG_RCODE_MASK) as u8;

    // Update DNS data
    data.dns_type = if qr == 0 {
        DnsType::Query as u8
    } else {
        DnsType::Response as u8
    };
    data.qr = qr as u8;
    data.opcode = opcode;
    data.rcode = rcode;

    // Parse query name if this is a query and we have questions
    if qr == 0 && header.qdcount > 0 {
        let mut query_name = [0u8; 256];
        let mut query_len = 0;
        let mut pos = DNS_HEADER_SIZE;

        // Read domain name labels
        while pos < buf_size && query_len < 255 {
            let label_len =
                unsafe { bpf_probe_read_user(buf_ptr.add(pos) as *const u8).map_err(|e| e)? };

            if label_len == 0 {
                break;
            }

            // Add dot if not first label
            if query_len > 0 {
                query_name[query_len] = b'.';
                query_len += 1;
            }

            // Read label
            for i in 0..label_len {
                if query_len >= 255 {
                    break;
                }
                let c = unsafe {
                    bpf_probe_read_user(buf_ptr.add(pos + 1 + i as usize) as *const u8)
                        .map_err(|e| e)?
                };
                query_name[query_len] = c;
                query_len += 1;
            }

            pos += label_len as usize + 1;
        }

        // Read question type and class
        if pos + 4 <= buf_size {
            let question: DnsQuestion = unsafe {
                bpf_probe_read_user(buf_ptr.add(pos) as *const DnsQuestion).map_err(|e| e)?
            };
            data.qtype = u16::from_be(question.qtype);
            data.qclass = u16::from_be(question.qclass);
        }

        data.set_query(&query_name[..query_len]);
    }

    // Create and send event
    let event = DnsEvent::new(Type::Network, data);
    send(ctx, &event);

    Ok(())
}

#[kprobe(function = "__sys_recvfrom")]
pub fn dns_enter_recvfrom(ctx: ProbeContext) -> u32 {
    match try_dns_enter_recvfrom(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_dns_enter_recvfrom(ctx: &ProbeContext) -> Result<(), i64> {
    // Store socket fd for return probe
    let sock_fd: i32 = ctx.arg(0).ok_or(-1)?;
    let mut data = DnsData::new(sock_fd);
    data.dns_type = DnsType::Response as u8;

    // Create and send event
    let event = DnsEvent::new(Type::Network, data);
    send(ctx, &event);

    Ok(())
}

#[kretprobe(function = "__sys_sendto")]
pub fn dns_exit_sendto(ctx: RetProbeContext) -> u32 {
    match try_dns_exit_sendto(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_dns_exit_sendto(ctx: &RetProbeContext) -> Result<(), i32> {
    let _rc = ctx.ret().unwrap_or(-1);
    Ok(())
}

#[kretprobe(function = "__sys_recvfrom")]
pub fn dns_exit_recvfrom(ctx: RetProbeContext) -> u32 {
    match try_dns_exit_recvfrom(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_dns_exit_recvfrom(ctx: &RetProbeContext) -> Result<(), i32> {
    let _rc = ctx.ret().unwrap_or(-1);
    Ok(())
}
