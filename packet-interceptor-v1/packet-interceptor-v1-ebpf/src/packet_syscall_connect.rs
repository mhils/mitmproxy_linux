use crate::bindings_linux_in::sockaddr_in;
use crate::maps::EVENT_QUEUE;
use aya_ebpf::bindings::{sa_family_t, sockaddr};
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user};
use aya_ebpf::macros::kprobe;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::PtRegs;
use packet_interceptor_v1_common::PacketEvent;

const AF_INET: u16 = 2;
//const AF_INET6: u16 = 10;

// #[kprobe(name = "snitchrs_syscall_connect")]
#[kprobe]
pub fn packet_syscall_connect(ctx: ProbeContext) -> u32 {
    match try_packet_syscall_connect(&ctx) {
        Ok(ret) => ret,
        Err(err) => match err.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[inline]
fn try_packet_syscall_connect(ctx: &ProbeContext) -> Result<u32, i64> {
    // syscalls wraps arguments in this regs object.
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);
    //  int connect(int sockfd, const struct sockaddr *addr,
    //                    socklen_t addrlen);
    let sockaddr: *const sockaddr = regs.arg(1).ok_or(1i64)?;
    let (ip, port) = parse_sockaddr(sockaddr)?.ok_or(1i64)?;
    let pid = bpf_get_current_pid_tgid() as u32;
    let event = &PacketEvent::new_connect_func(ip, port, pid);
    EVENT_QUEUE.output(ctx, event, 0);
    Ok(0)
}

#[inline]
fn parse_sockaddr(sockaddr: *const sockaddr) -> Result<Option<(u32, u16)>, i64> {
    if sockaddr.is_null() {
        return Ok(None);
    }

    let family =
        unsafe { ((bpf_probe_read_user(&*sockaddr)).map_err(|_e| 5i64)? as sockaddr).sa_family };
    // First we need to get the family, then we can use it to cast the sockaddr to a more specific type
    // Also, it helps filter out UDS and IPv6 connections.
    if family != AF_INET as sa_family_t {
        return Ok(None);
    }
    let sock_in_addr: *const sockaddr_in = unsafe { core::mem::transmute(sockaddr) };
    let sock_in: sockaddr_in = unsafe { bpf_probe_read_user(sock_in_addr)? };
    let ip = u32::from_be(sock_in.sin_addr.s_addr);
    let port = u16::from_be(sock_in.sin_port);
    let local = 0x7f << 6 * 4 | 0xff; // 127.0.0.x
                                      // skip 127.0.0.x (for example, 53 might be used for DNS)
    if ip & local == ip {
        return Ok(None);
    }
    Ok(Some((ip, port)))
}
