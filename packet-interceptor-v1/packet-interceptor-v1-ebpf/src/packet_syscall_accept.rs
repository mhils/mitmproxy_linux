use crate::bindings_linux_in::sockaddr_in;
use crate::maps::EVENT_QUEUE;
use aya_ebpf::bindings::{sa_family_t, sockaddr};
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user};
use aya_ebpf::macros::{kprobe, kretprobe, map};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::PtRegs;
use packet_interceptor_v1_common::PacketEvent;

const AF_INET: u16 = 2;
//const AF_INET6: u16 = 10;

#[map]
static ACCEPT_TID_ARGS_MAP: HashMap<u64, usize> = HashMap::with_max_entries(1024, 0);

// #[kprobe(name = "packet_syscall_accept")]
#[kprobe]
pub fn packet_syscall_accept(ctx: ProbeContext) -> u32 {
    match try_packet_syscall_accept(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            let err = match ret.try_into() {
                Ok(rt) => rt,
                Err(_) => 1,
            };
            err
        }
    }
}

#[inline]
pub fn try_packet_syscall_accept(ctx: &ProbeContext) -> Result<u32, i64> {
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);
    let sock_addr: *const sockaddr = regs.arg(1).ok_or(2i64)?;
    if sock_addr.is_null() {
        return Ok(0);
    }
    ACCEPT_TID_ARGS_MAP.insert(&bpf_get_current_pid_tgid(), &sock_addr.addr(), 0)?;
    Ok(0)
}

// #[kretprobe(name = "packet_syscall_accept_ret")]
#[kretprobe]
pub fn packet_syscall_accept_ret(ctx: ProbeContext) -> u32 {
    match try_packet_syscall_accept_ret(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            let err = match ret.try_into() {
                Ok(rt) => rt,
                Err(_) => 1,
            };
            err
        }
    }
}

#[inline]
fn try_packet_syscall_accept_ret(ctx: &ProbeContext) -> Result<u32, i64> {
    // int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    // int accept4(int sockfd, struct sockaddr *addr,socklen_t *addrlen, int flags);
    let as_addr = unsafe {
        ACCEPT_TID_ARGS_MAP
            .get(&bpf_get_current_pid_tgid())
            .ok_or(1i64)?
    };
    ACCEPT_TID_ARGS_MAP.remove(&bpf_get_current_pid_tgid())?;

    let sock_addr: *const sockaddr = (*as_addr) as *const sockaddr;

    let family =
        unsafe { (bpf_probe_read_user(&*sock_addr).map_err(|_e| 5i64)? as sockaddr).sa_family };
    // First we need to get the family, then we can use it to cast the sockaddr to a more specific type
    // Also, it helps filter out UDS and IPv6 connections.
    if family != AF_INET as sa_family_t {
        return Ok(0);
    }
    let sock_in_addr: *const sockaddr_in = unsafe { core::mem::transmute(sock_addr) };
    let sock_in: sockaddr_in = unsafe { bpf_probe_read_user(sock_in_addr)? };
    let ip = u32::from_be(sock_in.sin_addr.s_addr);
    let port = u16::from_be(sock_in.sin_port);

    let pid = bpf_get_current_pid_tgid() as u32;
    let event = &PacketEvent::new_accept_func(ip, port, pid);
    EVENT_QUEUE.output(ctx, event, 0);
    Ok(0)
}
