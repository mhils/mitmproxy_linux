#![no_std]
#![no_main]

#![allow(unused)]

/// Try out every handler that may update a sockmap.
/// https://github.com/torvalds/linux/blame/2f87d0916ce0d2925cedbc9e8f5d6291ba2ac7b2/kernel/bpf/verifier.c#L9052


use core::net::Ipv4Addr;
use core::ops::Index;
use aya_ebpf::{bpf_printk, macros::{map, sk_msg}, maps::SockHash, programs::SkMsgContext, EbpfContext, TASK_COMM_LEN};
use aya_ebpf::bindings::{bpf_sock, bpf_sock_ops, xdp_action, BPF_ANY};
use aya_ebpf::bindings::bpf_ret_code::BPF_OK;
use aya_ebpf::bindings::sk_action::SK_PASS;
use aya_ebpf::cty::{c_long, c_uint, c_void};
use aya_ebpf::helpers::{bpf_map_update_elem, bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_user, bpf_sock_hash_update};
use aya_ebpf::macros::{cgroup_sock, kprobe, stream_parser, stream_verdict, xdp, sock_ops, flow_dissector, sk_lookup};
use aya_ebpf::maps::SockMap;
use aya_ebpf::programs::{FlowDissectorContext, ProbeContext, SkBuffContext, SkLookupContext, SockContext, SockOpsContext, XdpContext};
use aya_ebpf::programs::sk_buff::SkBuff;
use aya_log_ebpf::{error, info};
use echo_test_common::SockKey;

pub fn command_to_str(command: &[u8; 16]) -> &str {
    let len = command.iter()
        .position(|&c| c == b'\0')
        .unwrap_or(command.len());
    unsafe { core::str::from_utf8_unchecked(&command[..len]) }
}

pub fn is_nc(command: Result<[u8; TASK_COMM_LEN], c_long>) -> bool {
    let c = command.unwrap_or_default();
    let cmd = command_to_str(&c);
    cmd == "nc"
}

// BPF_PROG_TYPE_TRACING only works for iterators, this is not what we want.

/// BPF_PROG_TYPE_SOCK_OPS would be great, but unfortunately TCP only.
#[sock_ops]
fn sock_ops_program(ctx: SockOpsContext) -> c_uint {
    if ctx.remote_ip4() == 0x08_08_08_08 {
        info!(&ctx, "sock_ops: {}", ctx.op());
    }
    1
}

// BPF_PROG_TYPE_SOCKET_FILTER is only for inbound packets

// BPF_PROG_TYPE_SCHED_CLS is for a specific network interface - not ideal.
// BPF_PROG_TYPE_SCHED_ACT is deprecated in favor of BPF_PROG_TYPE_SCHED_CLS

/*
/// BPF_PROG_TYPE_XDP is for a specific network interface - not ideal. And also for RX only (??)
#[xdp]
pub fn xdp_hello(ctx: XdpContext) -> u32 {
    if is_nc(ctx.command()) {
        info!(&ctx, "xdp: {}", ctx. );
    }
    xdp_action::XDP_PASS
}
 */

// BPF_PROG_TYPE_SK_REUSEPORT is not what we want

// https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_FLOW_DISSECTOR/
// not implemented in aya, https://github.com/aya-rs/aya/issues/216


// BPF_PROG_TYPE_SK_LOOKUP is for inbound only.

#[cgroup_sock(sock_create)]
pub fn cgroup_sock_create(ctx: SockContext) -> i32 {

    unsafe {
        // XXX: something is off here.
        // bpf_printk!(b"sock_create! %u", (*ctx.sock).src_port);
        // info!(&ctx, "sock_create {:x} {:x}", (*ctx.sock).src_port, (*ctx.sock).dst_ip6[0]);
    }
    if is_nc(ctx.command()) {
        unsafe { bpf_printk!(b"sock_create"); }

        info!(&ctx, "sock_create {}", unsafe { (*ctx.sock).dst_port });
        /*unsafe {
            (*ctx.sock).bound_dev_if = 143;  // Replace with interface id from `ip link show`
        }*/
    }
    1
}

#[flow_dissector]
pub fn flow_dissector_program(ctx: FlowDissectorContext) -> u32 {
    // XXX: This is never called somehow?
    unsafe {
        bpf_printk!(b"flow_dissector");
    }
    BPF_OK
}

#[sk_lookup]
pub fn sk_lookup_program(ctx: SkLookupContext) -> u32 {
    unsafe {
        if (*ctx.lookup).remote_ip4 == 0x08_08_08_08 {
            info!(&ctx, "sk_lookup_program for 8.8.8.8");
        }
    }
    SK_PASS
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
