#![no_std]
#![no_main]

use core::ops::Index;
use aya_ebpf::{macros::{map, sk_msg}, maps::SockHash, programs::SkMsgContext, EbpfContext};
use aya_ebpf::bindings::{bpf_sock, bpf_sock_ops, xdp_action, BPF_ANY};
use aya_ebpf::bindings::sk_action::SK_PASS;
use aya_ebpf::cty::c_void;
use aya_ebpf::helpers::{bpf_map_update_elem, bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_user, bpf_sock_hash_update};
use aya_ebpf::macros::{cgroup_sock, kprobe, stream_parser, stream_verdict, xdp};
use aya_ebpf::maps::SockMap;
use aya_ebpf::programs::{ProbeContext, SkBuffContext, SockContext, XdpContext};
use aya_ebpf::programs::sk_buff::SkBuff;
use aya_log_ebpf::{error, info};
use echo_test_common::SockKey;

#[map]
static TEST_MAP: SockHash<SockKey> = SockHash::<SockKey>::with_max_entries(1024, 0);

pub fn command_to_str(command: &[u8; 16]) -> &str {
    let len = command.iter()
        .position(|&c| c == b'\0')
        .unwrap_or(command.len());
    unsafe { core::str::from_utf8_unchecked(&command[..len]) }
}

#[cgroup_sock(sock_create)]
pub fn cgroup_sock_create(ctx: SockContext) -> i32 {
    let c = ctx.command().unwrap_or_default();
    let cmd = command_to_str(&c);

    if cmd == "nc" {
        info!(&ctx, "sock create: {} {}", cmd, unsafe { (*ctx.sock).state });

        unsafe {
            (*ctx.sock).bound_dev_if = 143;  // Replace with interface id from `ip link show`
        }
    }
    1
}


/*
These here all require things to be attached to the map, doesn't work for us.
Also aya only has stream verdicts, we want to do UDP as well.

#[map(name = "INGRESS")]
static mut INGRESS: SockHash<u32> = SockHash::with_max_entries(2048, BPF_ANY);

#[stream_parser]
fn stream_parser(ctx: SkBuffContext) -> u32 {
    ctx.len()
}

#[stream_verdict]
fn stream_verdict(ctx: SkBuffContext) -> u32 {
    let c = ctx.command().unwrap_or_default();
    let cmd = command_to_str(&c);
    info!(&ctx, "stream_verdict {} port={}", cmd, ctx.skb.remote_port());
    // let _ret = unsafe { INGRESS.redirect_skb(&ctx, &mut key, 0) };
    SK_PASS
}
*/

#[sk_msg]
pub fn echo_test(ctx: SkMsgContext) -> u32 {
    match try_echo_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_echo_test(ctx: SkMsgContext) -> Result<u32, u32> {
    info!(&ctx, "received a message on the socket");
    Ok(SK_PASS)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
