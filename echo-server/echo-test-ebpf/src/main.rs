#![no_std]
#![no_main]

use core::ops::Index;
use aya_ebpf::{macros::{map, sk_msg}, maps::SockHash, programs::SkMsgContext, EbpfContext};
use aya_ebpf::bindings::bpf_sock_ops;
use aya_ebpf::bindings::sk_action::SK_PASS;
use aya_ebpf::macros::{cgroup_sock, kprobe};
use aya_ebpf::programs::{ProbeContext, SockContext};
use aya_log_ebpf::{error, info};
use echo_test_common::SockKey;

#[map]
static TEST_MAP: SockHash<SockKey> = SockHash::<SockKey>::with_max_entries(1024, 0);


#[cgroup_sock(sock_create)]
pub fn cgroup_sock_create(ctx: SockContext) -> i32 {
    let command = ctx.command().unwrap_or_default();
    let len = command.iter()
        .position(|&c| c == b'\0')
        .unwrap_or(command.len());
    let command2 = unsafe { core::str::from_utf8_unchecked(&command[..len]) };


    if command2 == "nc" {
        info!(&ctx, "sock create: {} {}", command2, unsafe { (*ctx.sock).state });

        let mut key = SockKey::default();
        let ptr = ctx.as_ptr().cast::<bpf_sock_ops>();
        // TEST_MAP.update(&mut key, unsafe { &mut *ptr }, 0);
    }


    0
}

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
