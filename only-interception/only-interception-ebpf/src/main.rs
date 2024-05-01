#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{macros::classifier, macros::map, programs::TcContext, maps::PerCpuArray, bindings::TC_ACT_PIPE};
use aya_ebpf::bindings::{iphdr, tcphdr, eth};
use aya_log_ebpf::info;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();

#[repr(C)]
struct Buf {
    pub buf: [u8; 1500], // Assuming maximum Ethernet frame size
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

//EGRESS PROGRAM
#[classifier]
pub fn only_interception_egress(ctx: TcContext) -> i32 {
    match try_only_interception_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_only_interception_egress(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received an egress packet");
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
        &mut *ptr
    };
    let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    ctx.load_bytes(offset, &mut buf.buf).map_err(|_| TC_ACT_PIPE)?;

    Ok(TC_ACT_PIPE)
}

//INGRESS PROGRAM
#[classifier]
pub fn only_interception_ingress(ctx: TcContext) -> i32 {
    match try_only_interception_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_only_interception_ingress(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received an ingress packet");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
