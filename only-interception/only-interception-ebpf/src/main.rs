#![no_std]
#![no_main]

use core::{mem, ptr};
use aya_ebpf::{macros::classifier, macros::map, programs::TcContext, maps::RingBuf, bindings::TC_ACT_PIPE};
use aya_log_ebpf::info;

const BUF_SIZE: usize = 1500;

#[repr(C)]
pub struct Packet {
    pub buf: [u8; BUF_SIZE], // Assuming maximum Ethernet frame size
}

#[map]
pub static mut PACKETS: RingBuf = RingBuf::with_byte_size(BUF_SIZE as u32, 0);

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
    unsafe{
        // let start = ctx.data();
        // let end = ctx.data_end();
        if let Some(mut buf) = PACKETS.reserve::<Packet>(0) {
            let ptr = buf.as_mut_ptr();
            // let len = end - start;
            // let buf_size = BUF_SIZE.min(len);
            // if end < start {
            //     return Err(TC_ACT_PIPE);
            // }
            // if start + BUF_SIZE > end {
            //     return Err(TC_ACT_PIPE);
            // }
            // if start <= 0 {
            //     return Err(TC_ACT_PIPE);
            // }
            ctx.load_bytes(0, &mut (*ptr).buf).map_err(|_| TC_ACT_PIPE)?;
            buf.submit(0);
        }
    } 
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
