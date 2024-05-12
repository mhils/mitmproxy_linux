#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{macros::classifier, macros::map, programs::TcContext, maps::PerfEventArray, maps::PerCpuArray, bindings::TC_ACT_PIPE};
use aya_log_ebpf::info;
use only_interception_common::{Packet, BUF_SIZE};



#[map]
// static PACKETS: RingBuf = RingBuf::with_byte_size(10*mem::size_of::<Packet>() as u32, 0);
static mut PACKETS: PerCpuArray<Packet> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut EVENTS: PerfEventArray<Packet> = PerfEventArray::with_max_entries(1024, 0);

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
    let start = ctx.data();
    let end = ctx.data_end();
    let mut len = ctx.len() as usize;

    info!(&ctx, "packet length: {}", len);
    // let mut tmp = [0u8; BUF_SIZE];
    if len >= BUF_SIZE {
        len = BUF_SIZE;
    }
    let packet = unsafe {
        let ptr = PACKETS.get_ptr_mut(0).ok_or(0_i32)?;
        &mut *ptr
    };
    for i in 0..len as usize {
        packet.buf[i] = ctx.load(i).map_err(|_| 0)?;
    }

    // packet.buf = tmp;

    unsafe{
        EVENTS.output(&ctx, &(*packet), 0);
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
