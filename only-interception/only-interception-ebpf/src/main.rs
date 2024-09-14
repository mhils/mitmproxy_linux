#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, macros::map, programs::TcContext, maps::PerfEventArray, maps::PerCpuArray, bindings::TC_ACT_PIPE, bindings::TC_ACT_SHOT};
use aya_log_ebpf::info;
use only_interception_common::{Packet, BUF_SIZE};

fn load_packet(ctx: TcContext) -> Result<(), i32> {
    let mut len = ctx.len() as usize;
    unsafe {
        let packet = {
            let ptr = PACKETS.get_ptr_mut(0).ok_or(0_i32)?;
            &mut *ptr
        };
        if len >= BUF_SIZE {
            len = BUF_SIZE;
        }
        for i in 0..len as usize {
            packet.buf[i] = ctx.load(i).map_err(|_| 0)?;
        }
        EVENTS.output(&ctx, &(*packet), 0);
    }
    Ok(())
}


#[map]
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
    load_packet(ctx).map_err(|_| 0)?;
    Ok(TC_ACT_SHOT)
    // Ok(TC_ACT_PIPE)
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
    load_packet(ctx).map_err(|_| 0)?;
    Ok(TC_ACT_SHOT)
    // Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
