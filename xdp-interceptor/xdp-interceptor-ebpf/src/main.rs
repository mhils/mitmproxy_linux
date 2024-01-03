#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;

const LOG_BUF_CAPACITY: usize = 1024;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[map]
static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[derive(Debug)]
enum ExecutionError {
    PointerOverflow,
    PointerOutOfBounds,
    PacketMalformed,
    PacketTooSmall,

}

#[inline(always)]
fn get_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ExecutionError> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    let new_ptr = start
        .checked_add(offset)
        .ok_or(ExecutionError::PointerOverflow)?;

    if new_ptr
        .checked_add(len)
        .ok_or(ExecutionError::PointerOverflow)?
        > end
    {
        return Err(ExecutionError::PointerOutOfBounds);
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn get_mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ExecutionError> {
    let ptr: *const T = get_ptr_at(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[inline(always)]
fn get_raw_packet(ctx: &XdpContext) -> Result<*const [u8], ExecutionError> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = end-start;

    if start.checked_add(len).ok_or(ExecutionError::PointerOverflow)? > end {
        return Err(ExecutionError::PointerOutOfBounds);
    }

    let start_ptr: *const u8 = start as usize as *const u8;
    let raw_packet = unsafe{core::slice::from_raw_parts(start_ptr, len)};
    Ok(raw_packet)
}

#[xdp]
pub fn xdp_interceptor(ctx: XdpContext) -> u32 {
    match try_xdp_interceptor(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_interceptor(ctx: XdpContext) -> Result<u32, ExecutionError> {

    //get the source pid
    let pid: u32 = match ctx.pid() {
        Ok(data) => data,
        Err(_) => {
            info!(&ctx, "Failed to get pid");
            return Ok(xdp_action::XDP_ABORTED);
        },
    };

    //get the source process name


    //get the entire raw packet
    let raw_packet: *const [u8] = match get_raw_packet(&ctx) {
        Ok(data) => data,
        Err(_) => {
            info!(&ctx, "Failed to get raw packet");
            return Ok(xdp_action::XDP_ABORTED);
        },
    };

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
