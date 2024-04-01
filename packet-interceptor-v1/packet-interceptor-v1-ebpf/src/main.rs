#![no_std]
#![feature(strict_provenance)]
#![no_main]

mod bindings_linux_in;
mod maps;
mod packet_classifier;
mod packet_syscall_accept;
mod packet_syscall_connect;

pub use packet_classifier::*;
pub use packet_syscall_accept::*;
pub use packet_syscall_connect::*;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
