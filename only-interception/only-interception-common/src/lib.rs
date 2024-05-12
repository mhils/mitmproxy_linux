// #![no_std]
#![cfg_attr(not(feature = "user"), no_std)]
pub mod packet;

pub use packet::{Packet, BUF_SIZE};
