use aya_ebpf::macros::map;
use aya_ebpf::maps::PerfEventArray;
use packet_interceptor_v1_common::PacketEvent;

#[map]
pub static EVENT_QUEUE: PerfEventArray<PacketEvent> = PerfEventArray::with_max_entries(0, 0);
