use crate::maps::EVENT_QUEUE;
use aya_bpf::maps::Array;
use aya_ebpf::bindings::{TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::debug;
use packet_interceptor_v1_common::{PacketDirection, PacketEvent};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

const MAX_PACKET_SIZE: usize = 65535;
#[map]
static ACCEPT_TID_ARGS_MAP: HashMap<u64, usize> = HashMap::with_max_entries(1024, 0);


// #[classifier(name = "snitchrs_classifier_ingress")]
#[classifier]
pub fn packet_classifier_ingress(ctx: TcContext) -> i32 {
    match try_packet_classifier(ctx, PacketDirection::Ingress) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_SHOT,
    }
}

// #[classifier(name = "snitchrs_classifier_egress")]
#[classifier]
pub fn packet_classifier_egress(ctx: TcContext) -> i32 {
    match try_packet_classifier(ctx, PacketDirection::Egress) {
        Ok(_) => TC_ACT_PIPE,
        Err(_) => TC_ACT_SHOT,
    }
}

#[inline]
fn try_packet_classifier(ctx: TcContext, ingress: PacketDirection) -> Result<(), ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if !matches!(ethhdr.ether_type, EtherType::Ipv4) {
        return Ok(());
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if !matches!(ipv4hdr.proto, IpProto::Tcp) {
        return Ok(());
    }
    // only works with Ipv4 and TCP for now...

    let destination_ip = u32::from_be(ipv4hdr.dst_addr);
    let source_ip = u32::from_be(ipv4hdr.src_addr);
    let transport_hdr_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let tcp_hdr: TcpHdr = ctx.load(transport_hdr_offset).map_err(|_| ())?;
    let destination_port = u16::from_be(tcp_hdr.dest);
    let source_port = u16::from_be(tcp_hdr.source);
    /*
    The TCP payload size is calculated by taking the "Total Length" from the IP
    header (ip.len) and then substract the "IP header length" (ip.hdr_len) and the
    "TCP header length" (tcp.hdr_len).
    */
    let payload_size = ipv4hdr.tot_len - Ipv4Hdr::LEN as u16 + TcpHdr::LEN as u16;
    let mut index = 0;
    let mut offset = 0;
    // let payload: [u8;64] = ctx.load(transport_hdr_offset + TcpHdr::LEN).map_err(|_| ())?;
    // let payload= [2;64];
    let ev = &get_event(
        &ctx,
        ingress,
        is_initial_packet(&tcp_hdr),
        is_fin_packet(&tcp_hdr),
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        payload_size,
        payload,
    );

    EVENT_QUEUE.output(&ctx, ev, 0);

    //info!(&ctx, "DEST {:ipv4}, ACTION {}", destination, action);
    Ok(())
}

#[inline]
fn get_event(
    _ctx: &TcContext,
    direction: PacketDirection,
    is_initial_packet: bool,
    is_fin_packet: bool,
    source_ip: u32,
    source_port: u16,
    destination_ip: u32,
    destination_port: u16,
    payload_size: u16,
    payload: [u8; 64],
) -> PacketEvent {
    /*info!(
    ctx,
    "DEST {:ipv4}, source {:ipv4}", destination_ip, source_ip
    );*/
    let (remote_ip, remote_port, local_port) = if direction == PacketDirection::Ingress {
        (source_ip, source_port, destination_port)
    } else {
        (destination_ip, destination_port, source_port)
    };
    if is_initial_packet {
        PacketEvent::new_connect(remote_ip, remote_port, local_port, direction)
    } else if is_fin_packet {
        PacketEvent::new_disconnect(remote_ip, remote_port, local_port, direction)
    } else {
        PacketEvent::new_traffic(
            remote_ip,
            remote_port,
            local_port,
            payload_size,
            direction,
            payload,
        )
    }
}

#[inline]
fn is_initial_packet(packet: &TcpHdr) -> bool {
    packet.syn() == 1
}

#[inline]
fn is_fin_packet(packet: &TcpHdr) -> bool {
    packet.fin() == 1
}
