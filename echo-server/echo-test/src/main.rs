#![allow(unused)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::thread;
use aya::{maps::SockHash, programs::SkMsg};
use aya::maps::SockMap;
use aya::programs::{CgroupAttachMode, CgroupSock, FlowDissector, KProbe, SkLookup, SockOps};
use echo_test_common::SockKey;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::net::{TcpSocket, TcpStream};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/echo-test"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let prog: &mut CgroupSock = ebpf.program_mut("cgroup_sock_create").unwrap().try_into()?;
    // root cgroup to get all events.
    let cgroup = std::fs::File::open("/sys/fs/cgroup/")?;
    prog.load()?;
    prog.attach(&cgroup, CgroupAttachMode::Single)?;
    info!("Attached!");

    let prog: &mut SockOps = ebpf.program_mut("sock_ops_program").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&cgroup, CgroupAttachMode::Single)?;

    let prog: &mut FlowDissector = ebpf.program_mut("flow_dissector_program").unwrap().try_into()?;
    prog.load()?;
    let net_ns = File::open("/proc/self/ns/net")?;
    prog.attach(net_ns)?;

    let prog: &mut SkLookup = ebpf.program_mut("sk_lookup_program").unwrap().try_into()?;
    prog.load()?;
    let net_ns = File::open("/proc/self/ns/net")?;
    prog.attach(net_ns);

    let mut stream = TcpStream::connect("8.8.8.8:53").await?;


    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
