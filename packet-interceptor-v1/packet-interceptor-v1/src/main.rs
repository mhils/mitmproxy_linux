use aya::programs::{tc, KProbe, SchedClassifier, TcAttachType, UProbe};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{debug, info, warn};

use crate::utils::syscall_fnname_add_prefix;
use aya::maps::perf::PerfBufferError;
use aya::maps::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use packet_interceptor_v1_common::{PacketDirection, PacketEvent};
use procfs::net::TcpState;
use procfs::process::{all_processes, FDTarget};
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::pin::Pin;
use tokio::signal;

mod utils {
    use aya::util::syscall_prefix;
    use std::io;

    /// Given a name, it finds and append the system's syscall prefix to it.
    /// This function doesn't check if the name is for an existing syscall.
    /// For example, given "clone" the helper would return "sys_clone" or "__x64_sys_clone".
    pub fn syscall_fnname_add_prefix(name: &str) -> Result<String, io::Error> {
        Ok(format!("{}{}", syscall_prefix()?, name))
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

// todo: there is probably a better way to do this, the code works so I will keep it for now.
fn find_process_by_port(port_to_find: u16) -> Result<Option<i32>, anyhow::Error> {
    // get all processes
    let all_procs = all_processes()?;

    // build up a map between socket inodes and processes:
    let mut map = std::collections::HashMap::new();
    for process in all_procs {
        let process = process?;
        if let Ok(fds) = process.fd() {
            for fd in fds {
                if let FDTarget::Socket(inode) = fd?.target {
                    map.insert(inode, process.pid());
                }
            }
        }
    }

    // get the tcp table
    let tcp = procfs::net::tcp()?;
    let tcp6 = procfs::net::tcp6()?;

    for entry in tcp.into_iter().chain(tcp6) {
        if entry.local_address.port() == port_to_find && entry.state == TcpState::Listen {
            if let Some(pid) = map.remove(&entry.inode) {
                return Ok(Some(pid));
            }
        }
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/packet-interceptor-v1"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/packet-interceptor-v1"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf
        .program_mut("packet_classifier_egress")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;

    let program: &mut SchedClassifier = bpf
        .program_mut("packet_classifier_ingress")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    let program: &mut KProbe = bpf
        .program_mut("packet_syscall_connect")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(&syscall_fnname_add_prefix("connect")?, 0)?;

    let program: &mut KProbe = bpf
        .program_mut("packet_syscall_accept")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(&syscall_fnname_add_prefix("accept4")?, 0)?;
    program.attach(&syscall_fnname_add_prefix("accept")?, 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENT_QUEUE").unwrap())?;
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    for cpu_id in cpus {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, None)?;

        // process each perf buffer in a separate task
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await?;

                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketEvent;
                    let packet_event = unsafe { ptr.read_unaligned() };
                    println!("{}", packet_to_string(&packet_event)?)
                }
            }

            Ok::<_, anyhow::Error>(())
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn ip_string(ip: u32) -> String {
    let ipv4_addr = Ipv4Addr::from(ip);
    ipv4_addr.to_string()
}
fn packet_to_string(snitcher: &PacketEvent) -> Result<String, anyhow::Error> {
    let dir_to_str = |dir: &PacketDirection| match *dir {
        PacketDirection::Ingress => "ingress",
        PacketDirection::Egress => "egress",
    };
    Ok(match snitcher {
        PacketEvent::Connect {
            remote_ip,
            remote_port,
            local_port,
            direction,
        } => {
            format!(
                "{}_connect {}:{} :{}",
                dir_to_str(direction),
                ip_string(*remote_ip),
                local_port,
                remote_port,
            )
        }
        PacketEvent::Disconnect {
            remote_ip,
            remote_port,
            local_port,
            direction,
        } => {
            format!(
                "{}_disconnect {}:{} :{} ",
                dir_to_str(direction),
                ip_string(*remote_ip),
                remote_port,
                local_port,
            )
        }
        PacketEvent::Traffic {
            remote_ip,
            payload_size,
            local_port,
            remote_port,
            direction,
            payload,
        } => {
            format!(
                "{}_traffic {}:{} :{} size: {}\npayload: {:?}",
                dir_to_str(direction),
                ip_string(*remote_ip),
                remote_port,
                local_port,
                payload_size,
                payload
            )
        }
        PacketEvent::ConnectFunc {
            destination_ip,
            destination_port,
            pid,
            ..
        } => {
            format!(
                "syscall_connect {}:{} {}",
                ip_string(*destination_ip),
                destination_port,
                pid
            )
        }
        PacketEvent::AcceptFunc {
            source_ip,
            source_port,
            pid,
            ..
        } => {
            format!(
                "syscall_accept {}:{} {}",
                ip_string(*source_ip),
                source_port,
                pid
            )
        }
    })
}
