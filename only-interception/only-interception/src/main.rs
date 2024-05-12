
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;
use only_interception_common::{Packet, BUF_SIZE};
use aya::maps::AsyncPerfEventArray;
use bytes::BytesMut;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
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
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/only-interception"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/only-interception"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.


    //EGRESS PROGRAM
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf
        .program_mut("only_interception_egress")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;

    // Read from the map and print the packets
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    let len_of_packet = std::mem::size_of::<Packet>();
    for cpu_id in online_cpus()? {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, Some(32))?;

        // process each perf buffer in a separate task
        tokio::spawn(async move {
            // Prepare a set of buffers to store the data read from the perf buffer.
            // Here, 10 buffers are created, each with a capacity equal to the size of the Data structure.
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(len_of_packet))
                .collect::<Vec<_>>();
            loop {
                // Attempt to read events from the perf buffer into the prepared buffers.
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        warn!("Error reading events: {}", e);
                        continue;
                    }
                };
                // Iterate over the number of events read. `events.read` indicates how many events were read.
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let packet = buf.as_ptr() as *const Packet; // Cast the buffer pointer to a Data pointer.
                    info!("{}", unsafe { *packet });
                }
            }
        });
    }


    //INGRESS PROGRAM
    let program: &mut SchedClassifier = bpf
        .program_mut("only_interception_ingress")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
