
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn, error};
use tokio::signal;
use std::thread;
use only_interception_common::{Packet, BUF_SIZE};
use aya::maps::AsyncPerfEventArray;
use bytes::BytesMut;
use tun_tap::{Iface, Mode};
use std::sync::{Arc, Mutex};
use hex;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

/// Run a shell command. Panic if it fails in any way.
fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new("ip")
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execte {}", cmd);
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

    //INGRESS PROGRAM
    let program: &mut SchedClassifier = bpf
        .program_mut("only_interception_ingress")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;


    // Read from the map and print the packets
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    let len_of_packet = std::mem::size_of::<Packet>();
    //Create tap interface
    // let iface = Iface::new("tap10", Mode::Tap).unwrap();
    // eprintln!("Iface: {:?}", iface);
    // Configure the „local“ (kernel) endpoint. Kernel is (the host) 10.107.1.3, we (the app)
    // pretend to be 10.107.1.2.
    // cmd("ip", &["addr", "add", "dev", iface.name(), "10.107.1.3/24"]);
    // cmd("ip", &["link", "set", "up", "dev", iface.name()]);
    
    // const PING: &[u8] = &[0, 0, 8, 0, 69, 0, 0, 84, 44, 166, 64, 0, 64, 1, 247, 40, 10, 107, 1, 2, 10,
    // 107, 1, 3, 8, 0, 62, 248, 19, 160, 0, 2, 232, 228, 34, 90, 0, 0, 0, 0, 216, 83, 3, 0, 0, 0, 0,
    // 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    // 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55];
    //
    // let iface = Arc::new(iface);
    // let iface_writer = Arc::clone(&iface);
    // let iface_reader = Arc::clone(&iface);
    // let writer = thread::spawn(move || {
    //     // Yeh, mutable reference to immutable thing. Nuts…
    //     loop {
    //         thread::sleep(Duration::from_secs(1));
    //         println!("Sending a ping");
    //         let amount = iface_writer.send(PING).unwrap();
    //         assert!(amount == PING.len());
    //     }
    // });
    // let reader = thread::spawn(move || {
        // MTU + TUN header
    //     let mut buffer = vec![0; 1504];
    //     loop {
    //         let size = iface_reader.recv(&mut buffer).unwrap();
    //         // Strip the „header“
    //         assert!(size >= 4);
    //         println!("Packet: {:?}", &buffer[4..size]);
    //     }
    // });
    // writer.join()
    //     .unwrap();
    // reader.join()
    //     .unwrap();

    // let iface = Arc::new(Mutex::new(iface));



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
                    let hex_string = hex::encode(&buf);
                    info!("hex string: {}", hex_string);
                }
            }
        });
    }



    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
