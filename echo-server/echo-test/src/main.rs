use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::thread;
use aya::{maps::SockHash, programs::SkMsg};
use aya::maps::SockMap;
use aya::programs::{CgroupAttachMode, CgroupSock, KProbe};
use echo_test_common::SockKey;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    /*
    let listener = TcpListener::bind("127.0.0.1:8000")?;
    let local_addr = listener.local_addr()?;
     */

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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/echo-test"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let prog: &mut CgroupSock = ebpf.program_mut("cgroup_sock_create").unwrap().try_into()?;
    let cgroup = std::fs::File::open("/sys/fs/cgroup/")?;
    prog.load()?;
    prog.attach(&cgroup, CgroupAttachMode::Single)?;
    println!("Attached!");

    let mut sock_map: SockHash<_, SockKey> = ebpf.map("TEST_MAP").unwrap().try_into()?;

    let key = SockKey {
        remote_ip4: 0,
        local_ip4: 0,
        remote_port: 0,
        local_port: 0,
    };


    let map_fd = sock_map.fd().try_clone()?;

    let prog: &mut SkMsg = ebpf.program_mut("echo_test").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&map_fd)?;

    /*
    info!("Listening on {local_addr}");

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {

                    /*
                    let mut sock_map: SockHash<_, SockKey> = ebpf.map_mut("TEST_MAP").unwrap().try_into().expect("cannot get map");
                    sock_map.insert(key, stream.as_raw_fd(), 0).expect("cannot insert");
                    */
                    thread::spawn(move || {
                        handle_client(stream);
                    });
                }
                Err(_) => {
                    println!("Error");
                }
            }
        }
    });
     */

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn handle_client(mut stream: TcpStream) {
    loop {
        let mut read = [0; 1028];
        match stream.read(&mut read) {
            Ok(n) => {
                println!("echo: {:?}", &read[0..n]);
                if n == 0 {
                    // connection was closed
                    break;
                }
                stream.write(&read[0..n]).unwrap();
            }
            Err(err) => {
                panic!("{}", err);
            }
        }
    }
}