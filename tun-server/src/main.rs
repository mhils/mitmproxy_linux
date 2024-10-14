use std::io::Read;

extern crate tun2;

fn main() {
    let mut config = tun2::Configuration::default();
    config.address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let mut dev = tun2::create(&config).unwrap();
    let mut buf = [0; 4096];

    loop {
        let amount = dev.read(&mut buf).unwrap();
        println!("{:x?}", &buf[0 .. amount]);
    }
}