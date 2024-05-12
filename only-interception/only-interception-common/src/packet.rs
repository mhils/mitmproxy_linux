pub const BUF_SIZE: usize = 1500;
// use std::fmt

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub buf: [u8; BUF_SIZE], // Assuming maximum Ethernet frame size
}

#[cfg(feature = "user")]
impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.buf.len() < 14 {
            return write!(f, "Invalid Ethernet frame: less than 14 bytes");
        }

        let dest_mac = &self.buf[0..6];
        let src_mac = &self.buf[6..12];
        let ethertype = u16::from_be_bytes([self.buf[12], self.buf[13]]);
        let payload = &self.buf[14..];

        let payload_str: String = payload.iter().map(|&c| if c.is_ascii() && c != 0 { c as char } else { '.' }).collect();

        write!(
            f,
            "Dest MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, Src MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, EtherType: {:04x}, Payload: {:?}",
            dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5],
            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
            ethertype,
            payload_str
        )
        // Convert 'comm' and 'buf' fields to strings for display.
        // 'String::from_utf8_lossy' will replace invalid UTF-8 sequences with U+FFFD REPLACEMENT CHARACTER.
        // let data_str = std::str::from_utf8(&self.buf[..BUF_SIZE as usize]).unwrap();
        // for byte in self.buf.iter() {
        //     write!(f, "{:x}", byte)?;
        // }
        // Ok(())

        // Write the formatted output to the formatter.
        // Adjust formatting as needed for clarity and readability.
        // write!(
        //     f,
        //     "Data: {}",
        //     data_str
        // )
    }
}
