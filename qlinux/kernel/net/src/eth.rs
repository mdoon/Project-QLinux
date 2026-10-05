//! L2: Ethernet II

pub type MacAddr = [u8; 6];

pub const BROADCAST: MacAddr = [0xFF; 6];
pub const ETH_HDR_LEN: usize = 14;
pub const ETH_MTU: usize = 1500;
pub const MAX_FRAME: usize = ETH_HDR_LEN + ETH_MTU;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP:  u16 = 0x0806;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthHeader {
    pub dst:       MacAddr,
    pub src:       MacAddr,
    pub ethertype: u16,
}

impl EthHeader {
    pub fn parse(frame: &[u8]) -> Option<(Self, &[u8])> {
        if frame.len() < ETH_HDR_LEN { return None; }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&frame[0..6]);
        src.copy_from_slice(&frame[6..12]);
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        Some((Self { dst, src, ethertype }, &frame[ETH_HDR_LEN..]))
    }

    pub fn write(&self, out: &mut [u8]) -> usize {
        out[0..6].copy_from_slice(&self.dst);
        out[6..12].copy_from_slice(&self.src);
        out[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        ETH_HDR_LEN
    }
}
