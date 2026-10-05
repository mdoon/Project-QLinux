//! L4 (下位): UDP。QTLS レコードを運ぶ

use crate::ipv4::{checksum_add, checksum_finish, Ipv4Addr, PROTO_UDP};

pub const UDP_HDR_LEN: usize = 8;

fn pseudo_sum(src: Ipv4Addr, dst: Ipv4Addr, len: u16) -> u32 {
    let mut s = checksum_add(0, &src);
    s = checksum_add(s, &dst);
    s + PROTO_UDP as u32 + len as u32
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader { pub src_port: u16, pub dst_port: u16 }

impl UdpHeader {
    pub fn parse(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> Option<(Self, &[u8])> {
        if seg.len() < UDP_HDR_LEN { return None; }
        let len = u16::from_be_bytes([seg[4], seg[5]]) as usize;
        if len < UDP_HDR_LEN || len > seg.len() { return None; }
        let seg = &seg[..len];
        if u16::from_be_bytes([seg[6], seg[7]]) != 0
            && checksum_finish(checksum_add(pseudo_sum(src, dst, len as u16), seg)) != 0
        {
            return None;
        }
        let h = Self {
            src_port: u16::from_be_bytes([seg[0], seg[1]]),
            dst_port: u16::from_be_bytes([seg[2], seg[3]]),
        };
        Some((h, &seg[UDP_HDR_LEN..]))
    }

    /// out[UDP_HDR_LEN..][..payload_len] にペイロードが書かれている前提でヘッダを埋める
    pub fn finish(&self, src: Ipv4Addr, dst: Ipv4Addr, payload_len: usize, out: &mut [u8]) -> usize {
        let len = (UDP_HDR_LEN + payload_len) as u16;
        out[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&len.to_be_bytes());
        out[6..8].copy_from_slice(&[0, 0]);
        let mut c = checksum_finish(checksum_add(pseudo_sum(src, dst, len), &out[..len as usize]));
        if c == 0 { c = 0xFFFF; }
        out[6..8].copy_from_slice(&c.to_be_bytes());
        len as usize
    }
}
