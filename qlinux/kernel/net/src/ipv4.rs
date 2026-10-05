//! L3: IPv4 (オプション・フラグメント非対応、DF 付きで送信)

pub type Ipv4Addr = [u8; 4];

pub const IPV4_HDR_LEN: usize = 20;
pub const PROTO_UDP: u8 = 17;
const DEFAULT_TTL: u8 = 64;
const FLAG_DF: u16 = 0x4000;

pub fn checksum_add(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks { sum += u16::from_be_bytes([c[0], c[1]]) as u32; }
    if let [b] = chunks.remainder() { sum += (*b as u32) << 8; }
    sum
}

pub fn checksum_finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub src:      Ipv4Addr,
    pub dst:      Ipv4Addr,
    pub protocol: u8,
    pub ttl:      u8,
    pub id:       u16,
}

impl Ipv4Header {
    /// ヘッダ検証済みのペイロードを返す
    pub fn parse(p: &[u8]) -> Option<(Self, &[u8])> {
        if p.len() < IPV4_HDR_LEN || p[0] >> 4 != 4 { return None; }
        let ihl = ((p[0] & 0x0F) as usize) * 4;
        let total = u16::from_be_bytes([p[2], p[3]]) as usize;
        if ihl < IPV4_HDR_LEN || total < ihl || total > p.len() { return None; }
        if checksum_finish(checksum_add(0, &p[..ihl])) != 0 { return None; }
        let frag = u16::from_be_bytes([p[6], p[7]]);
        if frag & 0x3FFF != 0 { return None; } // MF またはオフセット付きは破棄
        let mut h = Self { src: [0; 4], dst: [0; 4], protocol: p[9], ttl: p[8], id: u16::from_be_bytes([p[4], p[5]]) };
        h.src.copy_from_slice(&p[12..16]);
        h.dst.copy_from_slice(&p[16..20]);
        Some((h, &p[ihl..total]))
    }

    pub fn write(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, id: u16, payload_len: usize, out: &mut [u8]) -> usize {
        let total = (IPV4_HDR_LEN + payload_len) as u16;
        out[0] = 0x45;
        out[1] = 0;
        out[2..4].copy_from_slice(&total.to_be_bytes());
        out[4..6].copy_from_slice(&id.to_be_bytes());
        out[6..8].copy_from_slice(&FLAG_DF.to_be_bytes());
        out[8] = DEFAULT_TTL;
        out[9] = protocol;
        out[10..12].copy_from_slice(&[0, 0]);
        out[12..16].copy_from_slice(&src);
        out[16..20].copy_from_slice(&dst);
        let c = checksum_finish(checksum_add(0, &out[..IPV4_HDR_LEN]));
        out[10..12].copy_from_slice(&c.to_be_bytes());
        IPV4_HDR_LEN
    }
}
