//! L2.5: ARP (IPv4 over Ethernet)

use crate::eth::MacAddr;
use crate::ipv4::Ipv4Addr;

pub const ARP_LEN: usize = 28;
pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY:   u16 = 2;
const ARP_FIXED: [u8; 6] = [0x00, 0x01, 0x08, 0x00, 6, 4]; // Ethernet / IPv4 / HLEN=6 / PLEN=4
const CACHE_SIZE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub op:  u16,
    pub sha: MacAddr,
    pub spa: Ipv4Addr,
    pub tha: MacAddr,
    pub tpa: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(p: &[u8]) -> Option<Self> {
        if p.len() < ARP_LEN || p[0..6] != ARP_FIXED { return None; }
        let mut pkt = Self { op: u16::from_be_bytes([p[6], p[7]]), sha: [0; 6], spa: [0; 4], tha: [0; 6], tpa: [0; 4] };
        pkt.sha.copy_from_slice(&p[8..14]);
        pkt.spa.copy_from_slice(&p[14..18]);
        pkt.tha.copy_from_slice(&p[18..24]);
        pkt.tpa.copy_from_slice(&p[24..28]);
        Some(pkt)
    }

    pub fn write(&self, out: &mut [u8]) -> usize {
        out[0..6].copy_from_slice(&ARP_FIXED);
        out[6..8].copy_from_slice(&self.op.to_be_bytes());
        out[8..14].copy_from_slice(&self.sha);
        out[14..18].copy_from_slice(&self.spa);
        out[18..24].copy_from_slice(&self.tha);
        out[24..28].copy_from_slice(&self.tpa);
        ARP_LEN
    }
}

pub struct ArpCache {
    entries: [Option<(Ipv4Addr, MacAddr)>; CACHE_SIZE],
    next:    usize,
}

impl ArpCache {
    pub const fn new() -> Self { Self { entries: [None; CACHE_SIZE], next: 0 } }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.entries.iter().flatten().find(|(i, _)| *i == ip).map(|(_, m)| *m)
    }

    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        if let Some(e) = self.entries.iter_mut().flatten().find(|(i, _)| *i == ip) {
            e.1 = mac;
            return;
        }
        self.entries[self.next] = Some((ip, mac));
        self.next = (self.next + 1) % CACHE_SIZE;
    }
}
