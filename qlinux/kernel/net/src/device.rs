//! NIC ドライバインタフェース

use crate::eth::{MacAddr, MAX_FRAME};
use crate::NetError;

pub trait NetDevice {
    fn mac(&self) -> MacAddr;
    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError>;
    /// 受信フレームがあれば buf にコピーして長さを返す
    fn receive(&mut self, buf: &mut [u8]) -> Option<usize>;
}

const LOOPBACK_SLOTS: usize = 4;

/// 送信フレームを自分自身に返すデバイス (virtio-net 実装までの暫定 NIC)
pub struct LoopbackDevice {
    mac:   MacAddr,
    slots: [[u8; MAX_FRAME]; LOOPBACK_SLOTS],
    lens:  [usize; LOOPBACK_SLOTS],
    head:  usize,
    count: usize,
}

impl LoopbackDevice {
    pub const fn new(mac: MacAddr) -> Self {
        Self { mac, slots: [[0; MAX_FRAME]; LOOPBACK_SLOTS], lens: [0; LOOPBACK_SLOTS], head: 0, count: 0 }
    }
}

impl NetDevice for LoopbackDevice {
    fn mac(&self) -> MacAddr { self.mac }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if frame.len() > MAX_FRAME { return Err(NetError::PayloadTooLarge); }
        if self.count == LOOPBACK_SLOTS { return Err(NetError::DeviceFull); }
        let slot = (self.head + self.count) % LOOPBACK_SLOTS;
        self.slots[slot][..frame.len()].copy_from_slice(frame);
        self.lens[slot] = frame.len();
        self.count += 1;
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.count == 0 { return None; }
        let n = self.lens[self.head].min(buf.len());
        buf[..n].copy_from_slice(&self.slots[self.head][..n]);
        self.slots[self.head][..n].fill(0);
        self.head = (self.head + 1) % LOOPBACK_SLOTS;
        self.count -= 1;
        Some(n)
    }
}
