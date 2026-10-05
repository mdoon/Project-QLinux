#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! QLinux カーネル内ネットワークスタック。
//!
//! ```text
//!  L4+ QTLS     OTP(XOR) + ワンタイム Poly1305   ← qkey の使い捨て鍵
//!  L4  UDP
//!  L3  IPv4
//!  L2  Ethernet / ARP
//!  L1  NIC (古典)            +  qphy (量子: エンタングルメント / 高密度符号 / テレポーテーション)
//! ```

#[cfg(feature = "std_test")]
extern crate std;

pub mod arp;
pub mod device;
pub mod eth;
pub mod ipv4;
pub mod qtls;
pub mod stack;
pub mod udp;

use ksync::SpinLock;
use qkey::KeyError;

pub use device::{LoopbackDevice, NetDevice};
pub use stack::{NetStack, SessionHandle, SessionState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    ArpPending,
    NoPeer,
    NoSession,
    NotEstablished,
    WouldBlock,
    AuthFailed,
    Malformed,
    PayloadTooLarge,
    DeviceFull,
    TableFull,
    Key(KeyError),
}

/// カーネルが使う NIC。virtio-net / e1000 ドライバ実装までは Loopback
pub type KernelNic = LoopbackDevice;

pub const KERNEL_MAC: eth::MacAddr = [0x02, 0x51, 0x4C, 0x00, 0x00, 0x01];

/// モノリシックカーネル唯一のネットワークスタック。syscall 層から直接呼ばれる
pub static KERNEL_NET: SpinLock<NetStack<KernelNic>> =
    SpinLock::new(NetStack::new(LoopbackDevice::new(KERNEL_MAC)));

pub fn init(ip: ipv4::Ipv4Addr) {
    KERNEL_NET.lock().configure(ip);
}

/// パニック時などに全鍵材料を消去する。
/// [FIX-5] ネットワーク処理の途中 (ロック保持中) でパニックしても確実に消すため、
/// ロックを取れなければ強制アクセスで消去する。単一コアでパニック後は他に実行文脈が
/// 無いため、ここでの強制アクセスは安全。
pub fn emergency_zeroize() {
    if let Some(mut s) = KERNEL_NET.try_lock() {
        s.wipe_keys();
    } else {
        // SAFETY: パニック経路。スケジューラ・割り込みは停止し、他に KERNEL_NET へ
        // アクセスする文脈は存在しない。鍵を残すより強制消去を優先する。
        unsafe { KERNEL_NET.force_get_mut().wipe_keys(); }
    }
}

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;
    use eth::MacAddr;
    use qkey::LinkRole;
    use qphy::{ChannelModel, KeyMode, SimQuantumLink, XorShift64};
    use std::boxed::Box;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::vec::Vec;

    type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

    /// 2 台を直結する Ethernet ケーブル。tap で盗聴・改ざんできる
    struct WireNic { mac: MacAddr, tx: Queue, rx: Queue }

    impl NetDevice for WireNic {
        fn mac(&self) -> MacAddr { self.mac }
        fn transmit(&mut self, f: &[u8]) -> Result<(), NetError> { self.tx.borrow_mut().push_back(f.to_vec()); Ok(()) }
        fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
            let f = self.rx.borrow_mut().pop_front()?;
            buf[..f.len()].copy_from_slice(&f);
            Some(f.len())
        }
    }

    const IP_A: [u8; 4] = [10, 0, 0, 1];
    const IP_B: [u8; 4] = [10, 0, 0, 2];

    struct Net { a: Box<NetStack<WireNic>>, b: Box<NetStack<WireNic>>, a_to_b: Queue }

    fn pair(mode: KeyMode, blocks: usize) -> Net {
        let (ab, ba): (Queue, Queue) = Default::default();
        let mut a = Box::new(NetStack::new(WireNic { mac: [2, 0, 0, 0, 0, 1], tx: ab.clone(), rx: ba.clone() }));
        let mut b = Box::new(NetStack::new(WireNic { mac: [2, 0, 0, 0, 0, 2], tx: ba.clone(), rx: ab.clone() }));
        a.configure(IP_A);
        b.configure(IP_B);
        a.register_peer(IP_B, LinkRole::A).unwrap();
        b.register_peer(IP_A, LinkRole::B).unwrap();

        // L1: 量子リンクが両端に同じ鍵ブロックを配る
        let mut link = SimQuantumLink::new(XorShift64::new(42), ChannelModel::IDEAL, mode);
        for _ in 0..blocks {
            let blk = link.harvest().unwrap();
            a.deposit_key_block(IP_B, blk.seq, &blk.a).unwrap();
            b.deposit_key_block(IP_A, blk.seq, &blk.b).unwrap();
        }
        Net { a, b, a_to_b: ab }
    }

    fn pump(n: &mut Net) { for _ in 0..4 { n.a.poll(); n.b.poll(); } }

    fn handshake(n: &mut Net) -> (SessionHandle, SessionHandle) {
        n.b.listen(qtls::QTLS_PORT).unwrap();
        assert_eq!(n.a.connect(IP_B, qtls::QTLS_PORT), Err(NetError::ArpPending));
        pump(n);
        let ca = n.a.connect(IP_B, qtls::QTLS_PORT).unwrap();
        pump(n);
        assert_eq!(n.a.state(ca), SessionState::Established);
        let sb = n.b.accept(qtls::QTLS_PORT).expect("server accepted");
        (ca, sb)
    }

    #[test]
    fn test_end_to_end_all_key_modes() {
        for mode in [KeyMode::Entanglement, KeyMode::SuperdenseCoding, KeyMode::Teleportation] {
            let mut n = pair(mode, 8);
            let (ca, sb) = handshake(&mut n);
            n.a.send(ca, b"entangled greetings").unwrap();
            pump(&mut n);
            let mut buf = [0u8; 64];
            let len = n.b.recv(sb, &mut buf).unwrap();
            assert_eq!(&buf[..len], b"entangled greetings");

            n.b.send(sb, b"ack").unwrap();
            pump(&mut n);
            let len = n.a.recv(ca, &mut buf).unwrap();
            assert_eq!(&buf[..len], b"ack");
        }
    }

    #[test]
    fn test_wire_carries_no_plaintext() {
        let mut n = pair(KeyMode::Entanglement, 8);
        let (ca, _) = handshake(&mut n);
        n.a.send(ca, b"TOP-SECRET-PAYLOAD").unwrap();
        let frame = n.a_to_b.borrow().back().unwrap().clone();
        assert!(!frame.windows(18).any(|w| w == b"TOP-SECRET-PAYLOAD"));
    }

    #[test]
    fn test_tampered_frame_dropped() {
        let mut n = pair(KeyMode::Entanglement, 8);
        let (ca, sb) = handshake(&mut n);
        n.a.send(ca, b"pay 100").unwrap();
        {
            let mut q = n.a_to_b.borrow_mut();
            let f = q.back_mut().unwrap();
            let i = f.len() - 20; // 暗号文の 1 バイト
            f[i] ^= 0x04;
            // UDP チェックサムを無効化して QTLS まで届かせる (攻撃者は再計算できる)
            let udp_ck = 14 + 20 + 6;
            f[udp_ck] = 0; f[udp_ck + 1] = 0;
        }
        pump(&mut n);
        assert_eq!(n.b.recv(sb, &mut [0u8; 64]), Err(NetError::WouldBlock));
    }

    #[test]
    fn test_unknown_host_cannot_connect() {
        let mut n = pair(KeyMode::Entanglement, 2);
        assert_eq!(n.a.connect([10, 0, 0, 99], qtls::QTLS_PORT), Err(NetError::NoPeer));
    }

    #[test]
    fn test_send_refused_when_keys_exhausted() {
        let mut n = pair(KeyMode::Entanglement, 2); // tx/rx 各 256B
        let (ca, _) = handshake(&mut n);
        let (tx, _) = n.a.key_available(IP_B).unwrap();
        assert!(tx < qtls::key_cost(300));
        assert_eq!(n.a.send(ca, &[0u8; 300]), Err(NetError::Key(KeyError::InsufficientKey)));
    }

    #[test]
    fn test_kernel_global_stack_and_zeroize() {
        init([10, 0, 0, 1]);
        {
            let mut s = KERNEL_NET.lock();
            s.register_peer(IP_B, LinkRole::A).unwrap();
            s.deposit_key_block(IP_B, 0, &[0xAA; 64]).unwrap();
            assert_eq!(s.key_available(IP_B), Some((64, 0)));
        }
        emergency_zeroize();
        assert_eq!(KERNEL_NET.lock().key_available(IP_B), Some((0, 0)));
    }
}
