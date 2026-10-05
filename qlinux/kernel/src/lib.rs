#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

//! QLinux モノリシックカーネル
//!
//! メモリ管理・スケジューラ・IPC・ドライバ・量子物理層 (qphy)・鍵ストア (qkey)・
//! ネットワークスタック (L2-L4 + QTLS) を単一のカーネルイメージ / 単一アドレス空間に
//! リンクし、サブシステム間は関数呼び出しで直接連携する。
//! 鍵材料はカーネル空間から一切出ず、ユーザ空間は syscall 経由で平文だけを受け渡す。

extern crate drivers_core;
extern crate ipc;
extern crate memory;
extern crate net;
extern crate qkey;
extern crate qphy;
extern crate scheduler;
extern crate syscall;

use core::sync::atomic::{AtomicBool, Ordering};
use ksync::SpinLock;
use net::{NetDevice, NetStack, KERNEL_NET};
use qphy::{PhyError, QedaChipDriver, QuantumLinkDriver, KEY_BLOCK_BYTES};
use zeroize::Zeroize;

/// ノード設定 (将来はブートローダから受け取る)
pub mod config {
    use qkey::LinkRole;
    pub const NODE_IP: [u8; 4] = [10, 0, 0, 1];
    /// 量子リンクの対向ノード
    pub const QLINK_PEER_IP: [u8; 4] = [10, 0, 0, 2];
    /// 量子リンク上の自ノードの役割 (対向ノードは逆を設定する)
    pub const QLINK_ROLE: LinkRole = LinkRole::A;
}

static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);
static QPHY: SpinLock<QedaChipDriver> = SpinLock::new(QedaChipDriver);

#[no_mangle]
pub unsafe extern "C" fn kernel_main() -> ! {
    if KERNEL_INITIALIZED.swap(true, Ordering::SeqCst) {
        unsafe { arch_halt() };
    }
    memory::init();
    drivers_core::init();
    let _ = drivers_core::serial_write_str("QLinux monolithic kernel\n");

    net::init(config::NODE_IP);
    let _ = KERNEL_NET.lock().register_peer(config::QLINK_PEER_IP, config::QLINK_ROLE);
    if qkd_tick() == Err(PhyError::NoDevice) {
        let _ = drivers_core::serial_write_str("[qphy] quantum link not present: QTLS disabled\n");
    }

    // [FIX-3] カーネルイメージ範囲を syscall 層に登録し、ユーザポインタが
    // カーネルのコード・静的データ (鍵を含む) を指すのを拒否させる。
    // _skernel/_ekernel はカーネルのリンカスクリプトが定義するシンボル。
    #[cfg(not(any(test, feature = "std_test")))]
    unsafe {
        extern "C" {
            static _skernel: u8;
            static _ekernel: u8;
        }
        syscall::set_kernel_image(
            &_skernel as *const u8 as usize,
            &_ekernel as *const u8 as usize,
        );
    }

    scheduler::init();
    ipc::init();
    syscall::init();

    loop {
        let _ = qkd_tick();
        KERNEL_NET.lock().poll();
        unsafe { arch_halt() };
    }
}

/// L1 から 1 ブロック分の鍵を受け取り、ネットワークスタックの鍵レーンに積む
pub fn qkd_tick() -> Result<(), PhyError> {
    let mut drv = QPHY.lock();
    let mut stack = KERNEL_NET.lock();
    qkd_pump(&mut *drv, &mut stack, config::QLINK_PEER_IP)
}

pub fn qkd_pump<Q: QuantumLinkDriver, D: NetDevice>(
    drv: &mut Q, stack: &mut NetStack<D>, peer: [u8; 4],
) -> Result<(), PhyError> {
    let mut blk = [0u8; KEY_BLOCK_BYTES];
    let r = drv.harvest_local(&mut blk).map(|seq| {
        // レーン満杯なら破棄 (同じ seq は対向でも同様に溢れる前提; 要フロー制御)
        let _ = stack.deposit_key_block(peer, seq, &blk);
    });
    blk.zeroize();
    r
}

#[inline(always)]
unsafe fn arch_halt() {
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("hlt") };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("wfi") };
}

#[cfg(not(any(test, feature = "std_test")))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // 鍵材料をメモリに残さない
    net::emergency_zeroize();
    let _ = drivers_core::serial_write_str("\n[KERNEL PANIC]\n");
    if let Some(loc) = info.location() {
        let _ = drivers_core::serial_write_str(loc.file());
    }
    loop { unsafe { arch_halt() }; }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::LoopbackDevice;
    use qkey::LinkRole;

    struct FakeLink(u64);
    impl QuantumLinkDriver for FakeLink {
        fn harvest_local(&mut self, out: &mut [u8; KEY_BLOCK_BYTES]) -> Result<u64, PhyError> {
            out.fill(0x5A);
            self.0 += 1;
            Ok(self.0 - 1)
        }
    }

    #[test]
    fn test_qkd_pump_fills_lanes_alternately() {
        let mut stack = Box::new(NetStack::new(LoopbackDevice::new([2, 0, 0, 0, 0, 9])));
        stack.register_peer(config::QLINK_PEER_IP, LinkRole::A).unwrap();
        let mut link = FakeLink(0);
        qkd_pump(&mut link, &mut stack, config::QLINK_PEER_IP).unwrap();
        assert_eq!(stack.key_available(config::QLINK_PEER_IP), Some((KEY_BLOCK_BYTES, 0)));
        qkd_pump(&mut link, &mut stack, config::QLINK_PEER_IP).unwrap();
        assert_eq!(stack.key_available(config::QLINK_PEER_IP), Some((KEY_BLOCK_BYTES, KEY_BLOCK_BYTES)));
    }

    #[test]
    fn test_no_chip_reports_no_device() {
        let mut stack = Box::new(NetStack::new(LoopbackDevice::new([2, 0, 0, 0, 0, 9])));
        assert_eq!(qkd_pump(&mut QedaChipDriver, &mut stack, [0; 4]), Err(PhyError::NoDevice));
    }
}
