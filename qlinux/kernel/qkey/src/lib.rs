#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! カーネル空間の使い捨て鍵ストア。
//!
//! L1 (qphy) が両端ノードに同一の鍵ストリームを供給し、本クレートはそれを
//! 方向ごとの「レーン」に積む。鍵バイトは絶対オフセット (u64) で識別され、
//! 一度取り出したオフセット以前のバイトは即座にゼロ化され二度と使えない。
//!
//! レーン割り当て: L1 リンク上の役割が A のノードは lane0 で送信・lane1 で受信、
//! B のノードはその逆。これにより双方向で同じ鍵バイトを使うことはない。

#[cfg(feature = "std_test")]
extern crate std;

use zeroize::Zeroize;

/// 1レーンあたりの保持容量
pub const LANE_CAPACITY: usize = 16 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// 鍵が足りない。古典暗号へのフォールバックは行わない
    InsufficientKey,
    /// 既に消費済みのオフセット (鍵の再利用・リプレイ)
    AlreadyConsumed,
    /// 1 ブロックが大きすぎてレーンに収まらない
    BlockTooLarge,
    EmptyInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkRole { A = 0, B = 1 }

impl LinkRole {
    pub const fn tx_lane(self) -> usize { self as usize }
    pub const fn rx_lane(self) -> usize { 1 - self as usize }
}

/// 絶対オフセット付きリングバッファ
pub struct KeyLane {
    buf:   [u8; LANE_CAPACITY],
    read:  usize,
    count: usize,
    /// buf[read] の絶対オフセット
    base:  u64,
}

impl KeyLane {
    pub const fn new() -> Self {
        Self { buf: [0u8; LANE_CAPACITY], read: 0, count: 0, base: 0 }
    }

    pub fn available(&self) -> usize { self.count }
    pub fn next_offset(&self) -> u64 { self.base }

    /// [FIX-4] 鍵ストリーム上のスライディングウィンドウ。満杯なら最古の未使用バイトを
    /// 破棄して受け入れる。こうすると両端が同じ絶対オフセットに同じバイトを持つ性質が保たれ、
    /// パケット欠落で消費が片側だけ進んでも、相手の窓は現在のオフセットを追い越さず再同期できる。
    pub fn deposit(&mut self, key: &[u8]) -> Result<(), KeyError> {
        if key.is_empty() { return Err(KeyError::EmptyInput); }
        if key.len() > LANE_CAPACITY { return Err(KeyError::BlockTooLarge); }
        let overflow = (self.count + key.len()).saturating_sub(LANE_CAPACITY);
        if overflow > 0 { self.discard(overflow); } // 最古の未使用鍵を捨てて窓を進める
        let mut w = (self.read + self.count) % LANE_CAPACITY;
        for &b in key {
            self.buf[w] = b;
            w = (w + 1) % LANE_CAPACITY;
        }
        self.count += key.len();
        Ok(())
    }

    /// 送信側: 先頭から out.len() バイトを取り出し、その開始オフセットを返す
    pub fn take(&mut self, out: &mut [u8]) -> Result<u64, KeyError> {
        if out.is_empty() { return Err(KeyError::EmptyInput); }
        if out.len() > self.count { return Err(KeyError::InsufficientKey); }
        let off = self.base;
        self.copy_out(0, out);
        self.discard(out.len());
        Ok(off)
    }

    /// 受信側: offset から out.len() バイトを消費せずに読む (タグ検証用)。
    /// [FIX-4] 任意オフセットへの読み飛ばし制限は設けない。偽オフセットのレコードは
    /// ワンタイム Poly1305 タグ検証で必ず弾かれ、鍵は消費されない (consume は検証後のみ)。
    /// バッファ外のオフセットは InsufficientKey で読めないだけで、鍵は焼かれない。
    pub fn peek_at(&self, offset: u64, out: &mut [u8]) -> Result<(), KeyError> {
        if out.is_empty() { return Err(KeyError::EmptyInput); }
        // [FIX-OVF] 攻撃者が制御する offset (タグ検証前) による整数オーバーフローを防ぐ。
        // u64 のまま checked 演算し、範囲内が確定してから usize へ落とす。
        let skip = offset.checked_sub(self.base).ok_or(KeyError::AlreadyConsumed)?;
        let need = skip.checked_add(out.len() as u64).ok_or(KeyError::InsufficientKey)?;
        if need > self.count as u64 { return Err(KeyError::InsufficientKey); }
        // ここで skip <= count <= LANE_CAPACITY が保証されるので usize キャストは安全
        self.copy_out(skip as usize, out);
        Ok(())
    }

    /// 受信側: offset + len までの全バイトを破棄する (欠落パケット分も含む)
    pub fn consume_through(&mut self, offset: u64, len: usize) -> Result<(), KeyError> {
        // [FIX-OVF] peek_at と同じく checked 演算でオーバーフローを防ぐ
        let skip = offset.checked_sub(self.base).ok_or(KeyError::AlreadyConsumed)?;
        let end = skip.checked_add(len as u64).ok_or(KeyError::InsufficientKey)?;
        if end > self.count as u64 { return Err(KeyError::InsufficientKey); }
        self.discard(end as usize);
        Ok(())
    }

    fn copy_out(&self, skip: usize, out: &mut [u8]) {
        let mut r = (self.read + skip) % LANE_CAPACITY;
        for b in out.iter_mut() {
            *b = self.buf[r];
            r = (r + 1) % LANE_CAPACITY;
        }
    }

    fn discard(&mut self, n: usize) {
        for _ in 0..n {
            self.buf[self.read] = 0;
            self.read = (self.read + 1) % LANE_CAPACITY;
        }
        self.count -= n;
        self.base += n as u64;
    }

    pub fn wipe(&mut self) {
        self.buf.zeroize();
        self.base += self.count as u64;
        self.count = 0;
        self.read = 0;
    }
}

/// 1 ピア分の鍵 (送信レーン・受信レーン)
pub struct PeerKeys {
    pub role:  LinkRole,
    pub lanes: [KeyLane; 2],
}

impl PeerKeys {
    pub const fn new(role: LinkRole) -> Self {
        Self { role, lanes: [KeyLane::new(), KeyLane::new()] }
    }
    pub fn tx(&mut self) -> &mut KeyLane { &mut self.lanes[self.role.tx_lane()] }
    pub fn rx(&mut self) -> &mut KeyLane { &mut self.lanes[self.role.rx_lane()] }
    pub fn tx_ref(&self) -> &KeyLane { &self.lanes[self.role.tx_lane()] }
    pub fn rx_ref(&self) -> &KeyLane { &self.lanes[self.role.rx_lane()] }

    /// L1 から届いた block_seq 番目の鍵ブロックを積む。
    /// 両端で同じ seq → 同じレーンになるので、偶奇でレーンを交互に割り当てる。
    pub fn deposit_block(&mut self, block_seq: u64, key: &[u8]) -> Result<(), KeyError> {
        self.lanes[(block_seq & 1) as usize].deposit(key)
    }

    pub fn wipe(&mut self) {
        for l in self.lanes.iter_mut() { l.wipe(); }
    }
}

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;
    use std::boxed::Box;

    #[test]
    fn test_take_advances_offset_and_zeroizes() {
        let mut l = Box::new(KeyLane::new());
        l.deposit(&[1, 2, 3, 4, 5]).unwrap();
        let mut k = [0u8; 3];
        assert_eq!(l.take(&mut k).unwrap(), 0);
        assert_eq!(k, [1, 2, 3]);
        assert_eq!(l.next_offset(), 3);
        assert_eq!(l.buf[0], 0);
        assert_eq!(l.take(&mut [0u8; 3]), Err(KeyError::InsufficientKey));
    }

    #[test]
    fn test_rx_replay_rejected() {
        let mut l = Box::new(KeyLane::new());
        l.deposit(&[9u8; 64]).unwrap();
        let mut k = [0u8; 16];
        l.peek_at(16, &mut k).unwrap();
        l.consume_through(16, 16).unwrap();
        assert_eq!(l.peek_at(16, &mut k), Err(KeyError::AlreadyConsumed));
        assert_eq!(l.peek_at(0, &mut k), Err(KeyError::AlreadyConsumed));
        assert_eq!(l.available(), 32);
    }

    #[test]
    fn test_peek_beyond_buffer_rejected_but_keeps_key() {
        let mut l = Box::new(KeyLane::new());
        l.deposit(&[0u8; 64]).unwrap();
        // バッファ外のオフセットは読めないが、鍵は焼かれない (base は動かない)
        assert_eq!(l.peek_at(1000, &mut [0u8; 1]), Err(KeyError::InsufficientKey));
        assert_eq!(l.next_offset(), 0);
        assert_eq!(l.available(), 64);
    }

    #[test]
    fn test_huge_offset_does_not_overflow() {
        // [FIX-OVF] 攻撃者が巨大な key_offset を送ってもパニック/オーバーフローしない
        let mut l = Box::new(KeyLane::new());
        l.deposit(&[7u8; 64]).unwrap();
        // base を少し進めておく (offset-base の減算と加算の両方を試す)
        l.take(&mut [0u8; 8]).unwrap();
        // いずれも「パニックせずエラーを返し、鍵を消費しない」ことが保証
        for off in [u64::MAX, u64::MAX - 7, 1u64 << 63, usize::MAX as u64] {
            assert!(l.peek_at(off, &mut [0u8; 16]).is_err());
            assert!(l.consume_through(off, 16).is_err());
        }
        // 巨大だが base より大きい offset は InsufficientKey (AlreadyConsumed ではない)
        assert_eq!(l.peek_at(u64::MAX, &mut [0u8; 16]), Err(KeyError::InsufficientKey));
        // 鍵は一切消費されていない
        assert_eq!(l.next_offset(), 8);
        assert_eq!(l.available(), 56);
    }

    #[test]
    fn test_consume_fast_forwards_over_gap() {
        // [FIX-4] 欠落で受信側が遅れても、先のオフセットのレコードで追いつける
        let mut l = Box::new(KeyLane::new());
        l.deposit(&[5u8; 512]).unwrap();
        let mut k = [0u8; 16];
        l.peek_at(300, &mut k).unwrap();          // 300 は窓内 (旧 MAX_RX_SKIP=8192 を超える値でも可)
        l.consume_through(300, 16).unwrap();        // 0..316 を破棄して追従
        assert_eq!(l.next_offset(), 316);
        assert_eq!(l.available(), 512 - 316);
    }

    #[test]
    fn test_wraparound() {
        let mut l = Box::new(KeyLane::new());
        l.deposit(&[1u8; LANE_CAPACITY - 4]).unwrap();
        l.take(&mut [0u8; LANE_CAPACITY - 8]).unwrap();
        l.deposit(&[7u8; 8]).unwrap();
        let mut k = [0u8; 12];
        l.take(&mut k).unwrap();
        assert_eq!(k, [1, 1, 1, 1, 7, 7, 7, 7, 7, 7, 7, 7]);
    }

    #[test]
    fn test_deposit_slides_when_full() {
        // [FIX-4] 満杯のレーンにさらに積むと最古の未使用鍵が捨てられ、base が進む
        let mut l = Box::new(KeyLane::new());
        l.deposit(&[1u8; LANE_CAPACITY]).unwrap();
        assert_eq!(l.next_offset(), 0);
        l.deposit(&[2u8; 100]).unwrap();
        assert_eq!(l.next_offset(), 100);           // 先頭 100B が滑って破棄
        assert_eq!(l.available(), LANE_CAPACITY);
        // 1 ブロックがレーンより大きい場合だけ拒否
        assert_eq!(l.deposit(&[0u8; LANE_CAPACITY + 1]), Err(KeyError::BlockTooLarge));
    }

    #[test]
    fn test_roles_are_mirrored() {
        assert_eq!(LinkRole::A.tx_lane(), LinkRole::B.rx_lane());
        assert_eq!(LinkRole::B.tx_lane(), LinkRole::A.rx_lane());
    }
}
