//! L4 (上位): QTLS — SSL/TLS から分岐したセキュアトランスポート。
//!
//! TLS の鍵交換 (ECDHE) と共通鍵暗号 (AES-GCM 等) を廃し、L1 から供給された
//! 使い捨て鍵 (OTP) で次のように 1 レコードずつ保護する。
//!
//! ```text
//!  key[off .. off+32]          → Poly1305 ワンタイム鍵 (r, s)  ─ Wegman-Carter 認証
//!  key[off+32 .. off+32+len]   → XOR パッド                     ─ OTP 暗号化
//! ```
//!
//! 使った鍵バイトは送受信どちらでも即座にゼロ化され、オフセットは単調増加なので
//! 同じ鍵が二度使われることはない。受信側はタグ検証に成功するまで鍵を消費しない
//! (偽レコードによる鍵焼却を防ぐ)。鍵が尽きたら送信を拒否し、古典暗号には落とさない。
//!
//! レコード形式 (ビッグエンディアン):
//! ```text
//!  0      1        2           4             12       14            14+len
//!  | type | version | session_id | key_offset   | length | ciphertext | tag(16) |
//! ```

use qkey::KeyLane;
use uhf::{ct_eq_16, Poly1305, Poly1305Key, POLY1305_KEY_LEN, POLY1305_TAG_LEN};
use zeroize::Zeroize;

use crate::NetError;

pub const QTLS_PORT: u16 = 4433;
pub const QTLS_VERSION: u8 = 1;
pub const RECORD_HDR_LEN: usize = 14;
pub const TAG_LEN: usize = POLY1305_TAG_LEN;
pub const MAC_KEY_LEN: usize = POLY1305_KEY_LEN;
pub const MAX_RECORD_PAYLOAD: usize = 1400;
pub const MAX_RECORD_LEN: usize = RECORD_HDR_LEN + MAX_RECORD_PAYLOAD + TAG_LEN;

/// 1 レコードが消費する鍵バイト数
pub const fn key_cost(payload_len: usize) -> usize { MAC_KEY_LEN + payload_len }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType { Hello = 1, HelloAck = 2, Data = 3, Close = 4 }

impl ContentType {
    fn from_u8(v: u8) -> Option<Self> {
        match v { 1 => Some(Self::Hello), 2 => Some(Self::HelloAck), 3 => Some(Self::Data), 4 => Some(Self::Close), _ => None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub ctype:      ContentType,
    pub session_id: u16,
    pub key_offset: u64,
    pub length:     u16,
}

impl RecordHeader {
    fn write(&self, out: &mut [u8]) {
        out[0] = self.ctype as u8;
        out[1] = QTLS_VERSION;
        out[2..4].copy_from_slice(&self.session_id.to_be_bytes());
        out[4..12].copy_from_slice(&self.key_offset.to_be_bytes());
        out[12..14].copy_from_slice(&self.length.to_be_bytes());
    }

    pub fn parse(rec: &[u8]) -> Result<Self, NetError> {
        if rec.len() < RECORD_HDR_LEN + TAG_LEN || rec[1] != QTLS_VERSION { return Err(NetError::Malformed); }
        let ctype = ContentType::from_u8(rec[0]).ok_or(NetError::Malformed)?;
        let length = u16::from_be_bytes([rec[12], rec[13]]);
        if length as usize > MAX_RECORD_PAYLOAD || rec.len() != RECORD_HDR_LEN + length as usize + TAG_LEN {
            return Err(NetError::Malformed);
        }
        Ok(Self {
            ctype,
            session_id: u16::from_be_bytes([rec[2], rec[3]]),
            key_offset: u64::from_be_bytes(rec[4..12].try_into().unwrap()),
            length,
        })
    }
}

fn mac(key: &[u8], authenticated: &[u8]) -> [u8; TAG_LEN] {
    let k = Poly1305Key::new(key[..MAC_KEY_LEN].try_into().unwrap());
    Poly1305::mac(&k, authenticated)
}

/// 平文を暗号化してレコードを out に書き、長さを返す。鍵は tx レーンから消費する。
pub fn seal(
    tx: &mut KeyLane, ctype: ContentType, session_id: u16, plaintext: &[u8], out: &mut [u8],
) -> Result<usize, NetError> {
    let len = plaintext.len();
    if len > MAX_RECORD_PAYLOAD { return Err(NetError::PayloadTooLarge); }
    let total = RECORD_HDR_LEN + len + TAG_LEN;
    if out.len() < total { return Err(NetError::PayloadTooLarge); }

    let mut key = [0u8; key_cost(MAX_RECORD_PAYLOAD)];
    let key_offset = tx.take(&mut key[..key_cost(len)]).map_err(NetError::Key)?;

    RecordHeader { ctype, session_id, key_offset, length: len as u16 }.write(out);
    let pad = &key[MAC_KEY_LEN..MAC_KEY_LEN + len];
    for ((c, p), k) in out[RECORD_HDR_LEN..RECORD_HDR_LEN + len].iter_mut().zip(plaintext).zip(pad) {
        *c = p ^ k;
    }
    let tag = mac(&key, &out[..RECORD_HDR_LEN + len]);
    out[RECORD_HDR_LEN + len..total].copy_from_slice(&tag);
    key.zeroize();
    Ok(total)
}

/// レコードを検証・復号し、平文を out に書く。タグ検証成功時のみ rx レーンの鍵を消費する。
pub fn open(rx: &mut KeyLane, rec: &[u8], out: &mut [u8]) -> Result<(RecordHeader, usize), NetError> {
    let hdr = RecordHeader::parse(rec)?;
    let len = hdr.length as usize;
    if out.len() < len { return Err(NetError::PayloadTooLarge); }

    let mut key = [0u8; key_cost(MAX_RECORD_PAYLOAD)];
    rx.peek_at(hdr.key_offset, &mut key[..key_cost(len)]).map_err(NetError::Key)?;

    let expected = mac(&key, &rec[..RECORD_HDR_LEN + len]);
    let tag: [u8; TAG_LEN] = rec[RECORD_HDR_LEN + len..].try_into().unwrap();
    if !ct_eq_16(&expected, &tag) {
        key.zeroize();
        return Err(NetError::AuthFailed);
    }
    rx.consume_through(hdr.key_offset, key_cost(len)).map_err(NetError::Key)?;

    let pad = &key[MAC_KEY_LEN..MAC_KEY_LEN + len];
    for ((p, c), k) in out[..len].iter_mut().zip(&rec[RECORD_HDR_LEN..RECORD_HDR_LEN + len]).zip(pad) {
        *p = c ^ k;
    }
    key.zeroize();
    Ok((hdr, len))
}

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;
    use qkey::KeyError;
    use std::boxed::Box;

    fn lanes() -> (Box<KeyLane>, Box<KeyLane>) {
        let mut a = Box::new(KeyLane::new());
        let mut b = Box::new(KeyLane::new());
        let key: std::vec::Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        a.deposit(&key).unwrap();
        b.deposit(&key).unwrap();
        (a, b)
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let (mut tx, mut rx) = lanes();
        let mut rec = [0u8; MAX_RECORD_LEN];
        let n = seal(&mut tx, ContentType::Data, 7, b"quantum hello", &mut rec).unwrap();
        assert_ne!(&rec[RECORD_HDR_LEN..RECORD_HDR_LEN + 13], b"quantum hello");
        let mut pt = [0u8; MAX_RECORD_PAYLOAD];
        let (h, len) = open(&mut rx, &rec[..n], &mut pt).unwrap();
        assert_eq!((h.ctype, h.session_id, h.key_offset), (ContentType::Data, 7, 0));
        assert_eq!(&pt[..len], b"quantum hello");
        assert_eq!(tx.next_offset(), key_cost(13) as u64);
        assert_eq!(rx.next_offset(), key_cost(13) as u64);
    }

    #[test]
    fn test_key_never_reused() {
        let (mut tx, _) = lanes();
        let mut r1 = [0u8; MAX_RECORD_LEN];
        let mut r2 = [0u8; MAX_RECORD_LEN];
        seal(&mut tx, ContentType::Data, 1, b"same", &mut r1).unwrap();
        seal(&mut tx, ContentType::Data, 1, b"same", &mut r2).unwrap();
        assert_ne!(r1[RECORD_HDR_LEN..RECORD_HDR_LEN + 4], r2[RECORD_HDR_LEN..RECORD_HDR_LEN + 4]);
    }

    #[test]
    fn test_tamper_rejected_without_burning_key() {
        let (mut tx, mut rx) = lanes();
        let mut rec = [0u8; MAX_RECORD_LEN];
        let n = seal(&mut tx, ContentType::Data, 1, b"transfer 100", &mut rec).unwrap();
        rec[RECORD_HDR_LEN] ^= 0x01; // 1bit 改ざん (OTP は可鍛性があるので MAC 必須)
        let mut pt = [0u8; MAX_RECORD_PAYLOAD];
        assert_eq!(open(&mut rx, &rec[..n], &mut pt), Err(NetError::AuthFailed));
        assert_eq!(rx.next_offset(), 0);
        rec[RECORD_HDR_LEN] ^= 0x01;
        assert!(open(&mut rx, &rec[..n], &mut pt).is_ok());
    }

    #[test]
    fn test_replay_rejected() {
        let (mut tx, mut rx) = lanes();
        let mut rec = [0u8; MAX_RECORD_LEN];
        let n = seal(&mut tx, ContentType::Data, 1, b"once", &mut rec).unwrap();
        let mut pt = [0u8; MAX_RECORD_PAYLOAD];
        open(&mut rx, &rec[..n], &mut pt).unwrap();
        assert_eq!(open(&mut rx, &rec[..n], &mut pt), Err(NetError::Key(KeyError::AlreadyConsumed)));
    }

    #[test]
    fn test_key_exhaustion_refuses_to_send() {
        let mut tx = Box::new(KeyLane::new());
        tx.deposit(&[1u8; 40]).unwrap();
        let mut rec = [0u8; MAX_RECORD_LEN];
        assert_eq!(seal(&mut tx, ContentType::Data, 1, &[0u8; 9], &mut rec),
                   Err(NetError::Key(KeyError::InsufficientKey)));
    }
}
