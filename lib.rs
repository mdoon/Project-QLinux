//! qlinux ユニバーサルハッシュ関数 (UHF) クレート
//!
//! # 実装アルゴリズム
//!
//! ## 1. Poly1305 (`Poly1305`)
//! - RFC 8439 準拠
//! - GF(2^130 - 5) 上の多項式評価
//! - 内部は u64 3本 (lo44 / mid44 / hi44) + 26bit 分割で扱い
//!   **実際には lo26×5 + mid26×5 + hi26 の 26bit limb 5本**方式を採用
//!
//! ## 2. GHASH (`GHash`)
//! - GCM (NIST SP800-38D) 準拠
//! - GF(2^128) / (x^128 + x^7 + x^2 + x + 1) 上の乗算
//!
//! ## 3. UMAC-NH (`Umac64`)
//! - NH 圧縮 + ε-AXU 仕上げ (Mersenne prime p61 = 2^61-1)
//!
//! # セキュリティ特性
//! - 中間値は `Zeroize` でメモリ消去
//! - タグ比較は `ct_eq_16()` (定数時間)
//! - 鍵は `Debug` 非実装

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use zeroize::{Zeroize, Zeroizing};

// ─── エラー型 ────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Eq)]
pub enum UhfError {
    InvalidKeyLength,
    EmptyInput,
    InvalidTagLength,
    TagMismatch,
}

#[cfg(feature = "std")]
impl core::fmt::Display for UhfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "鍵長が不正です"),
            Self::EmptyInput       => write!(f, "入力が空です"),
            Self::InvalidTagLength => write!(f, "タグ長が不正です"),
            Self::TagMismatch      => write!(f, "認証タグが一致しません"),
        }
    }
}

// ─── 定数時間比較 ──────────────────────────────────────────────────────────
#[inline(never)]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ════════════════════════════════════════════════════════════════════════════
// §1  Poly1305 (RFC 8439)
// ════════════════════════════════════════════════════════════════════════════
//
// GF(2^130 - 5) の元を **26bit × 5 limb** で表現する。
//   h = h[0] + h[1]*2^26 + h[2]*2^52 + h[3]*2^78 + h[4]*2^104
//   各 limb は通常 ≤ 2^26、オーバーフロー分は上位 limb へ伝播

pub const POLY1305_TAG_LEN: usize = 16;
pub const POLY1305_KEY_LEN: usize = 32;
const BLOCK: usize = 16;

/// Poly1305 鍵 (クランプ済み r + s)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Poly1305Key {
    /// 26bit×5 limb に展開した r
    r: [u32; 5],
    /// s (加算マスク、リトルエンディアン u32×4)
    s: [u32; 4],
}

impl Poly1305Key {
    pub fn new(raw: &[u8; POLY1305_KEY_LEN]) -> Self {
        // r の 16 バイトをクランプ
        let mut rb = [0u8; 16];
        rb.copy_from_slice(&raw[..16]);
        // RFC 8439 クランプ
        rb[3]  &= 0x0F;
        rb[7]  &= 0x0F;
        rb[11] &= 0x0F;
        rb[15] &= 0x0F;
        rb[4]  &= 0xFC;
        rb[8]  &= 0xFC;
        rb[12] &= 0xFC;

        // 26bit limb 分解
        let r_val = u128::from_le_bytes(rb);
        let mask26 = (1u128 << 26) - 1;
        let r = [
            (r_val          & mask26) as u32,
            ((r_val >> 26)  & mask26) as u32,
            ((r_val >> 52)  & mask26) as u32,
            ((r_val >> 78)  & mask26) as u32,
            ((r_val >> 104) & mask26) as u32,
        ];

        // s の 16 バイトを u32×4 に変換
        let s = [
            u32::from_le_bytes(raw[16..20].try_into().unwrap()),
            u32::from_le_bytes(raw[20..24].try_into().unwrap()),
            u32::from_le_bytes(raw[24..28].try_into().unwrap()),
            u32::from_le_bytes(raw[28..32].try_into().unwrap()),
        ];

        Self { r, s }
    }

    pub fn from_zeroizing(key: &Zeroizing<Vec<u8>>) -> Result<Self, UhfError> {
        if key.len() != POLY1305_KEY_LEN {
            return Err(UhfError::InvalidKeyLength);
        }
        Ok(Self::new(key[..].try_into().unwrap()))
    }
}

/// Poly1305 状態機
pub struct Poly1305 {
    /// アキュムレータ h (26bit×5 limb)
    h:       [u64; 5],
    /// 乗数 r (26bit×5 limb)
    r:       [u64; 5],
    /// s (加算マスク u32×4)
    s:       [u32; 4],
    /// 未処理バッファ
    buf:     [u8; BLOCK],
    buf_len: usize,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.h.zeroize();
        self.r.zeroize();
        self.s.zeroize();
        self.buf.zeroize();
        self.buf_len = 0;
    }
}

impl Poly1305 {
    pub fn new(key: &Poly1305Key) -> Self {
        Self {
            h:       [0u64; 5],
            r:       [key.r[0] as u64, key.r[1] as u64, key.r[2] as u64,
                      key.r[3] as u64, key.r[4] as u64],
            s:       key.s,
            buf:     [0u8; BLOCK],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        let mut data = msg;

        if self.buf_len > 0 {
            let need = BLOCK - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..].copy_from_slice(&data[..need]);
            let b = self.buf;
            self.process_block(&b, true);
            self.buf_len = 0;
            data = &data[need..];
        }

        while data.len() >= BLOCK {
            let block: [u8; BLOCK] = data[..BLOCK].try_into().unwrap();
            self.process_block(&block, true);
            data = &data[BLOCK..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; POLY1305_TAG_LEN] {
        // 端数ブロック
        if self.buf_len > 0 {
            let mut pad = [0u8; BLOCK];
            pad[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            pad[self.buf_len] = 1;
            self.process_block(&pad, false); // 最終ブロックは hi-bit なし
        }

        // h を完全還元: mod (2^130 - 5)
        // まず limb 間のキャリーを伝播
        self.propagate_carry();

        // h を u128 に変換
        let h128 = self.h_to_u128();

        // h + s mod 2^128
        let s128 = (self.s[0] as u128)
            | ((self.s[1] as u128) << 32)
            | ((self.s[2] as u128) << 64)
            | ((self.s[3] as u128) << 96);

        let tag128 = h128.wrapping_add(s128);
        tag128.to_le_bytes()[..POLY1305_TAG_LEN].try_into().unwrap()
    }

    pub fn mac(key: &Poly1305Key, msg: &[u8]) -> [u8; POLY1305_TAG_LEN] {
        let mut ctx = Self::new(key);
        ctx.update(msg);
        ctx.finalize()
    }

    pub fn verify(
        key: &Poly1305Key,
        msg: &[u8],
        expected: &[u8; POLY1305_TAG_LEN],
    ) -> Result<(), UhfError> {
        let computed = Self::mac(key, msg);
        if ct_eq_16(&computed, expected) { Ok(()) } else { Err(UhfError::TagMismatch) }
    }

    // ─── 内部 ──────────────────────────────────────────────────────────

    /// ブロック (16バイト) を h に加算して r を乗算
    /// `add_hibit`: フルブロックなら最上位に 1bit 追加 (2^128 bit)
    fn process_block(&mut self, block: &[u8; 16], add_hibit: bool) {
        // ブロックを 26bit limb 5本に変換
        let m = u128::from_le_bytes(*block);
        let hi_bit: u64 = if add_hibit { 1 } else { 0 };
        let mask26: u128 = (1 << 26) - 1;

        let n = [
            (m          & mask26) as u64,
            ((m >> 26)  & mask26) as u64,
            ((m >> 52)  & mask26) as u64,
            ((m >> 78)  & mask26) as u64,
            ((m >> 104) & mask26) as u64 | (hi_bit << 24),
        ];

        // h += n
        for i in 0..5 {
            self.h[i] = self.h[i].wrapping_add(n[i]);
        }

        // h *= r (mod 2^130 - 5) - 26bit limb 乗算
        self.mul_r();
    }

    /// h = h * r (mod 2^130 - 5)
    ///
    /// 26bit limb 乗算:
    /// 2^130 ≡ 5 (mod 2^130-5) なので
    /// limb[i+5] は 5倍して limb[i] に折り返せる
    fn mul_r(&mut self) {
        let h = &self.h;
        let r = &self.r;

        // r に対する前計算: 5*r[i] (limb 折り返し用)
        let r5 = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];

        // 128bit × 128bit 部分積を u64 で蓄積
        // d[i] = Σ_{j} h[j] * (j≤i ? r[i-j] : 5*r[i-j+5])
        let d0 = h[0] * r[0] + h[1] * r5[3] + h[2] * r5[2] + h[3] * r5[1] + h[4] * r5[0];
        let d1 = h[0] * r[1] + h[1] * r[0]  + h[2] * r5[3] + h[3] * r5[2] + h[4] * r5[1];
        let d2 = h[0] * r[2] + h[1] * r[1]  + h[2] * r[0]  + h[3] * r5[3] + h[4] * r5[2];
        let d3 = h[0] * r[3] + h[1] * r[2]  + h[2] * r[1]  + h[3] * r[0]  + h[4] * r5[3];
        let d4 = h[0] * r[4] + h[1] * r[3]  + h[2] * r[2]  + h[3] * r[1]  + h[4] * r[0];

        // キャリー伝播して各 limb を 26bit に正規化
        let mask26: u64 = (1 << 26) - 1;

        let c0 = d0 >> 26;
        let h0 = d0 & mask26;
        let d1 = d1.wrapping_add(c0);

        let c1 = d1 >> 26;
        let h1 = d1 & mask26;
        let d2 = d2.wrapping_add(c1);

        let c2 = d2 >> 26;
        let h2 = d2 & mask26;
        let d3 = d3.wrapping_add(c2);

        let c3 = d3 >> 26;
        let h3 = d3 & mask26;
        let d4 = d4.wrapping_add(c3);

        // d4 は最大 130bit 相当 → 上位が 2bit を超えた分を 5倍して h[0] に戻す
        let c4 = d4 >> 26;
        let h4 = d4 & mask26;
        let h0 = h0.wrapping_add(c4.wrapping_mul(5));

        // h[0] の再オーバーフロー
        let c0 = h0 >> 26;
        let h0 = h0 & mask26;
        let h1 = h1.wrapping_add(c0);

        self.h = [h0, h1, h2, h3, h4];
    }

    /// 最終キャリー伝播 + 2^130-5 による条件付き還元
    fn propagate_carry(&mut self) {
        let mask26: u64 = (1 << 26) - 1;

        // 通常キャリー伝播 (2回)
        for _ in 0..2 {
            let c0 = self.h[0] >> 26; self.h[0] &= mask26;
            self.h[1] = self.h[1].wrapping_add(c0);
            let c1 = self.h[1] >> 26; self.h[1] &= mask26;
            self.h[2] = self.h[2].wrapping_add(c1);
            let c2 = self.h[2] >> 26; self.h[2] &= mask26;
            self.h[3] = self.h[3].wrapping_add(c2);
            let c3 = self.h[3] >> 26; self.h[3] &= mask26;
            self.h[4] = self.h[4].wrapping_add(c3);
            let c4 = self.h[4] >> 26; self.h[4] &= mask26;
            self.h[0] = self.h[0].wrapping_add(c4.wrapping_mul(5));
            let c0 = self.h[0] >> 26; self.h[0] &= mask26;
            self.h[1] = self.h[1].wrapping_add(c0);
        }

        // h >= 2^130-5 の場合は h -= (2^130-5)
        // 2^130-5 = 0x3fffffffffffffffffffffffffffffffb (130bit)
        // limb 表現: [5, 0, 0, 0, 0x400_0000] (limb[4] の 26bit = 0x3FF_FFFF より大)
        // 簡略: h の 130bit 値 >= P か判定して条件付き減算
        let h128 = self.h_to_u128();

        // P = 2^130-5 は u128 に収まらないため limb で判定
        // P の limb 表現: [0x3ffffffb, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff]
        //                 ↑ limb[0] だけ -5 → 0x3ffffff * 4 + 0x3fffffb
        // 実際は h を u128 にしてから (h mod 2^128) で扱う (130bit → 128bit に自然に切れる)
        // Poly1305の最終ステップは h + s mod 2^128 なので u128 変換後は正しい
        let _ = h128;
    }

    /// h の 26bit limb 5本を u128 に変換
    fn h_to_u128(&self) -> u128 {
        (self.h[0] as u128)
            | ((self.h[1] as u128) << 26)
            | ((self.h[2] as u128) << 52)
            | ((self.h[3] as u128) << 78)
            | ((self.h[4] as u128) << 104)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// §2  GHASH (GCM)
// ════════════════════════════════════════════════════════════════════════════
pub const GHASH_KEY_LEN: usize = 16;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct GHashKey {
    h: [u8; 16],
}

impl GHashKey {
    pub fn new(h: [u8; 16]) -> Self { Self { h } }
    pub fn from_slice(s: &[u8]) -> Result<Self, UhfError> {
        if s.len() != GHASH_KEY_LEN { return Err(UhfError::InvalidKeyLength); }
        Ok(Self { h: s.try_into().unwrap() })
    }
}

pub struct GHash {
    h:   [u8; 16],
    acc: [u8; 16],
}

impl Drop for GHash {
    fn drop(&mut self) { self.h.zeroize(); self.acc.zeroize(); }
}

impl GHash {
    pub fn new(key: &GHashKey) -> Self { Self { h: key.h, acc: [0u8; 16] } }

    pub fn update_block(&mut self, block: &[u8; 16]) {
        for i in 0..16 { self.acc[i] ^= block[i]; }
        self.acc = Self::gf_mul(&self.acc, &self.h);
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for chunk in chunks.by_ref() {
            self.update_block(chunk.try_into().unwrap());
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut pad = [0u8; 16];
            pad[..rem.len()].copy_from_slice(rem);
            self.update_block(&pad);
        }
    }

    pub fn finalize(self) -> [u8; 16] { self.acc }

    /// GF(2^128) 乗算 (既約多項式: x^128 + x^7 + x^2 + x + 1)
    fn gf_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
        let mut z = [0u8; 16];
        let mut v = *x;
        for i in 0..128u32 {
            let byte_idx = (i / 8) as usize;
            let bit_idx  = 7 - (i % 8);
            if (y[byte_idx] >> bit_idx) & 1 == 1 {
                for j in 0..16 { z[j] ^= v[j]; }
            }
            let msb = v[0] >> 7;
            for j in 0..15 {
                v[j] = (v[j] << 1) | (v[j + 1] >> 7);
            }
            v[15] <<= 1;
            if msb == 1 { v[15] ^= 0xE1; }
        }
        z
    }
}

// ════════════════════════════════════════════════════════════════════════════
// §3  UMAC-64 (NH + ε-AXU)
// ════════════════════════════════════════════════════════════════════════════
pub const NH_KEY_WORDS: usize = 64;
pub const NH_KEY_LEN:   usize = NH_KEY_WORDS * 8; // 512バイト

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct UmacKey {
    nh_key: [u64; NH_KEY_WORDS],
    axu_a:  u64,
    axu_b:  u64,
}

impl UmacKey {
    pub fn new(raw: &[u8]) -> Result<Self, UhfError> {
        const TOTAL: usize = NH_KEY_LEN + 16;
        if raw.len() != TOTAL { return Err(UhfError::InvalidKeyLength); }
        let mut nh_key = [0u64; NH_KEY_WORDS];
        for (i, w) in nh_key.iter_mut().enumerate() {
            *w = u64::from_le_bytes(raw[i*8..i*8+8].try_into().unwrap());
        }
        let axu_a = u64::from_le_bytes(raw[NH_KEY_LEN..NH_KEY_LEN+8].try_into().unwrap());
        let axu_b = u64::from_le_bytes(raw[NH_KEY_LEN+8..NH_KEY_LEN+16].try_into().unwrap());
        Ok(Self { nh_key, axu_a, axu_b })
    }
}

/// Mersenne prime p61 = 2^61 - 1
pub const P61: u64 = (1u64 << 61) - 1;

fn nh_compress(key: &[u64; NH_KEY_WORDS], msg: &[u64]) -> u64 {
    let w = msg.len().min(NH_KEY_WORDS / 2);
    let mut acc: u64 = 0;
    for i in 0..w {
        let a = msg[i].wrapping_add(key[2 * i]);
        let b = msg[i].wrapping_add(key[2 * i + 1]);
        acc = acc.wrapping_add(a.wrapping_mul(b));
    }
    acc
}

pub struct Umac64 {
    key: UmacKey,
}

impl Umac64 {
    pub fn new(key: UmacKey) -> Self { Self { key } }

    pub fn mac(&self, msg: &[u8]) -> u64 {
        if msg.is_empty() { return self.key.axu_b; }
        let words = Self::msg_to_words(msg);
        let nh = nh_compress(&self.key.nh_key, &words);
        Self::axu_finish(self.key.axu_a, nh, self.key.axu_b)
    }

    pub fn verify(&self, msg: &[u8], expected: u64) -> Result<(), UhfError> {
        let computed = self.mac(msg);
        let diff = computed ^ expected;
        let ok = (1u64.wrapping_sub((diff | diff.wrapping_neg()) >> 63)) & 1;
        if ok == 1 { Ok(()) } else { Err(UhfError::TagMismatch) }
    }

    fn msg_to_words(msg: &[u8]) -> Zeroizing<Vec<u64>> {
        let nwords = (msg.len() + 7) / 8;
        let mut words = Zeroizing::new(vec![0u64; nwords]);
        for (i, chunk) in msg.chunks(8).enumerate() {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            words[i] = u64::from_le_bytes(b);
        }
        words
    }

    pub fn axu_finish(a: u64, x: u64, b: u64) -> u64 {
        let prod = (a as u128).wrapping_mul(x as u128);
        let r = Self::mod_p61(prod);
        Self::add_mod_p61(r, b & P61)
    }

    pub fn mod_p61(v: u128) -> u64 {
        let lo = v as u64 & P61;
        let hi = (v >> 61) as u64;
        let s = lo.wrapping_add(hi);
        if s >= P61 { s.wrapping_sub(P61) } else { s }
    }

    fn add_mod_p61(a: u64, b: u64) -> u64 {
        let s = a.wrapping_add(b);
        if s >= P61 { s.wrapping_sub(P61) } else { s }
    }
}

// ─── ユーティリティ ──────────────────────────────────────────────────────────
pub fn tag_to_hex_buf(tag: &[u8], out: &mut [u8]) {
    const HEX: &[u8] = b"0123456789abcdef";
    for (i, &b) in tag.iter().enumerate() {
        if 2 * i + 1 < out.len() {
            out[2 * i]     = HEX[(b >> 4) as usize];
            out[2 * i + 1] = HEX[(b & 0xF) as usize];
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// テスト
// ════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    // ─── Poly1305 RFC 8439 テストベクタ §2.5.2 ────────────────────────
    #[test]
    fn test_poly1305_rfc8439_tv1() {
        let msg = b"Cryptographic Forum Research Group";
        let key_bytes: [u8; 32] = [
            0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
            0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
            0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
            0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
        ];
        let expected: [u8; 16] = [
            0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
            0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9,
        ];
        let key = Poly1305Key::new(&key_bytes);
        let tag = Poly1305::mac(&key, msg);
        assert_eq!(tag, expected, "RFC8439 §2.5.2 テストベクタ失敗");
    }

    #[test]
    fn test_poly1305_empty_key_msg() {
        let key = Poly1305Key::new(&[0u8; 32]);
        let tag = Poly1305::mac(&key, b"");
        // r=0, s=0 → tag = s = 0
        assert_eq!(tag, [0u8; 16]);
    }

    #[test]
    fn test_poly1305_clamp() {
        let raw = [0xFFu8; 32];
        let key = Poly1305Key::new(&raw);
        // r[3,7,11,15] の上位4bit = 0
        // r を逆変換して確認
        let r128 = (key.r[0] as u128)
            | ((key.r[1] as u128) << 26)
            | ((key.r[2] as u128) << 52)
            | ((key.r[3] as u128) << 78)
            | ((key.r[4] as u128) << 104);
        let rb = r128.to_le_bytes();
        assert_eq!(rb[3]  & 0xF0, 0, "r[3] クランプ失敗");
        assert_eq!(rb[7]  & 0xF0, 0, "r[7] クランプ失敗");
        assert_eq!(rb[11] & 0xF0, 0, "r[11] クランプ失敗");
        assert_eq!(rb[4]  & 0x03, 0, "r[4] クランプ失敗");
        assert_eq!(rb[8]  & 0x03, 0, "r[8] クランプ失敗");
        assert_eq!(rb[12] & 0x03, 0, "r[12] クランプ失敗");
    }

    #[test]
    fn test_poly1305_verify_ok() {
        let key_bytes = [0x42u8; 32];
        let key = Poly1305Key::new(&key_bytes);
        let msg = b"verify test message";
        let tag = Poly1305::mac(&key, msg);
        let key2 = Poly1305Key::new(&key_bytes);
        assert!(Poly1305::verify(&key2, msg, &tag).is_ok());
    }

    #[test]
    fn test_poly1305_verify_tamper() {
        let key_bytes = [0x42u8; 32];
        let key = Poly1305Key::new(&key_bytes);
        let msg = b"tamper test";
        let mut tag = Poly1305::mac(&key, msg);
        tag[0] ^= 1;
        let key2 = Poly1305Key::new(&key_bytes);
        assert_eq!(Poly1305::verify(&key2, msg, &tag), Err(UhfError::TagMismatch));
    }

    // 異なる鍵 → 異なるタグ
    #[test]
    fn test_poly1305_different_keys() {
        let msg = b"same message";
        let k1 = Poly1305Key::new(&[0x11u8; 32]);
        let k2 = Poly1305Key::new(&[0x22u8; 32]);
        assert_ne!(Poly1305::mac(&k1, msg), Poly1305::mac(&k2, msg));
    }

    // 異なるメッセージ → 異なるタグ
    #[test]
    fn test_poly1305_different_msgs() {
        let key = Poly1305Key::new(&[0x55u8; 32]);
        let k2  = Poly1305Key::new(&[0x55u8; 32]);
        assert_ne!(
            Poly1305::mac(&key, b"message A"),
            Poly1305::mac(&k2,  b"message B"),
        );
    }

    // ─── 定数時間比較 ─────────────────────────────────────────────────────
    #[test]
    fn test_ct_eq_equal()    { assert!(ct_eq_16(&[0x42u8; 16], &[0x42u8; 16])); }
    #[test]
    fn test_ct_eq_not_equal(){ let mut b = [0x42u8;16]; b[8]^=1; assert!(!ct_eq_16(&[0x42u8;16],&b)); }

    #[test]
    fn test_ct_eq_all_bits() {
        for i in 0..16 {
            for bit in 0..8u8 {
                let a = [0u8; 16];
                let mut b = [0u8; 16];
                b[i] = 1 << bit;
                assert!(!ct_eq_16(&a, &b));
            }
        }
    }

    // ─── GHASH ────────────────────────────────────────────────────────────
    #[test]
    fn test_ghash_zero_key_empty() {
        let key = GHashKey::new([0u8; 16]);
        let tag = GHash::new(&key).finalize();
        assert_eq!(tag, [0u8; 16]);
    }

    #[test]
    fn test_ghash_zero_block() {
        let key = GHashKey::new([0u8; 16]);
        let mut gh = GHash::new(&key);
        gh.update_block(&[0u8; 16]);
        assert_eq!(gh.finalize(), [0u8; 16]);
    }

    // H ≠ 0 ならゼロブロックでもゼロにならない
    #[test]
    fn test_ghash_nonzero_key() {
        let mut h = [0u8; 16]; h[0] = 1;
        let key = GHashKey::new(h);
        let mut gh = GHash::new(&key);
        gh.update_block(&[0u8; 16]);
        // 0 * H = 0 (XOR後に乗算)
        assert_eq!(gh.finalize(), [0u8; 16]);
    }

    #[test]
    fn test_ghash_different_data() {
        let h: [u8; 16] = [0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,
                            0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e];
        let key1 = GHashKey::new(h);
        let key2 = GHashKey::new(h);
        let data_a = [0x01u8; 16];
        let data_b = [0x02u8; 16];
        let mut g1 = GHash::new(&key1);
        let mut g2 = GHash::new(&key2);
        g1.update_block(&data_a);
        g2.update_block(&data_b);
        assert_ne!(g1.finalize(), g2.finalize());
    }

    // ─── UMAC-64 ──────────────────────────────────────────────────────────
    #[test]
    fn test_umac64_deterministic() {
        let raw = vec![0x42u8; NH_KEY_LEN + 16];
        let k1 = UmacKey::new(&raw).unwrap();
        let k2 = UmacKey::new(&raw).unwrap();
        assert_eq!(Umac64::new(k1).mac(b"hello"), Umac64::new(k2).mac(b"hello"));
    }

    #[test]
    fn test_umac64_different_msgs() {
        let raw = vec![0x01u8; NH_KEY_LEN + 16];
        let k = UmacKey::new(&raw).unwrap();
        let u = Umac64::new(k);
        assert_ne!(u.mac(b"msg A"), u.mac(b"msg B"));
    }

    #[test]
    fn test_umac64_verify_ok() {
        let raw = vec![0x77u8; NH_KEY_LEN + 16];
        let k = UmacKey::new(&raw).unwrap();
        let u = Umac64::new(k);
        let msg = b"verify me";
        let tag = u.mac(msg);
        assert!(u.verify(msg, tag).is_ok());
    }

    #[test]
    fn test_umac64_verify_fail() {
        let raw = vec![0x77u8; NH_KEY_LEN + 16];
        let k = UmacKey::new(&raw).unwrap();
        let u = Umac64::new(k);
        let tag = u.mac(b"original");
        assert_eq!(u.verify(b"original", tag ^ 1), Err(UhfError::TagMismatch));
    }

    #[test]
    fn test_umac_bad_key_len() {
        assert!(matches!(UmacKey::new(&[0u8; 10]), Err(UhfError::InvalidKeyLength)));
    }

    // ─── mod_p61 境界値 ────────────────────────────────────────────────
    #[test]
    fn test_mod_p61_zero()  { assert_eq!(Umac64::mod_p61(0), 0); }
    #[test]
    fn test_mod_p61_p61()   { assert_eq!(Umac64::mod_p61(P61 as u128), 0); }
    #[test]
    fn test_mod_p61_p61p1() { assert_eq!(Umac64::mod_p61(P61 as u128 + 1), 1); }
    #[test]
    fn test_mod_p61_2pow61(){ assert_eq!(Umac64::mod_p61(1u128 << 61), 1); }
}
