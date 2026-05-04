#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use zeroize::{Zeroize, Zeroizing};

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

#[inline(never)]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 { diff |= a[i] ^ b[i]; }
    diff == 0
}

pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

pub const POLY1305_TAG_LEN: usize = 16;
pub const POLY1305_KEY_LEN: usize = 32;
const BLOCK: usize = 16;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Poly1305Key {
    pub r: [u32; 5],
    pub s: [u32; 4],
}

impl Poly1305Key {
    pub fn new(raw: &[u8; POLY1305_KEY_LEN]) -> Self {
        let mut rb = [0u8; 16];
        rb.copy_from_slice(&raw[..16]);
        rb[3] &= 0x0F; rb[7] &= 0x0F; rb[11] &= 0x0F; rb[15] &= 0x0F;
        rb[4] &= 0xFC; rb[8] &= 0xFC; rb[12] &= 0xFC;
        let r_val = u128::from_le_bytes(rb);
        let mask26 = (1u128 << 26) - 1;
        let r = [
            (r_val          & mask26) as u32,
            ((r_val >> 26)  & mask26) as u32,
            ((r_val >> 52)  & mask26) as u32,
            ((r_val >> 78)  & mask26) as u32,
            ((r_val >> 104) & mask26) as u32,
        ];
        let s = [
            u32::from_le_bytes(raw[16..20].try_into().unwrap()),
            u32::from_le_bytes(raw[20..24].try_into().unwrap()),
            u32::from_le_bytes(raw[24..28].try_into().unwrap()),
            u32::from_le_bytes(raw[28..32].try_into().unwrap()),
        ];
        Self { r, s }
    }

    pub fn from_zeroizing(key: &Zeroizing<Vec<u8>>) -> Result<Self, UhfError> {
        if key.len() != POLY1305_KEY_LEN { return Err(UhfError::InvalidKeyLength); }
        Ok(Self::new(key[..].try_into().unwrap()))
    }
}

pub struct Poly1305 {
    h:       [u64; 5],
    r:       [u64; 5],
    s:       [u32; 4],
    buf:     [u8; BLOCK],
    buf_len: usize,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.h.zeroize(); self.r.zeroize(); self.s.zeroize();
        self.buf.zeroize(); self.buf_len = 0;
    }
}

impl Poly1305 {
    pub fn new(key: &Poly1305Key) -> Self {
        Self {
            h: [0u64; 5],
            r: [key.r[0] as u64, key.r[1] as u64, key.r[2] as u64,
                key.r[3] as u64, key.r[4] as u64],
            s: key.s,
            buf: [0u8; BLOCK],
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
        if self.buf_len > 0 {
            let mut pad = [0u8; BLOCK];
            pad[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            pad[self.buf_len] = 1;
            self.process_block(&pad, false);
        }
        self.propagate_carry();
        let h128 = self.h_to_u128();
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

    pub fn verify(key: &Poly1305Key, msg: &[u8], expected: &[u8; POLY1305_TAG_LEN]) -> Result<(), UhfError> {
        let computed = Self::mac(key, msg);
        if ct_eq_16(&computed, expected) { Ok(()) } else { Err(UhfError::TagMismatch) }
    }

    fn process_block(&mut self, block: &[u8; 16], add_hibit: bool) {
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
        for i in 0..5 { self.h[i] = self.h[i].wrapping_add(n[i]); }
        self.mul_r();
    }

    fn mul_r(&mut self) {
        let h = &self.h;
        let r = &self.r;
        let r5 = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
        let d0 = h[0]*r[0] + h[1]*r5[3] + h[2]*r5[2] + h[3]*r5[1] + h[4]*r5[0];
        let d1 = h[0]*r[1] + h[1]*r[0]  + h[2]*r5[3] + h[3]*r5[2] + h[4]*r5[1];
        let d2 = h[0]*r[2] + h[1]*r[1]  + h[2]*r[0]  + h[3]*r5[3] + h[4]*r5[2];
        let d3 = h[0]*r[3] + h[1]*r[2]  + h[2]*r[1]  + h[3]*r[0]  + h[4]*r5[3];
        let d4 = h[0]*r[4] + h[1]*r[3]  + h[2]*r[2]  + h[3]*r[1]  + h[4]*r[0];
        let mask26: u64 = (1 << 26) - 1;
        let c0 = d0 >> 26; let h0 = d0 & mask26; let d1 = d1.wrapping_add(c0);
        let c1 = d1 >> 26; let h1 = d1 & mask26; let d2 = d2.wrapping_add(c1);
        let c2 = d2 >> 26; let h2 = d2 & mask26; let d3 = d3.wrapping_add(c2);
        let c3 = d3 >> 26; let h3 = d3 & mask26; let d4 = d4.wrapping_add(c3);
        let c4 = d4 >> 26; let h4 = d4 & mask26;
        let h0 = h0.wrapping_add(c4.wrapping_mul(5));
        let c0 = h0 >> 26; let h0 = h0 & mask26;
        let h1 = h1.wrapping_add(c0);
        self.h = [h0, h1, h2, h3, h4];
    }

    fn propagate_carry(&mut self) {
        let mask26: u64 = (1 << 26) - 1;
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
    }

    fn h_to_u128(&self) -> u128 {
        (self.h[0] as u128)
            | ((self.h[1] as u128) << 26)
            | ((self.h[2] as u128) << 52)
            | ((self.h[3] as u128) << 78)
            | ((self.h[4] as u128) << 104)
    }
}

pub const GHASH_KEY_LEN: usize = 16;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct GHashKey { pub h: [u8; 16] }

impl GHashKey {
    pub fn new(h: [u8; 16]) -> Self { Self { h } }
    pub fn from_slice(s: &[u8]) -> Result<Self, UhfError> {
        if s.len() != GHASH_KEY_LEN { return Err(UhfError::InvalidKeyLength); }
        Ok(Self { h: s.try_into().unwrap() })
    }
}

pub struct GHash { h: [u8; 16], acc: [u8; 16] }

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
        for chunk in chunks.by_ref() { self.update_block(chunk.try_into().unwrap()); }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut pad = [0u8; 16];
            pad[..rem.len()].copy_from_slice(rem);
            self.update_block(&pad);
        }
    }

    pub fn finalize(self) -> [u8; 16] { self.acc }

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
            for j in 0..15 { v[j] = (v[j] << 1) | (v[j + 1] >> 7); }
            v[15] <<= 1;
            if msb == 1 { v[15] ^= 0xE1; }
        }
        z
    }
}

pub const NH_KEY_WORDS: usize = 64;
pub const NH_KEY_LEN:   usize = NH_KEY_WORDS * 8;
pub const P61: u64 = (1u64 << 61) - 1;

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

pub struct Umac64 { key: UmacKey }

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

pub fn tag_to_hex_buf(tag: &[u8], out: &mut [u8]) {
    const HEX: &[u8] = b"0123456789abcdef";
    for (i, &b) in tag.iter().enumerate() {
        if 2 * i + 1 < out.len() {
            out[2 * i]     = HEX[(b >> 4) as usize];
            out[2 * i + 1] = HEX[(b & 0xF) as usize];
        }
    }
}
