#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! L1 量子物理層: 鍵供給部。
//!
//! 物理層は次の 3 つの量子プリミティブで両端ノードに同一の鍵ストリームを供給する。
//!
//! * エンタングルメント (BBM92): ベル対 |Φ+⟩ を両端で無作為基底 (Z/X) 測定し、
//!   基底一致分を鍵ビットとする。
//! * 高密度符号 (superdense coding): 共有済みベル対の A 側半分に 2bit を符号化して
//!   B へ送る。1 量子ビットの伝送で 2bit の鍵を運ぶ。
//! * 量子テレポーテーション: A が無作為基底で用意した鍵量子ビットを、共有ベル対と
//!   2bit の古典通信 (L2/IP 経由) で B へ転送し、B が無作為基底で測定する。
//!
//! どのモードでも、ふるい分け後の鍵ビットから無作為抽出したサンプルで QBER を推定し、
//! 閾値 (11%) を超えたら盗聴ありとしてブロックを破棄する。
//!
//! 実チップ (QEDA) が無い環境ではステートベクタシミュレータ [`StateVec`] で
//! 量子チャネルを模擬する。

#[cfg(feature = "std_test")]
extern crate std;

use zeroize::{Zeroize, Zeroizing};

// ─── 乱数源 ──────────────────────────────────────────────────────────────

pub trait EntropySource {
    fn next_u64(&mut self) -> u64;

    fn bit(&mut self) -> bool { self.next_u64() & 1 == 1 }

    /// [0, 1) の一様乱数
    fn unit_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    fn chance_ppm(&mut self, ppm: u32) -> bool { self.next_u64() % 1_000_000 < ppm as u64 }
}

/// シミュレーション/テスト用 (暗号用途には使わないこと)
pub struct XorShift64(u64);

impl XorShift64 {
    pub const fn new(seed: u64) -> Self { Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed }) }
}

impl EntropySource for XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        self.0 = x;
        x
    }
}

/// x86_64 RDRAND。基底選択など古典側の乱数に使う。
#[cfg(target_arch = "x86_64")]
pub struct RdRand;

#[cfg(target_arch = "x86_64")]
impl EntropySource for RdRand {
    fn next_u64(&mut self) -> u64 {
        for _ in 0..32 {
            let v: u64;
            let ok: u8;
            unsafe {
                core::arch::asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok,
                    options(nomem, nostack));
            }
            if ok == 1 { return v; }
        }
        panic!("RDRAND exhausted");
    }
}

// ─── ステートベクタシミュレータ (4 量子ビット, 実振幅) ────────────────────

pub const SIM_QUBITS: usize = 4;
const DIM: usize = 1 << SIM_QUBITS;
const FRAC_1_SQRT_2: f64 = core::f64::consts::FRAC_1_SQRT_2;

/// 本シミュレータで扱う状態 (|0⟩,|1⟩,|+⟩,|−⟩ とベル状態) は全て実振幅で表せる。
/// 測定後は正規化せず、確率は全ノルムとの比で求める (no_std で sqrt 不要)。
#[derive(Clone)]
pub struct StateVec { amp: [f64; DIM] }

impl StateVec {
    pub fn zero() -> Self {
        let mut amp = [0.0; DIM];
        amp[0] = 1.0;
        Self { amp }
    }

    pub fn x(&mut self, q: usize) {
        let m = 1 << q;
        for i in 0..DIM { if i & m == 0 { self.amp.swap(i, i | m); } }
    }

    pub fn z(&mut self, q: usize) {
        let m = 1 << q;
        for i in 0..DIM { if i & m != 0 { self.amp[i] = -self.amp[i]; } }
    }

    pub fn h(&mut self, q: usize) {
        let m = 1 << q;
        for i in 0..DIM {
            if i & m == 0 {
                let (a, b) = (self.amp[i], self.amp[i | m]);
                self.amp[i]     = (a + b) * FRAC_1_SQRT_2;
                self.amp[i | m] = (a - b) * FRAC_1_SQRT_2;
            }
        }
    }

    pub fn cnot(&mut self, control: usize, target: usize) {
        let (c, t) = (1 << control, 1 << target);
        for i in 0..DIM { if i & c != 0 && i & t == 0 { self.amp.swap(i, i | t); } }
    }

    pub fn prob_one(&self, q: usize) -> f64 {
        let m = 1 << q;
        let (mut p1, mut total) = (0.0, 0.0);
        for i in 0..DIM {
            let p = self.amp[i] * self.amp[i];
            total += p;
            if i & m != 0 { p1 += p; }
        }
        p1 / total
    }

    /// 計算基底で測定し状態を収縮させる
    pub fn measure<R: EntropySource>(&mut self, q: usize, rng: &mut R) -> bool {
        let one = rng.unit_f64() < self.prob_one(q);
        let m = 1 << q;
        for i in 0..DIM { if (i & m != 0) != one { self.amp[i] = 0.0; } }
        one
    }

    /// basis_x = true なら X 基底で測定
    pub fn measure_in<R: EntropySource>(&mut self, q: usize, basis_x: bool, rng: &mut R) -> bool {
        if basis_x { self.h(q); }
        let r = self.measure(q, rng);
        if basis_x { self.h(q); }
        r
    }

    /// q0,q1 に |Φ+⟩ を生成
    pub fn bell_pair(&mut self, a: usize, b: usize) {
        self.h(a);
        self.cnot(a, b);
    }
}

// ─── 量子チャネルモデル ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct ChannelModel {
    /// 伝送量子ビットにランダムなパウリ誤りが入る確率 (ppm)
    pub depolarize_ppm: u32,
    /// 盗聴者 (intercept-resend) の有無
    pub eavesdropper: bool,
}

impl ChannelModel {
    pub const IDEAL: Self = Self { depolarize_ppm: 0, eavesdropper: false };

    fn transmit<R: EntropySource>(&self, s: &mut StateVec, q: usize, rng: &mut R) {
        if self.eavesdropper {
            let basis = rng.bit();
            let _ = s.measure_in(q, basis, rng);
        }
        if self.depolarize_ppm > 0 && rng.chance_ppm(self.depolarize_ppm) {
            match rng.next_u64() % 3 {
                0 => s.x(q),
                1 => s.z(q),
                _ => { s.x(q); s.z(q); }
            }
        }
    }
}

// ─── 鍵供給プロトコル ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMode {
    Entanglement,
    SuperdenseCoding,
    Teleportation,
}

/// 1 ラウンドの結果。sifted = false なら基底不一致で破棄
#[derive(Clone, Copy, Debug)]
pub struct Round { pub a: u8, pub b: u8, pub nbits: u8, pub sifted: bool }

/// BBM92: 量子ビット0 = A, 1 = B (B へ伝送)
pub fn round_entanglement<R: EntropySource>(m: &ChannelModel, rng: &mut R) -> Round {
    let mut s = StateVec::zero();
    s.bell_pair(0, 1);
    m.transmit(&mut s, 1, rng);
    let (ba, bb) = (rng.bit(), rng.bit());
    let a = s.measure_in(0, ba, rng) as u8;
    let b = s.measure_in(1, bb, rng) as u8;
    Round { a, b, nbits: 1, sifted: ba == bb }
}

/// 高密度符号: ベル対 (0=A, 1=B) は事前共有。A が 2bit を符号化し量子ビット0を B へ送る
pub fn round_superdense<R: EntropySource>(m: &ChannelModel, rng: &mut R) -> Round {
    let mut s = StateVec::zero();
    s.bell_pair(0, 1);
    let msg = (rng.next_u64() & 0b11) as u8;
    if msg & 0b01 != 0 { s.x(0); }
    if msg & 0b10 != 0 { s.z(0); }
    m.transmit(&mut s, 0, rng);
    // B: ベル測定で 2bit を復号
    s.cnot(0, 1);
    s.h(0);
    let hi = s.measure(0, rng) as u8;
    let lo = s.measure(1, rng) as u8;
    Round { a: msg, b: (hi << 1) | lo, nbits: 2, sifted: true }
}

/// テレポーテーション: 0 = A の鍵量子ビット, 1 = A 側ベル対, 2 = B 側ベル対 (B へ伝送済み)
pub fn round_teleport<R: EntropySource>(m: &ChannelModel, rng: &mut R) -> Round {
    let mut s = StateVec::zero();
    let (bit, basis_a) = (rng.bit(), rng.bit());
    if bit { s.x(0); }
    if basis_a { s.h(0); }
    s.bell_pair(1, 2);
    m.transmit(&mut s, 2, rng);
    // A: ベル測定
    s.cnot(0, 1);
    s.h(0);
    let m0 = s.measure(0, rng);
    let m1 = s.measure(1, rng);
    // (m0, m1) は L2/IP の認証付き古典チャネルで B へ送られる
    if m1 { s.x(2); }
    if m0 { s.z(2); }
    let basis_b = rng.bit();
    let b = s.measure_in(2, basis_b, rng) as u8;
    Round { a: bit as u8, b, nbits: 1, sifted: basis_a == basis_b }
}

// ─── 鍵蒸留 ────────────────────────────────────────────────────────────────

pub const KEY_BLOCK_BYTES: usize = 256;
const KEY_BLOCK_BITS: usize = KEY_BLOCK_BYTES * 8;
/// プライバシー増幅前の生鍵バッファ (最終出力の 2 倍を蒸留する)
const RAW_BYTES: usize = KEY_BLOCK_BYTES * 2;
const RAW_BITS: usize = RAW_BYTES * 8;
/// BBM92/BB84 の盗聴検出閾値
pub const QBER_ABORT_PPM: u32 = 110_000;
/// [FIX-1] 検査ラウンドの割合 (1/4)。鍵ラウンドと物理的に区別できないため
/// 中間者 (ベル対すり替え) も intercept-resend も検査ラウンドを乱して露見する
const CHECK_PPM: u32 = 250_000;
const MIN_CHECKS: u32 = 256;
const MAX_ROUNDS: usize = RAW_BITS * 64;
/// 誤り訂正のパス数
const EC_PASSES: usize = 5;
/// [FIX-2] プライバシー増幅の安全マージン (bit)
const PA_SAFETY_BITS: u32 = 64;
/// [FIX-2] Toeplitz 行列を生成する公開シード (両端で同一・raw とは独立)
const PA_SEED: u64 = 0x5144_4E5F_5041_3031;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyError {
    /// 物理デバイス (量子チップ) が無い
    NoDevice,
    /// QBER が閾値超過: 盗聴の疑い。ブロックは破棄済み
    QberExceeded { qber_ppm: u32 },
    /// サンプル不足で QBER を推定できない
    InsufficientSamples,
    /// 誤り訂正後も両端の鍵が一致しない
    ReconciliationFailed,
    /// [FIX-2] 盗聴者情報 + EC 公開分を差し引くと安全な鍵が足りない
    InsufficientSecrecy { secure_bits: u32 },
}

/// 両端に配られる鍵ブロック。a は A ノード、b は B ノードの L1 ドライバに届く。
/// プライバシー増幅済みで、盗聴者の持つ情報は無視できるレベルまで削られている。
pub struct KeyBlockPair {
    pub seq:         u64,
    pub a:           [u8; KEY_BLOCK_BYTES],
    pub b:           [u8; KEY_BLOCK_BYTES],
    pub qber_ppm:    u32,
    /// 誤り訂正で公開したパリティ数
    pub leaked_bits: u32,
    /// [FIX-2] プライバシー増幅前に残っていた安全ビット数 (出力より必ず大きい)
    pub secure_bits: u32,
}

impl Drop for KeyBlockPair {
    fn drop(&mut self) { self.a.zeroize(); self.b.zeroize(); }
}

fn get_bit(buf: &[u8], i: usize) -> u8 { (buf[i / 8] >> (i % 8)) & 1 }
fn flip_bit(buf: &mut [u8], i: usize) { buf[i / 8] ^= 1 << (i % 8); }

/// 2 元エントロピー h2(p) をビット単位で返す (0 <= p <= 0.5、1% 刻みの線形補間)
fn binary_entropy(qber_ppm: u32) -> f64 {
    const H: [f64; 12] = [
        0.0, 0.0808, 0.1414, 0.1944, 0.2423, 0.2864,
        0.3274, 0.3659, 0.4022, 0.4365, 0.4690, 0.4999,
    ];
    let p = (qber_ppm as f64 / 1e6).min(0.11);
    let x = p * 100.0;
    let i = x as usize;
    if i >= 11 { return H[11]; }
    H[i] + (H[i + 1] - H[i]) * (x - i as f64)
}

/// 量子リンク (シミュレーション)。両端の測定結果を同時に生成する。
pub struct SimQuantumLink<R: EntropySource> {
    rng:      R,
    pub model: ChannelModel,
    pub mode:  KeyMode,
    next_seq: u64,
}

impl<R: EntropySource> SimQuantumLink<R> {
    pub fn new(rng: R, model: ChannelModel, mode: KeyMode) -> Self {
        Self { rng, model, mode, next_seq: 0 }
    }

    fn key_round(&mut self) -> Round {
        match self.mode {
            KeyMode::Entanglement     => round_entanglement(&self.model, &mut self.rng),
            KeyMode::SuperdenseCoding => round_superdense(&self.model, &mut self.rng),
            KeyMode::Teleportation    => round_teleport(&self.model, &mut self.rng),
        }
    }

    /// 1 ブロック分の鍵を生成・検査・訂正・増幅して両端へ返す
    pub fn harvest(&mut self) -> Result<KeyBlockPair, PhyError> {
        let mut raw_a = Zeroizing::new([0u8; RAW_BYTES]);
        let mut raw_b = Zeroizing::new([0u8; RAW_BYTES]);
        let (mut filled, mut checks, mut errors) = (0usize, 0u32, 0u32);

        for _ in 0..MAX_ROUNDS {
            if filled >= RAW_BITS && checks >= MIN_CHECKS { break; }
            // [FIX-1] 検査ラウンドか鍵ラウンドかを秘密裏に決める。チャネル上は
            // どちらも「もつれ対の片割れを 1 量子ビット伝送」で区別できない
            if self.rng.chance_ppm(CHECK_PPM) || filled >= RAW_BITS {
                let r = round_entanglement(&self.model, &mut self.rng);
                if r.sifted {
                    checks += 1;
                    if r.a != r.b { errors += 1; }
                }
                continue;
            }
            let r = self.key_round();
            if !r.sifted { continue; }
            for k in 0..r.nbits {
                if filled >= RAW_BITS { break; }
                if (r.a >> k) & 1 == 1 { flip_bit(&mut *raw_a, filled); }
                if (r.b >> k) & 1 == 1 { flip_bit(&mut *raw_b, filled); }
                filled += 1;
            }
        }
        if filled < RAW_BITS || checks < MIN_CHECKS {
            return Err(PhyError::InsufficientSamples);
        }
        let qber_ppm = ((errors as u64 * 1_000_000) / checks as u64) as u32;
        if qber_ppm > QBER_ABORT_PPM {
            return Err(PhyError::QberExceeded { qber_ppm });
        }

        let leaked = reconcile(&mut *raw_a, &mut *raw_b, RAW_BITS);
        if raw_a[..] != raw_b[..] { return Err(PhyError::ReconciliationFailed); }

        // [FIX-2] プライバシー増幅: 盗聴者情報 (QBER 由来) + EC 公開分 + 安全マージンを削る
        let eve_bits = (RAW_BITS as f64 * binary_entropy(qber_ppm)) as u32;
        let secure_bits = (RAW_BITS as u32)
            .saturating_sub(eve_bits)
            .saturating_sub(leaked)
            .saturating_sub(PA_SAFETY_BITS);
        if secure_bits < KEY_BLOCK_BITS as u32 {
            return Err(PhyError::InsufficientSecrecy { secure_bits });
        }

        let mut blk = KeyBlockPair {
            seq: self.next_seq, a: [0; KEY_BLOCK_BYTES], b: [0; KEY_BLOCK_BYTES],
            qber_ppm, leaked_bits: leaked, secure_bits,
        };
        toeplitz_compress(&raw_a, &mut blk.a);
        toeplitz_compress(&raw_b, &mut blk.b);
        self.next_seq += 1;
        Ok(blk)
    }
}

/// 誤り訂正の最大スーパーラウンド数 (Cascade 風の反復)
const EC_MAX_ROUNDS: usize = 12;

/// Cascade 風の反復 BINARY 法による誤り訂正 (b を a に合わせる)。公開したパリティ数を返す。
/// 1 スーパーラウンドで区間長と置換を変えた複数パスを行い、区間内の誤りが奇数個なら 1 つ潰す。
/// 一致するまで (または上限まで) スーパーラウンドを繰り返すので、QBER が 10% 近くでも訂正できる。
/// 公開パリティ数は盗聴者情報としてプライバシー増幅で全て差し引かれる。
fn reconcile(a: &mut [u8], b: &mut [u8], nbits: usize) -> u32 {
    // (区間長, 置換の乗数)。乗数は nbits と互いに素になるよう奇数を選ぶ
    const PASSES: [(usize, usize); EC_PASSES] = [(16, 1), (32, 1237), (64, 797), (128, 1531), (256, 389)];
    let mut leaked = 0u32;
    for round in 0..EC_MAX_ROUNDS {
        if a == b { break; }
        // ラウンドごとに置換を回して、前ラウンドで見逃した偶数誤りを別区間に分散させる
        let salt = 1 + 2 * round;
        for (chunk_bits, mul0) in PASSES {
            let mul = mul0 * salt;
            let perm = |i: usize| (i * mul + round * 101) % nbits;
            let par = |buf: &[u8], lo: usize, hi: usize| (lo..hi).fold(0, |p, i| p ^ get_bit(buf, perm(i)));
            for chunk in 0..nbits / chunk_bits {
                let (mut lo, mut hi) = (chunk * chunk_bits, (chunk + 1) * chunk_bits);
                leaked += 1;
                if par(a, lo, hi) == par(b, lo, hi) { continue; }
                while hi - lo > 1 {
                    let mid = (lo + hi) / 2;
                    leaked += 1;
                    if par(a, lo, mid) != par(b, lo, mid) { hi = mid; } else { lo = mid; }
                }
                flip_bit(b, perm(lo));
            }
        }
    }
    leaked
}

/// [FIX-2] Toeplitz ハッシュによるプライバシー増幅: RAW_BITS → KEY_BLOCK_BITS に圧縮。
/// 行列は公開シードから決定的に生成するので両端で同一の出力になり、raw と独立なため
/// 盗聴者が raw について持つ部分情報を出力からほぼ消去できる (leftover hash lemma)。
fn toeplitz_compress(raw: &[u8; RAW_BYTES], out: &mut [u8; KEY_BLOCK_BYTES]) {
    const SEED_BITS: usize = RAW_BITS + KEY_BLOCK_BITS - 1;
    const SEED_BYTES: usize = SEED_BITS / 8 + 1;
    // 公開シードから Toeplitz 対角定数 t[0..SEED_BITS] を生成
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    let mut prng = XorShift64::new(PA_SEED);
    for chunk in seed.chunks_mut(8) {
        let v = prng.next_u64().to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    let t = |k: usize| (seed[k / 8] >> (k % 8)) & 1;
    out.fill(0);
    for i in 0..KEY_BLOCK_BITS {
        let mut acc = 0u8;
        for j in 0..RAW_BITS {
            acc ^= get_bit(raw, j) & t(i + (RAW_BITS - 1) - j);
        }
        if acc != 0 { flip_bit(out, i); }
    }
}

// ─── 実機ドライバ ──────────────────────────────────────────────────────────

/// カーネルが呼ぶ L1 ドライバのインタフェース。自ノード側の鍵ブロックだけを返す。
pub trait QuantumLinkDriver {
    fn harvest_local(&mut self, out: &mut [u8; KEY_BLOCK_BYTES]) -> Result<u64, PhyError>;
}

/// QEDA 量子チップ用ドライバ (チップ未実装のため常に NoDevice)
pub struct QedaChipDriver;

impl QuantumLinkDriver for QedaChipDriver {
    fn harvest_local(&mut self, _out: &mut [u8; KEY_BLOCK_BYTES]) -> Result<u64, PhyError> {
        Err(PhyError::NoDevice)
    }
}

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;

    fn rng() -> XorShift64 { XorShift64::new(0xC0FFEE) }

    #[test]
    fn test_bell_pair_correlated_in_both_bases() {
        let mut r = rng();
        for _ in 0..200 {
            for basis in [false, true] {
                let mut s = StateVec::zero();
                s.bell_pair(0, 1);
                let a = s.measure_in(0, basis, &mut r);
                let b = s.measure_in(1, basis, &mut r);
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn test_superdense_decodes_all_four_messages() {
        let mut r = rng();
        for _ in 0..200 {
            let rd = round_superdense(&ChannelModel::IDEAL, &mut r);
            assert_eq!(rd.a, rd.b);
        }
    }

    #[test]
    fn test_teleport_preserves_state() {
        let mut r = rng();
        let mut sifted = 0;
        for _ in 0..400 {
            let rd = round_teleport(&ChannelModel::IDEAL, &mut r);
            if rd.sifted { sifted += 1; assert_eq!(rd.a, rd.b); }
        }
        assert!(sifted > 100);
    }

    #[test]
    fn test_harvest_ideal_all_modes() {
        for mode in [KeyMode::Entanglement, KeyMode::SuperdenseCoding, KeyMode::Teleportation] {
            let mut link = SimQuantumLink::new(rng(), ChannelModel::IDEAL, mode);
            let blk = link.harvest().unwrap();
            assert_eq!(blk.a, blk.b);
            assert_eq!(blk.qber_ppm, 0);
            assert!(blk.a.iter().any(|&x| x != 0));
            assert_eq!(link.harvest().unwrap().seq, 1);
        }
    }

    #[test]
    fn test_eavesdropper_detected_all_modes() {
        let eve = ChannelModel { depolarize_ppm: 0, eavesdropper: true };
        for mode in [KeyMode::Entanglement, KeyMode::SuperdenseCoding, KeyMode::Teleportation] {
            let mut link = SimQuantumLink::new(rng(), eve, mode);
            match link.harvest() {
                Err(PhyError::QberExceeded { qber_ppm }) => assert!(qber_ppm > QBER_ABORT_PPM),
                other => panic!("{:?}: Eve not detected ({:?})", mode, other.map(|b| b.qber_ppm)),
            }
        }
    }

    #[test]
    fn test_low_noise_corrected_all_modes() {
        // 0.5% の雑音で 20 ブロック中 19 以上は訂正に成功すること
        let noisy = ChannelModel { depolarize_ppm: 5_000, eavesdropper: false };
        for mode in [KeyMode::Entanglement, KeyMode::SuperdenseCoding, KeyMode::Teleportation] {
            let mut link = SimQuantumLink::new(rng(), noisy, mode);
            let ok = (0..20).filter(|_| link.harvest().map(|b| assert_eq!(b.a, b.b)).is_ok()).count();
            assert!(ok >= 19, "{mode:?}: {ok}/20");
        }
    }

    #[test]
    fn test_reconcile_fixes_adjacent_error_pair() {
        let mut a = [0x5Au8; KEY_BLOCK_BYTES];
        let mut b = a;
        flip_bit(&mut b, 100);
        flip_bit(&mut b, 101);
        reconcile(&mut a, &mut b, KEY_BLOCK_BITS);
        assert_eq!(a, b);
    }

    #[test]
    fn test_privacy_amplification_shrinks_and_matches() {
        let mut link = SimQuantumLink::new(rng(), ChannelModel::IDEAL, KeyMode::Entanglement);
        let blk = link.harvest().unwrap();
        assert_eq!(blk.a, blk.b);
        // 出力 2048bit より多くの安全ビットが残っていたこと (生鍵は 2 倍の 4096bit)
        assert!(blk.secure_bits >= KEY_BLOCK_BITS as u32);
        assert!(blk.secure_bits <= RAW_BITS as u32);
    }

    #[test]
    fn test_toeplitz_is_deterministic_and_linear() {
        let mut x = [0u8; RAW_BYTES];
        let mut y = [0u8; RAW_BYTES];
        for i in 0..RAW_BYTES { x[i] = (i * 7) as u8; y[i] = (i * 13 + 1) as u8; }
        let (mut hx, mut hy, mut hxy) = ([0u8; KEY_BLOCK_BYTES], [0u8; KEY_BLOCK_BYTES], [0u8; KEY_BLOCK_BYTES]);
        toeplitz_compress(&x, &mut hx);
        let mut hx2 = [0u8; KEY_BLOCK_BYTES];
        toeplitz_compress(&x, &mut hx2);
        assert_eq!(hx, hx2, "決定的であること");
        toeplitz_compress(&y, &mut hy);
        let mut xy = x;
        for i in 0..RAW_BYTES { xy[i] ^= y[i]; }
        toeplitz_compress(&xy, &mut hxy);
        for i in 0..KEY_BLOCK_BYTES { assert_eq!(hxy[i], hx[i] ^ hy[i], "線形性 (GF(2))"); }
    }

    #[test]
    fn test_chip_driver_reports_no_device() {
        let mut d = QedaChipDriver;
        assert_eq!(d.harvest_local(&mut [0; KEY_BLOCK_BYTES]), Err(PhyError::NoDevice));
    }
}
