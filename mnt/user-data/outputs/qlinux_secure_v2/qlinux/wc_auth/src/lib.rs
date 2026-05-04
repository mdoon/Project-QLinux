//! WC 認証 (Word-Count Authentication)
//!
//! # 概念
//! WC認証は「送受信したデータ量(ワード数)を認証の追加因子として組み込む」方式。
//! - **Nonce として word_count を使用**: 同一鍵でも処理済みワード数が異なれば
//!   異なるサブ鍵を導出 → 再利用攻撃を根本から防ぐ
//! - **MAR (Message Authentication Record)**: 各メッセージに
//!   `(word_count, length, poly1305_tag)` を付与
//! - **セッション**: `WcAuthSession` が通算ワード数を追跡し単調増加を強制
//!
//! # 構造
//! ```text
//! 送信側:
//!   MAR = WcAuthSession::seal(plaintext)
//!     → word_count (8B) || msg_len (4B) || tag (16B) || ciphertext
//!
//! 受信側:
//!   WcAuthSession::open(MAR)
//!     → 1. word_count が現在の期待値と一致するか確認
//!     → 2. Poly1305 タグを定数時間で検証
//!     → 3. 正当なら plaintext を返し word_count を進める
//! ```
//!
//! # サブ鍵導出
//! `subkey(master, word_count)` = Poly1305 をコア UHF として使い
//! `master` を鍵に `word_count || context_label` をハッシュして 32バイトを得る。
//! 実運用では HKDF-SHA256 へ差し替えること (stub として実装)。
//!
//! # セキュリティ保証
//! - word_count は u64 で単調増加のみ許可 → リプレイ攻撃不可
//! - タグ検証は定数時間 (`ct_eq_16`) → タイミングオラクル排除
//! - セッション鍵は `Zeroizing` でドロップ時ゼロ化
//! - 最大メッセージ長を `MAX_MSG_LEN` で制限 → バッファオーバーフロー防止

use thiserror::Error;
use uhf::{ct_eq_16, Poly1305, Poly1305Key, UhfError, POLY1305_KEY_LEN, POLY1305_TAG_LEN};
use zeroize::{Zeroize, Zeroizing};

// ─── 定数 ────────────────────────────────────────────────────────────────────
/// 1ワード = 8バイト (u64 単位)
pub const WORD_BYTES: usize = 8;
/// MAR ヘッダサイズ: word_count(8) + msg_len(4) + tag(16) = 28バイト
pub const MAR_HEADER_LEN: usize = 8 + 4 + POLY1305_TAG_LEN;
/// メッセージ最大長: 64KiB
pub const MAX_MSG_LEN: usize = 65536;
/// セッション鍵長 (POLY1305用)
const SESSION_KEY_LEN: usize = POLY1305_KEY_LEN;
/// コンテキストラベル (サブ鍵導出用)
const CONTEXT_LABEL: &[u8] = b"qlinux-wc-auth-v1";

// ─── エラー型 ────────────────────────────────────────────────────────────────
#[derive(Debug, Error)]
pub enum WcAuthError {
    #[error("認証タグが一致しません")]
    TagMismatch,
    #[error("word_count が期待値と不一致 (リプレイ攻撃または順序違反)")]
    WordCountMismatch,
    #[error("メッセージが長すぎます (最大 {MAX_MSG_LEN} バイト)")]
    MessageTooLong,
    #[error("MAR フォーマットが不正です")]
    InvalidMar,
    #[error("空のメッセージ")]
    EmptyMessage,
    #[error("鍵が不正です")]
    InvalidKey,
    #[error("word_count がオーバーフローします")]
    WordCountOverflow,
}

impl From<UhfError> for WcAuthError {
    fn from(e: UhfError) -> Self {
        match e {
            UhfError::TagMismatch     => Self::TagMismatch,
            UhfError::InvalidKeyLength => Self::InvalidKey,
            _                         => Self::InvalidMar,
        }
    }
}

// ─── MAR (Message Authentication Record) ────────────────────────────────────
/// MAR の解析済み表現
///
/// ヘッダと本体を分離して保持する。
/// `plaintext` は `Zeroizing` で管理。
pub struct Mar {
    pub word_count:  u64,
    pub msg_len:     u32,
    pub tag:         [u8; POLY1305_TAG_LEN],
    pub payload:     Zeroizing<Vec<u8>>,
}

impl Mar {
    /// バイト列から MAR をパース
    pub fn from_bytes(raw: &[u8]) -> Result<Self, WcAuthError> {
        if raw.len() < MAR_HEADER_LEN {
            return Err(WcAuthError::InvalidMar);
        }
        let word_count = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let msg_len    = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let tag: [u8; POLY1305_TAG_LEN] = raw[12..12 + POLY1305_TAG_LEN].try_into().unwrap();

        let payload_start = MAR_HEADER_LEN;
        if raw.len() < payload_start + msg_len as usize {
            return Err(WcAuthError::InvalidMar);
        }
        let payload = Zeroizing::new(raw[payload_start..payload_start + msg_len as usize].to_vec());

        Ok(Self { word_count, msg_len, tag, payload })
    }

    /// MAR をバイト列にシリアライズ
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(MAR_HEADER_LEN + self.payload.len()));
        out.extend_from_slice(&self.word_count.to_le_bytes());
        out.extend_from_slice(&self.msg_len.to_le_bytes());
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.payload);
        out
    }
}

// ─── サブ鍵導出 ─────────────────────────────────────────────────────────────
/// セッション鍵 + word_count からサブ鍵を導出する
///
/// # 実装
/// `subkey = Poly1305_mac(master_key, word_count_le || context_label)`
///
/// - 出力は 16バイトのみのため、`r` と `s` に同じ Poly1305 タグを使い回す
///   (実運用では HKDF-SHA256 に差し替えること)
///
/// # セキュリティノート
/// この KDF は「仮想的な UHF ベース KDF」であり、
/// 正式な KDF (HKDF / PBKDF2) の代替ではない。
/// Phase 2 で HKDF-SHA256 へ移行すること。
fn derive_subkey(
    master: &[u8; SESSION_KEY_LEN],
    word_count: u64,
) -> Zeroizing<[u8; SESSION_KEY_LEN]> {
    // 入力: word_count (8B, LE) || context_label
    let mut kdf_input = Zeroizing::new(Vec::with_capacity(8 + CONTEXT_LABEL.len()));
    kdf_input.extend_from_slice(&word_count.to_le_bytes());
    kdf_input.extend_from_slice(CONTEXT_LABEL);

    // Poly1305 タグ (16バイト) を KDF 出力として使用
    let kdf_key = Poly1305Key::new(master);
    let tag = Poly1305::mac(&kdf_key, &kdf_input);

    // 32バイトに引き延ばす: [tag || tag]
    // [SEC-FIX-C] r=s 問題を解消: 上位16Bと下位16Bを別ドメインで導出
    // label || word_count をそれぞれ "wc-r" / "wc-s" として分離
    const LABEL_R: &[u8] = b"qlinux-wc-auth-v1-r";
    const LABEL_S: &[u8] = b"qlinux-wc-auth-v1-s";

    let mut input_s = Zeroizing::new(Vec::with_capacity(8 + LABEL_S.len()));
    input_s.extend_from_slice(&word_count.to_le_bytes());
    input_s.extend_from_slice(LABEL_S);
    let kdf_key_s = Poly1305Key::new(master);
    let tag_s = Poly1305::mac(&kdf_key_s, &input_s);

    // 再利用した kdf_key は消費済み; 新しい鍵オブジェクトを作成
    let mut kdf_input_r = Zeroizing::new(Vec::with_capacity(8 + LABEL_R.len()));
    kdf_input_r.extend_from_slice(&word_count.to_le_bytes());
    kdf_input_r.extend_from_slice(LABEL_R);
    let kdf_key_r = Poly1305Key::new(master);
    // r として tag (= kdf_input_r への MAC) を使用
    let tag_r = Poly1305::mac(&kdf_key_r, &kdf_input_r);

    let mut subkey = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    subkey[..16].copy_from_slice(&tag_r); // r フィールド
    subkey[16..].copy_from_slice(&tag_s); // s フィールド

    // NOTE: Phase2 では HKDF-SHA256(master, word_count_le, label_r/s) へ移行すること

    subkey
}

// ─── WcAuthSession ───────────────────────────────────────────────────────────
/// WC 認証セッション
///
/// 送信側・受信側それぞれが1つのセッションを持つ。
/// セッション鍵は Zeroizing で保護される。
pub struct WcAuthSession {
    /// セッションマスター鍵 (32バイト)
    master_key:  Zeroizing<[u8; SESSION_KEY_LEN]>,
    /// 通算ワード数 (処理済みメッセージのバイト数 / WORD_BYTES, 切り上げ)
    word_count:  u64,
    /// セッションロール
    role:        SessionRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Sender,
    Receiver,
}

impl Drop for WcAuthSession {
    fn drop(&mut self) {
        self.master_key.zeroize();
        self.word_count = 0;
    }
}

impl WcAuthSession {
    /// 新しいセッションを作成する
    ///
    /// # 引数
    /// - `master_key`: 32バイトのセッション鍵 (安全な乱数で生成すること)
    /// - `initial_wc`: 初期 word_count (通常は 0; 再接続時は最後の値)
    /// - `role`:        送信側 / 受信側
    pub fn new(
        master_key: Zeroizing<Vec<u8>>,
        initial_wc: u64,
        role: SessionRole,
    ) -> Result<Self, WcAuthError> {
        if master_key.len() != SESSION_KEY_LEN {
            return Err(WcAuthError::InvalidKey);
        }
        let mut key_arr = Zeroizing::new([0u8; SESSION_KEY_LEN]);
        key_arr.copy_from_slice(&master_key);
        Ok(Self {
            master_key: key_arr,
            word_count: initial_wc,
            role,
        })
    }

    /// 送信: メッセージを認証して MAR を生成する
    ///
    /// # セキュリティ
    /// - 各呼び出しで word_count をインクリメント → サブ鍵が変わる
    /// - タグは `Poly1305(subkey, word_count || msg_len || payload)` で計算
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WcAuthError> {
        if self.role != SessionRole::Sender {
            // 受信側が seal を呼んではいけない (プロトコル違反)
            return Err(WcAuthError::InvalidKey);
        }
        if plaintext.is_empty() {
            return Err(WcAuthError::EmptyMessage);
        }
        if plaintext.len() > MAX_MSG_LEN {
            return Err(WcAuthError::MessageTooLong);
        }

        let wc = self.word_count;

        // サブ鍵を導出
        let subkey_bytes = derive_subkey(&self.master_key, wc);
        let poly_key = Poly1305Key::new(&subkey_bytes);

        // タグ計算対象: word_count(8B) || msg_len(4B) || payload
        let tag = Self::compute_tag(&poly_key, wc, plaintext);

        // MAR 構築
        let mar = Mar {
            word_count: wc,
            msg_len:    plaintext.len() as u32,
            tag,
            payload:    Zeroizing::new(plaintext.to_vec()),
        };

        // word_count を進める (切り上げワード数)
        let words = Self::bytes_to_words(plaintext.len());
        self.word_count = self.word_count
            .checked_add(words)
            .ok_or(WcAuthError::WordCountOverflow)?;

        Ok(mar.to_bytes())
    }

    /// 受信: MAR を検証して平文を返す
    ///
    /// # セキュリティ
    /// - word_count が期待値と一致しなければ即拒否 (リプレイ / 順序違反)
    /// - タグ検証は定数時間
    pub fn open(&mut self, raw_mar: &[u8]) -> Result<Zeroizing<Vec<u8>>, WcAuthError> {
        if self.role != SessionRole::Receiver {
            return Err(WcAuthError::InvalidKey);
        }

        let mar = Mar::from_bytes(raw_mar)?;

        // word_count の一致確認 (リプレイ攻撃防止)
        if mar.word_count != self.word_count {
            return Err(WcAuthError::WordCountMismatch);
        }

        if mar.payload.is_empty() {
            return Err(WcAuthError::EmptyMessage);
        }
        if mar.payload.len() > MAX_MSG_LEN {
            return Err(WcAuthError::MessageTooLong);
        }

        // サブ鍵導出
        let subkey_bytes = derive_subkey(&self.master_key, mar.word_count);
        let poly_key = Poly1305Key::new(&subkey_bytes);

        // タグ再計算 + 定数時間比較
        let expected_tag = Self::compute_tag(&poly_key, mar.word_count, &mar.payload);
        if !ct_eq_16(&expected_tag, &mar.tag) {
            return Err(WcAuthError::TagMismatch);
        }

        // 検証成功: word_count を進める
        let words = Self::bytes_to_words(mar.payload.len());
        self.word_count = self.word_count
            .checked_add(words)
            .ok_or(WcAuthError::WordCountOverflow)?;

        Ok(mar.payload)
    }

    /// 現在の word_count を取得する (状態確認用)
    pub fn current_word_count(&self) -> u64 {
        self.word_count
    }

    // ─── 内部ヘルパー ──────────────────────────────────────────────────────

    /// タグ計算: Poly1305(subkey, aad || payload)
    ///
    /// AAD = word_count(8B, LE) || msg_len(4B, LE)
    fn compute_tag(
        key:        &Poly1305Key,
        word_count: u64,
        payload:    &[u8],
    ) -> [u8; POLY1305_TAG_LEN] {
        let mut ctx = Poly1305::new(key);
        // AAD を先に入力
        ctx.update(&word_count.to_le_bytes());
        ctx.update(&(payload.len() as u32).to_le_bytes());
        // ペイロードを入力
        ctx.update(payload);
        ctx.finalize()
    }

    /// バイト数をワード数に変換 (切り上げ)
    #[inline]
    fn bytes_to_words(bytes: usize) -> u64 {
        ((bytes + WORD_BYTES - 1) / WORD_BYTES) as u64
    }
}

// ─── セッションペアのファクトリ ─────────────────────────────────────────────
/// 同一鍵から送信側/受信側セッションのペアを生成する
pub fn create_session_pair(
    master_key: Zeroizing<Vec<u8>>,
) -> Result<(WcAuthSession, WcAuthSession), WcAuthError> {
    if master_key.len() != SESSION_KEY_LEN {
        return Err(WcAuthError::InvalidKey);
    }
    // 鍵をコピーして2セッションに配布
    let key2 = Zeroizing::new(master_key.to_vec());
    let sender   = WcAuthSession::new(master_key, 0, SessionRole::Sender)?;
    let receiver = WcAuthSession::new(key2,       0, SessionRole::Receiver)?;
    Ok((sender, receiver))
}

// ─── テスト ──────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![0x5Au8; SESSION_KEY_LEN])
    }

    // ─── 正常系 ─────────────────────────────────────────────────────────
    #[test]
    fn test_seal_open_roundtrip() {
        let key = make_key();
        let (mut sender, mut receiver) = create_session_pair(key).unwrap();

        let plaintext = b"Hello, WC Auth!";
        let mar = sender.seal(plaintext).unwrap();
        let recovered = receiver.open(&mar).unwrap();

        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_multiple_messages() {
        let key = make_key();
        let (mut sender, mut receiver) = create_session_pair(key).unwrap();

        for i in 0u8..8 {
            let msg: Vec<u8> = (0..16).map(|j| i.wrapping_add(j)).collect();
            let mar = sender.seal(&msg).unwrap();
            let out = receiver.open(&mar).unwrap();
            assert_eq!(out.as_slice(), &msg[..]);
        }
    }

    #[test]
    fn test_word_count_advances() {
        let key = make_key();
        let (mut sender, _) = create_session_pair(key).unwrap();
        assert_eq!(sender.current_word_count(), 0);
        sender.seal(b"12345678").unwrap(); // 8バイト = 1ワード
        assert_eq!(sender.current_word_count(), 1);
        sender.seal(b"123456789").unwrap(); // 9バイト = 2ワード
        assert_eq!(sender.current_word_count(), 3);
    }

    // ─── リプレイ攻撃 ───────────────────────────────────────────────────
    #[test]
    fn test_replay_attack_rejected() {
        let key = make_key();
        let (mut sender, mut receiver) = create_session_pair(key).unwrap();

        let mar1 = sender.seal(b"first message").unwrap();
        receiver.open(&mar1).unwrap();

        // 同じ MAR を再度送信 → word_count 不一致で拒否
        let result = receiver.open(&mar1);
        assert_eq!(
            result.map_err(|e| matches!(e, WcAuthError::WordCountMismatch)),
            Err(true)
        );
    }

    // ─── タグ改ざん ─────────────────────────────────────────────────────
    #[test]
    fn test_tag_tamper_rejected() {
        let key = make_key();
        let (mut sender, mut receiver) = create_session_pair(key).unwrap();

        let mut mar = sender.seal(b"tamper test").unwrap().to_vec();
        // tag は offset 12 から 16バイト
        mar[12] ^= 0xFF;

        let result = receiver.open(&mar);
        assert!(
            matches!(result, Err(WcAuthError::TagMismatch)),
            "タグ改ざんが検出されなかった"
        );
    }

    // ─── ペイロード改ざん ────────────────────────────────────────────────
    #[test]
    fn test_payload_tamper_rejected() {
        let key = make_key();
        let (mut sender, mut receiver) = create_session_pair(key).unwrap();

        let mut mar = sender.seal(b"payload tamper").unwrap().to_vec();
        // payload は MAR_HEADER_LEN バイト目以降
        let last = mar.len() - 1;
        mar[last] ^= 1;

        assert!(matches!(receiver.open(&mar), Err(WcAuthError::TagMismatch)));
    }

    // ─── ロール違反 ─────────────────────────────────────────────────────
    #[test]
    fn test_receiver_cannot_seal() {
        let key = make_key();
        let (_, mut receiver) = create_session_pair(key).unwrap();
        let result = receiver.seal(b"wrong role");
        assert!(result.is_err());
    }

    #[test]
    fn test_sender_cannot_open() {
        let key = make_key();
        let (mut sender, _) = create_session_pair(key).unwrap();
        let dummy_mar = sender.seal(b"dummy").unwrap();
        // 送信側で open しようとする
        let result = sender.open(&dummy_mar);
        assert!(result.is_err());
    }

    // ─── 境界値テスト ────────────────────────────────────────────────────
    #[test]
    fn test_empty_message_rejected() {
        let key = make_key();
        let (mut sender, _) = create_session_pair(key).unwrap();
        assert!(matches!(sender.seal(b""), Err(WcAuthError::EmptyMessage)));
    }

    #[test]
    fn test_too_long_message_rejected() {
        let key = make_key();
        let (mut sender, _) = create_session_pair(key).unwrap();
        let long = vec![0u8; MAX_MSG_LEN + 1];
        assert!(matches!(sender.seal(&long), Err(WcAuthError::MessageTooLong)));
    }

    #[test]
    fn test_truncated_mar_rejected() {
        let key = make_key();
        let (_, mut receiver) = create_session_pair(key).unwrap();
        assert!(matches!(receiver.open(&[0u8; 10]), Err(WcAuthError::InvalidMar)));
    }

    // ─── MAR シリアライズ ─────────────────────────────────────────────
    #[test]
    fn test_mar_roundtrip() {
        let tag = [0x99u8; POLY1305_TAG_LEN];
        let payload = Zeroizing::new(b"test payload".to_vec());
        let mar = Mar {
            word_count: 42,
            msg_len:    12,
            tag,
            payload,
        };
        let bytes = mar.to_bytes();
        let parsed = Mar::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.word_count, 42);
        assert_eq!(parsed.msg_len, 12);
        assert_eq!(parsed.tag, tag);
        assert_eq!(parsed.payload.as_slice(), b"test payload");
    }

    // ─── bytes_to_words ──────────────────────────────────────────────
    #[test]
    fn test_bytes_to_words() {
        assert_eq!(WcAuthSession::bytes_to_words(0), 0);
        assert_eq!(WcAuthSession::bytes_to_words(1), 1);
        assert_eq!(WcAuthSession::bytes_to_words(8), 1);
        assert_eq!(WcAuthSession::bytes_to_words(9), 2);
        assert_eq!(WcAuthSession::bytes_to_words(16), 2);
    }
}
