//! Week3: OTP暗号化エンジン + 鍵消費・破棄機構
//! [FIX #6] decrypt()をencrypt()から分離 → Key Poolを消費しない正しい復号API

use key_pool::{KeyPoolError, KeyPoolManager};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("鍵長が平文長より短い")]  // [FIX] 具体的な長さをリークしない
    KeyTooShort,
    #[error("Key Pool エラー: {0}")]
    KeyPool(#[from] KeyPoolError),
    #[error("入力が空です")]
    EmptyInput,
}

pub struct OtpEngine {
    key_pool: KeyPoolManager,
}

impl OtpEngine {
    pub fn new(key_pool: KeyPoolManager) -> Self {
        Self { key_pool }
    }

    /// 暗号化: plaintext XOR key → ciphertext、鍵は使用後即時破棄
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(u64, Zeroizing<Vec<u8>>), OtpError> {
        if plaintext.is_empty() {
            return Err(OtpError::EmptyInput);
        }
        let needed = plaintext.len();
        let (key_id, key) = self.key_pool.acquire(needed)?;

        // 鍵長 >= 平文長を再確認 (acquireが保証するが防御的チェック)
        if key.len() < needed {
            // acquireから返ったkeyはここでdrop → ゼロ化される
            // consumeも呼ぶ (InUse状態を解消)
            self.key_pool.consume(key_id).ok();
            return Err(OtpError::KeyTooShort);
        }

        let ciphertext = Zeroizing::new(
            plaintext.iter().zip(key.iter()).map(|(p, k)| p ^ k).collect::<Vec<u8>>()
        );
        // key はここでdrop → ゼロ化される (consume前にdropさせる)

        self.key_pool.consume(key_id)?;
        Ok((key_id, ciphertext))
    }

    /// [FIX #6] 復号: 事前共有済みの鍵バイト列を直接受け取りXOR
    /// Key Poolからは取得しない (OTPは送受信側で同一鍵を使用)
    pub fn decrypt_with_key(
        &self,
        ciphertext: &[u8],
        key: &Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, OtpError> {
        if ciphertext.is_empty() {
            return Err(OtpError::EmptyInput);
        }
        if key.len() < ciphertext.len() {
            return Err(OtpError::KeyTooShort);
        }
        Ok(Zeroizing::new(
            ciphertext.iter().zip(key.iter()).map(|(c, k)| c ^ k).collect()
        ))
    }
}
