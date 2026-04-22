//! 認証レイヤー (Bio + Password + TPM2.0)
//! [FIX #5]  stub実装をコンパイルエラーにして本番バイパスを構造上防止
//! [FIX #11] エラーに認証状態(bool)を含めない → 攻撃者への情報漏洩を防止

use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("認証失敗")]  // [FIX #11] どの要素が失敗したか明示しない
    AuthenticationFailed,
    #[error("3要素認証が未完了です")]  // [FIX #11] 進捗状態をリークしない
    MultiFactorRequired,
    #[error("TPM2.0封印解除失敗")]
    TpmUnsealFailed,
}

/// 認証状態をゼロ化可能なフラグで管理
#[derive(Default)]
struct AuthFlags {
    biometric: bool,
    password: bool,
    tpm: bool,
}

impl Drop for AuthFlags {
    fn drop(&mut self) {
        // 認証状態をメモリからクリア
        self.biometric = false;
        self.password = false;
        self.tpm = false;
    }
}

pub struct AuthContext {
    flags: AuthFlags,
}

impl AuthContext {
    pub fn new() -> Self {
        Self { flags: AuthFlags::default() }
    }

    /// 生体認証 (ローカル処理のみ、テンプレート外部送信なし)
    /// [FIX #5] 未実装であることをコンパイル時に強制するため、
    ///          実装者は必ず verify_biometric_impl を提供する必要がある
    pub fn verify_biometric(&mut self, template: &[u8]) -> Result<(), AuthError> {
        // [MUST IMPLEMENT] TPM2.0封印テンプレートとの照合
        // 現在はコンパイルエラーを意図的に発生させる実装 (feature flagで切替)
        #[cfg(not(feature = "biometric_impl"))]
        compile_error!(
            "生体認証の実装が必要です。\
             feature = 'biometric_impl' を有効にし verify_biometric_impl() を実装してください。"
        );

        #[cfg(feature = "biometric_impl")]
        {
            self.verify_biometric_impl(template)?;
            self.flags.biometric = true;
        }
        let _ = template;
        Ok(())
    }

    /// [MUST IMPLEMENT] この関数を実装してfeature = "biometric_impl"を有効化すること
    #[cfg(feature = "biometric_impl")]
    fn verify_biometric_impl(&self, _template: &[u8]) -> Result<(), AuthError> {
        // TODO: tpm2-tools で封印されたテンプレートと照合
        // 実装例:
        //   let sealed = tpm2::unseal(TPM_HANDLE)?;
        //   if !biometric::compare(template, &sealed) {
        //       return Err(AuthError::AuthenticationFailed);
        //   }
        Err(AuthError::AuthenticationFailed) // 実装されるまでは必ず失敗
    }

    pub fn verify_password(&mut self, password: Zeroizing<String>) -> Result<(), AuthError> {
        // [MUST IMPLEMENT] Argon2id によるハッシュ検証
        #[cfg(not(feature = "password_impl"))]
        {
            let _ = password;
            return Err(AuthError::AuthenticationFailed); // 未実装は必ず失敗
        }
        #[cfg(feature = "password_impl")]
        {
            self.verify_password_impl(password)?;
            self.flags.password = true;
            Ok(())
        }
    }

    pub fn verify_tpm(&mut self) -> Result<(), AuthError> {
        // [MUST IMPLEMENT] tpm2-tools PCR封印解除
        #[cfg(not(feature = "tpm_impl"))]
        return Err(AuthError::TpmUnsealFailed); // 未実装は必ず失敗

        #[cfg(feature = "tpm_impl")]
        {
            self.verify_tpm_impl()?;
            self.flags.tpm = true;
            Ok(())
        }
    }

    /// [FIX #11] 3要素の達成状態をリークしない単一エラー
    pub fn authorize_key_access(&self) -> Result<(), AuthError> {
        // 定数時間比較 (タイミング攻撃対策)
        let all_verified = (self.flags.biometric as u8)
            & (self.flags.password as u8)
            & (self.flags.tpm as u8);

        if all_verified == 1 {
            Ok(())
        } else {
            Err(AuthError::MultiFactorRequired)
        }
    }
}

impl Default for AuthContext {
    fn default() -> Self { Self::new() }
}
