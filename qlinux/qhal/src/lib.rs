//! Quantum Hardware Abstraction Layer (QHAL)
//! [FIX #13] generate_random_bytes(0)拒否

pub mod drivers;

use thiserror::Error;
use zeroize::Zeroizing;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq)]
pub enum HardwareType {
    ThermalRNG,
    QKD_Fiber,
    QKD_Repeater,
    Teleportation,
}

#[derive(Debug, Error)]
pub enum QhalError {
    #[error("ハードウェア初期化失敗: {0}")]
    InitError(String),
    #[error("エントロピー不足")]
    InsufficientEntropy,
    #[error("デバイスアクセスエラー")]  // [FIX] エラー詳細をリークしない
    DeviceError,
    #[error("エントロピー品質不足")]
    QualityCheckFailed,
    #[error("無効な要求サイズ: 1以上を指定してください")]
    InvalidLength,  // [FIX #13]
}

/// 量子ハードウェア抽象化トレイト
pub trait QuantumHardwareAbstraction: Send + Sync {
    fn hardware_type(&self) -> HardwareType;

    /// 指定バイト数のランダムバイトを生成 (len >= 1)
    fn generate_random_bytes(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, QhalError>;

    /// エントロピー品質チェック
    fn check_entropy_quality(&self) -> Result<(), QhalError>;

    fn is_available(&self) -> bool;
}
