//! Week1: ThermalRNGドライバ (/dev/hwrng)
//! [FIX #7]  エントロピー品質チェック強化 (Chi-square + バイト分布)
//! [FIX #12] TOCTOU排除: exists()チェックを廃止しopen()の結果のみで判断
//! [FIX #13] len == 0 拒否

use crate::{HardwareType, QhalError, QuantumHardwareAbstraction};
use std::fs::OpenOptions;
use std::io::Read;
use zeroize::Zeroizing;

const HWRNG_DEVICE: &str = "/dev/hwrng";

/// エントロピー品質チェック用サンプルサイズ
const QUALITY_SAMPLE_BYTES: usize = 4096;
/// Chi-square検定: 均等分布からの許容偏差（自由度255, p=0.01相当の目安）
const CHI_SQUARE_THRESHOLD: f64 = 310.0;
/// 単一バイト値の最大出現許容率 (> 2/256 = 約0.8% が異常)
const MAX_BYTE_FREQ_RATIO: f64 = 0.02;

pub struct ThermalRng {
    device_path: &'static str,
}

impl ThermalRng {
    /// [FIX #12] open()で実際にデバイスにアクセスし、exists()チェックを廃止
    pub fn new() -> Result<Self, QhalError> {
        // 読み取り専用でオープン試行 → これがTOCTOU-freeな存在確認
        OpenOptions::new()
            .read(true)
            .open(HWRNG_DEVICE)
            .map_err(|_| QhalError::InitError(format!("{} を開けません", HWRNG_DEVICE)))?;
        Ok(Self { device_path: HWRNG_DEVICE })
    }

    fn open_device(&self) -> Result<std::fs::File, QhalError> {
        OpenOptions::new()
            .read(true)
            .open(self.device_path)
            .map_err(|_| QhalError::DeviceError)
    }
}

impl QuantumHardwareAbstraction for ThermalRng {
    fn hardware_type(&self) -> HardwareType {
        HardwareType::ThermalRNG
    }

    fn generate_random_bytes(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, QhalError> {
        // [FIX #13] 長さ0を拒否
        if len == 0 {
            return Err(QhalError::InvalidLength);
        }
        let mut file = self.open_device()?;
        let mut buf = Zeroizing::new(vec![0u8; len]);
        file.read_exact(&mut buf).map_err(|_| QhalError::DeviceError)?;
        Ok(buf)
    }

    /// [FIX #7] Chi-square検定 + バイト頻度チェックによる品質検証
    fn check_entropy_quality(&self) -> Result<(), QhalError> {
        let sample = self.generate_random_bytes(QUALITY_SAMPLE_BYTES)?;

        // バイト頻度カウント
        let mut freq = [0u32; 256];
        for &b in sample.iter() {
            freq[b as usize] += 1;
        }

        let n = QUALITY_SAMPLE_BYTES as f64;
        let expected = n / 256.0;

        // Chi-square統計量
        let chi_sq: f64 = freq.iter()
            .map(|&f| {
                let diff = f as f64 - expected;
                diff * diff / expected
            })
            .sum();

        if chi_sq > CHI_SQUARE_THRESHOLD {
            return Err(QhalError::QualityCheckFailed);
        }

        // 単一バイト値の偏り検出
        for &f in &freq {
            if (f as f64 / n) > MAX_BYTE_FREQ_RATIO {
                return Err(QhalError::QualityCheckFailed);
            }
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        self.open_device().is_ok()
    }
}
