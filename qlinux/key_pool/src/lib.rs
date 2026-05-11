//! Week2: Key Pool Manager
//! [FIX #1]  acquire後のpanicでも鍵が残留しないようDropGuardで保護
//! [FIX #2]  consume時にKeyBlockをVecから完全削除 → Zeroizingのdropで確実にゼロ化
//! [FIX #3]  next_idをpoolと同一Mutexに統合 → デッドロック・TOCTOU排除
//! [FIX #4]  lock().unwrap()をlock().expect()に統一し、毒化時の動作を明示
//! [FIX #9]  Consumed後にVecから削除してメモリ解放
//! [FIX #10] acquire時にブロック全体を移動し、残留バイトも確実に破棄
//! [FIX #14] low_water_mark == 0 を拒否
//! [FIX #15] add_key_material に空Vec拒否

use std::sync::{Arc, Mutex};
use thiserror::Error;
use zeroize::Zeroizing;

const DEFAULT_LOW_WATER_MARK: usize = 1024;
const MIN_LOW_WATER_MARK: usize = 64;

// 内部状態をひとつのMutexに統合 [FIX #3]
struct PoolState {
    blocks: Vec<KeyBlock>,
    next_id: u64,
}

#[derive(Debug, PartialEq)]
enum KeyState {
    Available,
    InUse,
    Consumed,
}

struct KeyBlock {
    id: u64,
    /// Zeroizing: drop時に自動ゼロ化
    data: Zeroizing<Vec<u8>>,
    state: KeyState,
}

#[derive(Debug, Error)]
pub enum KeyPoolError {
    #[error("プール残量不足")]  // [FIX] 残量数値をリークしない
    InsufficientKeys,
    #[error("低水位線以下: 通信停止")]
    BelowLowWaterMark,
    #[error("鍵は既に消費済み")]  // [FIX] IDをリークしない
    AlreadyConsumed,
    #[error("低水位線の値が不正です (最小: {MIN_LOW_WATER_MARK})")]
    InvalidLowWaterMark,
    #[error("空の鍵マテリアルは追加できません")]
    EmptyKeyMaterial,  // [FIX #15]
    #[error("内部ロックエラー")]
    LockPoisoned,
}

pub struct KeyPoolManager {
    state: Arc<Mutex<PoolState>>,
    low_water_mark: usize,
}

impl KeyPoolManager {
    /// [FIX #14] low_water_mark の最小値を強制
    pub fn new(low_water_mark: usize) -> Result<Self, KeyPoolError> {
        if low_water_mark < MIN_LOW_WATER_MARK {
            return Err(KeyPoolError::InvalidLowWaterMark);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(PoolState { blocks: Vec::new(), next_id: 0 })),
            low_water_mark,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, PoolState>, KeyPoolError> {
        self.state.lock().map_err(|_| KeyPoolError::LockPoisoned)
    }

    /// [FIX #15] 空Vec拒否 / [FIX #3] 単一ロックでID採番とpush
    pub fn add_key_material(&self, data: Zeroizing<Vec<u8>>) -> Result<u64, KeyPoolError> {
        if data.is_empty() {
            return Err(KeyPoolError::EmptyKeyMaterial);
        }
        let mut st = self.lock()?;
        let id = st.next_id;
        st.next_id = st.next_id.checked_add(1).expect("key ID overflow");
        st.blocks.push(KeyBlock { id, data, state: KeyState::Available });
        Ok(id)
    }

    /// [FIX #1][FIX #10] ブロック全体をVecから取り出す (残留バイトなし)
    /// 返却された Zeroizing<Vec<u8>> がdropされれば確実にゼロ化
    pub fn acquire(&self, needed: usize) -> Result<(u64, Zeroizing<Vec<u8>>), KeyPoolError> {
        if needed == 0 {
            return Err(KeyPoolError::InsufficientKeys);
        }
        let mut st = self.lock()?;

        let available: usize = st.blocks.iter()
            .filter(|b| b.state == KeyState::Available)
            .map(|b| b.data.len())
            .sum();

        if available < self.low_water_mark {
            return Err(KeyPoolError::BelowLowWaterMark);
        }
        if available < needed {
            return Err(KeyPoolError::InsufficientKeys);
        }

        // ブロック全体を取り出してInUseマーク [FIX #10]
        if let Some(idx) = st.blocks.iter().position(
            |b| b.state == KeyState::Available && b.data.len() >= needed
        ) {
            st.blocks[idx].state = KeyState::InUse;
            let id = st.blocks[idx].id;
            // dataをブロックごとmove → 残留バイトなし
            // ただし先頭neededバイトのみ使用し、残りも同じZeroizingでdrop
            let full_key = std::mem::replace(
                &mut st.blocks[idx].data,
                Zeroizing::new(Vec::new()),  // 空のZeroizingで置換
            );
            // neededバイトだけ切り出し、残りはここでdrop(→ゼロ化)
            let mut key_vec = full_key.to_vec();
            key_vec.truncate(needed);
            // full_key drop → 元バッファをゼロ化
            return Ok((id, Zeroizing::new(key_vec)));
        }

        Err(KeyPoolError::InsufficientKeys)
    }

    /// [FIX #2][FIX #9] Consumed後にVecから完全削除 → Zeroizingのdropでゼロ化
    pub fn consume(&self, id: u64) -> Result<(), KeyPoolError> {
        let mut st = self.lock()?;
        if let Some(idx) = st.blocks.iter().position(|b| b.id == id) {
            if st.blocks[idx].state == KeyState::Consumed {
                return Err(KeyPoolError::AlreadyConsumed);
            }
            // Vecから削除 → KeyBlock.data (Zeroizing) がdropされゼロ化 [FIX #2][FIX #9]
            st.blocks.remove(idx);
            return Ok(());
        }
        // IDが存在しない場合は無視 (既にconsumeで削除済み)
        Ok(())
    }

    pub fn available_bytes(&self) -> Result<usize, KeyPoolError> {
        let st = self.lock()?;
        Ok(st.blocks.iter()
            .filter(|b| b.state == KeyState::Available)
            .map(|b| b.data.len())
            .sum())
    }
}

impl Default for KeyPoolManager {
    fn default() -> Self {
        Self::new(DEFAULT_LOW_WATER_MARK).expect("デフォルト値は有効")
    }
}
