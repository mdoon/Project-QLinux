#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! モノリシックカーネル内で共有される同期プリミティブ。
//! 割り込みハンドラから取得する場合は呼び出し側で割り込みを禁止すること。

#[cfg(feature = "std_test")]
extern crate std;

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLock<T> {
    locked: AtomicBool,
    data:   UnsafeCell<T>,
}

// SAFETY: data へのアクセスは locked の獲得で排他される
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self { locked: AtomicBool::new(false), data: UnsafeCell::new(value) }
    }

    pub fn lock(&self) -> SpinGuard<'_, T> {
        while self.locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) { core::hint::spin_loop(); }
        }
        SpinGuard { lock: self }
    }

    /// パニック経路など、デッドロックが許されない場所で使う
    pub fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinGuard { lock: self })
    }

    /// [FIX-5] ロック状態を無視して中身への可変参照を得る。
    ///
    /// # Safety
    /// パニックハンドラなど、スケジューラと割り込みが停止し他の実行文脈が存在しないと
    /// 保証できる単一コアの文脈でのみ呼ぶこと。ロックを保持したまま別処理が中断された
    /// 状況 (= try_lock が失敗する状況) でも鍵を確実に消去するための最終手段。
    pub unsafe fn force_get_mut(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}

pub struct SpinGuard<'a, T> { lock: &'a SpinLock<T> }

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T { unsafe { &*self.lock.data.get() } }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.lock.data.get() } }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) { self.lock.locked.store(false, Ordering::Release); }
}

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;

    #[test]
    fn test_lock_unlock() {
        let l = SpinLock::new(1u32);
        { let mut g = l.lock(); *g += 1; }
        assert_eq!(*l.lock(), 2);
    }

    #[test]
    fn test_try_lock_contended() {
        let l = SpinLock::new(0u8);
        let _g = l.lock();
        assert!(l.try_lock().is_none());
    }
}
