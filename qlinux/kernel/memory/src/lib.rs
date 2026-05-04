#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "std_test")]
extern crate std;

use core::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroize;

pub const PAGE_SIZE:  usize = 4096;
pub const MAX_FRAMES: usize = 1024 * 256;
const BITMAP_WORDS:   usize = MAX_FRAMES / 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualMemoryRegion { pub base: usize, pub length: usize, pub kind: RegionKind }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegionKind { KernelCode=0, KernelData=1, UserCode=2, UserData=3, MmioDevice=4, Reserved=5 }

impl VirtualMemoryRegion {
    pub const fn new(base: usize, length: usize, kind: RegionKind) -> Self { Self { base, length, kind } }
    pub fn contains(&self, addr: usize) -> bool { addr >= self.base && addr < self.base.wrapping_add(self.length) }
    pub fn is_user(&self) -> bool { matches!(self.kind, RegionKind::UserCode | RegionKind::UserData) }
}

pub struct BumpAllocator { heap_start: usize, heap_end: usize, next: AtomicUsize }

impl BumpAllocator {
    pub const unsafe fn new(heap_start: usize, heap_end: usize) -> Self {
        Self { heap_start, heap_end, next: AtomicUsize::new(heap_start) }
    }

    pub fn alloc(&self, size: usize, align: usize) -> Result<*mut u8, AllocError> {
        if size == 0 { return Err(AllocError::ZeroSize); }
        if !align.is_power_of_two() { return Err(AllocError::BadAlignment); }
        let mut current = self.next.load(Ordering::Relaxed);
        loop {
            // [SEC-FIX-H] checked_add でオーバーフロー防止
            let aligned = current
                .checked_add(align.wrapping_sub(1))
                .ok_or(AllocError::Overflow)?
                & !(align - 1);
            let next = aligned.checked_add(size).ok_or(AllocError::Overflow)?;
            if next > self.heap_end { return Err(AllocError::OutOfMemory); }
            match self.next.compare_exchange_weak(current, next, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_)  => return Ok(aligned as *mut u8),
                Err(v) => current = v,
            }
        }
    }

    pub fn used_bytes(&self) -> usize { self.next.load(Ordering::Relaxed) - self.heap_start }
    pub fn free_bytes(&self) -> usize { self.heap_end.saturating_sub(self.next.load(Ordering::Relaxed)) }
}

pub struct FrameAllocator { bitmap: [u64; BITMAP_WORDS], total: usize, free_count: usize, phys_base: usize }

impl FrameAllocator {
    pub const fn new(phys_base: usize, total_frames: usize) -> Self {
        Self { bitmap: [0u64; BITMAP_WORDS], total: total_frames, free_count: total_frames, phys_base }
    }

    pub fn alloc_frame(&mut self) -> Result<usize, AllocError> {
        if self.free_count == 0 { return Err(AllocError::OutOfMemory); }
        for (word_idx, word) in self.bitmap.iter_mut().enumerate() {
            if *word == u64::MAX { continue; }
            let bit = word.trailing_ones() as usize;
            let frame_idx = word_idx * 64 + bit;
            if frame_idx >= self.total { break; }
            *word |= 1u64 << bit;
            self.free_count -= 1;
            return Ok(self.phys_base + frame_idx * PAGE_SIZE);
        }
        Err(AllocError::OutOfMemory)
    }

    pub unsafe fn free_frame(&mut self, phys_addr: usize) -> Result<(), AllocError> {
        if phys_addr < self.phys_base { return Err(AllocError::InvalidAddress); }
        let frame_idx = (phys_addr - self.phys_base) / PAGE_SIZE;
        if frame_idx >= self.total { return Err(AllocError::InvalidAddress); }
        let word_idx = frame_idx / 64;
        let bit      = frame_idx % 64;
        if self.bitmap[word_idx] & (1u64 << bit) == 0 { return Err(AllocError::DoubleFree); }
        unsafe {
            let page_ptr = phys_addr as *mut [u8; PAGE_SIZE];
            (*page_ptr).zeroize();
        }
        self.bitmap[word_idx] &= !(1u64 << bit);
        self.free_count += 1;
        Ok(())
    }

    pub fn free_frames(&self)  -> usize { self.free_count }
    pub fn total_frames(&self) -> usize { self.total }

    pub fn reserve_range(&mut self, phys_start: usize, phys_end: usize) {
        let start_frame = phys_start.saturating_sub(self.phys_base) / PAGE_SIZE;
        let end_frame   = (phys_end.saturating_sub(self.phys_base) + PAGE_SIZE - 1) / PAGE_SIZE;
        for frame_idx in start_frame..end_frame.min(self.total) {
            let word_idx = frame_idx / 64;
            let bit      = frame_idx % 64;
            if self.bitmap[word_idx] & (1u64 << bit) == 0 {
                self.bitmap[word_idx] |= 1u64 << bit;
                self.free_count = self.free_count.saturating_sub(1);
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AllocError { OutOfMemory, ZeroSize, BadAlignment, Overflow, InvalidAddress, DoubleFree }

pub fn init() {}

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;

    #[test]
    fn test_bump_alloc() {
        static mut HEAP: [u8; 1024] = [0u8; 1024];
        let (s, e) = unsafe { (HEAP.as_ptr() as usize, HEAP.as_ptr() as usize + 1024) };
        let a = unsafe { BumpAllocator::new(s, e) };
        let p1 = a.alloc(16, 8).unwrap();
        let p2 = a.alloc(32, 16).unwrap();
        assert!(p1 as usize % 8 == 0);
        assert!(p2 as usize % 16 == 0);
        assert!(p2 as usize > p1 as usize);
    }

    #[test]
    fn test_bump_oom() {
        static mut SMALL: [u8; 64] = [0u8; 64];
        let (s, e) = unsafe { (SMALL.as_ptr() as usize, SMALL.as_ptr() as usize + 64) };
        let a = unsafe { BumpAllocator::new(s, e) };
        assert!(a.alloc(128, 1).is_err());
    }

    #[test]
    fn test_frame_alloc_and_free() {
        static mut FRAMES: [u8; PAGE_SIZE * 8] = [0u8; PAGE_SIZE * 8];
        let base = unsafe { FRAMES.as_ptr() as usize };
        let mut fa = FrameAllocator::new(base, 8);
        let f1 = fa.alloc_frame().unwrap();
        let f2 = fa.alloc_frame().unwrap();
        assert_ne!(f1, f2);
        assert_eq!(fa.free_frames(), 6);
        unsafe { fa.free_frame(f1).unwrap() };
        assert_eq!(fa.free_frames(), 7);
    }

    #[test]
    fn test_double_free() {
        static mut FRAMES2: [u8; PAGE_SIZE * 4] = [0u8; PAGE_SIZE * 4];
        let base = unsafe { FRAMES2.as_ptr() as usize };
        let mut fa = FrameAllocator::new(base, 4);
        let f = fa.alloc_frame().unwrap();
        unsafe { fa.free_frame(f).unwrap() };
        assert_eq!(unsafe { fa.free_frame(f) }, Err(AllocError::DoubleFree));
    }

    #[test]
    fn test_region_contains() {
        let r = VirtualMemoryRegion::new(0x1000, 0x1000, RegionKind::KernelData);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }
}
