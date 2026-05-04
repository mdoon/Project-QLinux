#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "std_test")]
extern crate std;

use core::sync::atomic::{AtomicU32, Ordering};
use zeroize::Zeroize;

pub const MAX_TASKS: usize = 64;
pub const DEFAULT_TIMESLICE: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState { Empty=0, Ready=1, Running=2, Blocked=3, Zombie=4 }

#[derive(Default, Zeroize)]
#[repr(C)]
pub struct CpuContext {
    pub rsp: u64,
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub rbp: u64, pub rbx: u64,
}

pub struct TaskControlBlock {
    pub tid:        u32,
    pub state:      TaskState,
    pub context:    CpuContext,
    pub stack_top:  usize,
    pub stack_size: usize,
    pub timeslice:  u32,
    pub priority:   u8,
    pub entry:      Option<fn()>,
}

impl TaskControlBlock {
    pub const fn empty() -> Self {
        Self {
            tid: 0, state: TaskState::Empty,
            context: CpuContext { rsp:0, r15:0, r14:0, r13:0, r12:0, rbp:0, rbx:0 },
            stack_top:0, stack_size:0, timeslice:DEFAULT_TIMESLICE, priority:128, entry:None,
        }
    }
    pub fn zeroize_and_release(&mut self) {
        self.context.zeroize();
        self.stack_top=0; self.stack_size=0; self.entry=None;
        self.state=TaskState::Empty;
    }
}

static mut TASK_TABLE: [TaskControlBlock; MAX_TASKS] = {
    const EMPTY: TaskControlBlock = TaskControlBlock::empty();
    [EMPTY; MAX_TASKS]
};
static NEXT_TID: AtomicU32 = AtomicU32::new(1);
static mut CURRENT_IDX: usize = 0;

pub fn init() {}

pub fn spawn(entry: fn(), stack_top: usize, stack_size: usize, priority: u8) -> Result<u32, SpawnError> {
    critical_section(|| {
        let table = unsafe { &mut TASK_TABLE };
        let slot = table.iter_mut().find(|t| t.state == TaskState::Empty).ok_or(SpawnError::NoSlot)?;
        let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
        slot.tid=tid; slot.state=TaskState::Ready;
        slot.stack_top=stack_top; slot.stack_size=stack_size;
        slot.timeslice=DEFAULT_TIMESLICE; slot.priority=priority; slot.entry=Some(entry);
        slot.context.rsp = (stack_top + stack_size - 8) as u64;
        Ok(tid)
    })
}

pub unsafe fn tick() {
    let table = unsafe { &mut TASK_TABLE };
    let cur = unsafe { CURRENT_IDX };
    if cur < MAX_TASKS && table[cur].state == TaskState::Running {
        let ts = &mut table[cur].timeslice;
        if *ts > 0 { *ts -= 1; }
        if *ts == 0 {
            table[cur].state = TaskState::Ready;
            table[cur].timeslice = DEFAULT_TIMESLICE;
            unsafe { schedule() };
        }
    }
}

pub fn block_current() {
    critical_section(|| {
        let table = unsafe { &mut TASK_TABLE };
        let cur = unsafe { CURRENT_IDX };
        if cur < MAX_TASKS { table[cur].state = TaskState::Blocked; }
        unsafe { schedule() };
    });
}

pub fn unblock(tid: u32) -> Result<(), SpawnError> {
    critical_section(|| {
        let table = unsafe { &mut TASK_TABLE };
        let slot = table.iter_mut()
            .find(|t| t.tid == tid && t.state == TaskState::Blocked)
            .ok_or(SpawnError::NotFound)?;
        slot.state = TaskState::Ready;
        Ok(())
    })
}

unsafe fn schedule() {
    let table = unsafe { &mut TASK_TABLE };
    let cur = unsafe { CURRENT_IDX };
    let start = (cur + 1) % MAX_TASKS;
    let next = (start..MAX_TASKS).chain(0..start).find(|&i| table[i].state == TaskState::Ready);
    if let Some(next_idx) = next {
        table[next_idx].state = TaskState::Running;
        let prev_idx = cur;
        unsafe { CURRENT_IDX = next_idx };
        unsafe { context_switch(
            &mut table[prev_idx].context as *mut CpuContext,
            &table[next_idx].context as *const CpuContext,
        )};
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn context_switch(prev: *mut CpuContext, next: *const CpuContext) {
    unsafe { core::arch::asm!(
        "mov [{prev} + 0x00], rsp", "mov [{prev} + 0x08], r15",
        "mov [{prev} + 0x10], r14", "mov [{prev} + 0x18], r13",
        "mov [{prev} + 0x20], r12", "mov [{prev} + 0x28], rbp",
        "mov [{prev} + 0x30], rbx",
        "mov rbx, [{next} + 0x30]", "mov rbp, [{next} + 0x28]",
        "mov r12, [{next} + 0x20]", "mov r13, [{next} + 0x18]",
        "mov r14, [{next} + 0x10]", "mov r15, [{next} + 0x08]",
        "mov rsp, [{next} + 0x00]",
        prev = in(reg) prev, next = in(reg) next,
        options(nostack, preserves_flags),
    );}
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn context_switch(_prev: *mut CpuContext, _next: *const CpuContext) {}

fn critical_section<T, F: FnOnce() -> T>(f: F) -> T {
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("cli") };
    let result = f();
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("sti") };
    result
}

#[derive(Debug, PartialEq, Eq)]
pub enum SpawnError { NoSlot, NotFound }

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;

    #[test]
    fn test_task_state_eq() {
        assert_eq!(TaskState::Ready, TaskState::Ready);
        assert_ne!(TaskState::Ready, TaskState::Running);
    }

    #[test]
    fn test_cpu_context_zeroize() {
        let mut ctx = CpuContext { rsp:0xDEAD, r15:1, r14:2, r13:3, r12:4, rbp:5, rbx:6 };
        ctx.zeroize();
        assert_eq!(ctx.rsp, 0);
    }

    #[test]
    fn test_tcb_zeroize_and_release() {
        let mut tcb = TaskControlBlock::empty();
        tcb.state = TaskState::Running;
        tcb.stack_top = 0x1000;
        tcb.context.rsp = 0xABCD;
        tcb.zeroize_and_release();
        assert_eq!(tcb.state, TaskState::Empty);
        assert_eq!(tcb.context.rsp, 0);
    }

    #[test]
    fn test_default_timeslice() {
        let tcb = TaskControlBlock::empty();
        assert_eq!(tcb.timeslice, DEFAULT_TIMESLICE);
    }

    #[test]
    fn test_spawn_error_eq() {
        assert_eq!(SpawnError::NoSlot, SpawnError::NoSlot);
        assert_ne!(SpawnError::NoSlot, SpawnError::NotFound);
    }
}
