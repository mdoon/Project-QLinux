#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

extern crate scheduler;
extern crate memory;
extern crate ipc;
extern crate syscall;
extern crate drivers_core;

use core::sync::atomic::{AtomicBool, Ordering};

static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub unsafe extern "C" fn kernel_main() -> ! {
    if KERNEL_INITIALIZED.swap(true, Ordering::SeqCst) {
        unsafe { arch_halt() };
    }
    memory::init();
    drivers_core::init();
    scheduler::init();
    ipc::init();
    syscall::init();
    loop { unsafe { arch_halt() }; }
}

#[inline(always)]
unsafe fn arch_halt() {
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("hlt") };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("wfi") };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _ = drivers_core::serial_write_str("\n[KERNEL PANIC]\n");
    if let Some(loc) = info.location() {
        let _ = drivers_core::serial_write_str(loc.file());
    }
    loop { unsafe { arch_halt() }; }
}
