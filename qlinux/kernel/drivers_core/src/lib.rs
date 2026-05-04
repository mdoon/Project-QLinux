#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "std_test")]
extern crate std;

use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags)); }
}
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack, preserves_flags)); }
    val
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn outb(_port: u16, _val: u8) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn inb(_port: u16) -> u8 { 0 }

const COM1_BASE: u16 = 0x3F8;

pub struct Uart16550 { base: u16 }

impl Uart16550 {
    pub const fn new(base: u16) -> Self { Self { base } }

    pub unsafe fn init(&self) {
        unsafe {
            outb(self.base + 1, 0x00);
            outb(self.base + 3, 0x80);
            outb(self.base + 0, 0x01);
            outb(self.base + 1, 0x00);
            outb(self.base + 3, 0x03);
            outb(self.base + 2, 0xC7);
            outb(self.base + 4, 0x0B);
        }
    }

    pub unsafe fn write_byte(&self, byte: u8) {
        unsafe {
            while inb(self.base + 5) & 0x20 == 0 {}
            outb(self.base, byte);
        }
    }

    pub unsafe fn write_str_raw(&self, s: &str) {
        for byte in s.bytes() {
            unsafe {
                if byte == b'\n' { self.write_byte(b'\r'); }
                self.write_byte(byte);
            }
        }
    }
}

const PIT_CHANNEL0: u16 = 0x40;
const PIT_CMD:      u16 = 0x43;
const PIT_FREQ_HZ:  u32 = 1_193_182;

pub struct Pit8253;

impl Pit8253 {
    pub unsafe fn set_frequency(freq_hz: u32) {
        let divisor = (PIT_FREQ_HZ / freq_hz) as u16;
        unsafe {
            outb(PIT_CMD, 0x36);
            outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
            outb(PIT_CHANNEL0, ((divisor >> 8) & 0xFF) as u8);
        }
    }
}

// [SEC-FIX-G] シングルコア前提の安全性不変条件でstatic mutを保護
static SERIAL_INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut UART: Uart16550 = Uart16550::new(COM1_BASE);

pub fn init() {
    unsafe {
        UART.init();
        Pit8253::set_frequency(100);
    }
    SERIAL_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn serial_write_str(s: &str) -> Result<(), ()> {
    if !SERIAL_INITIALIZED.load(Ordering::Relaxed) { return Err(()); }
    unsafe { UART.write_str_raw(s) };
    Ok(())
}

pub fn serial_write_bytes(data: &[u8]) -> Result<(), ()> {
    if !SERIAL_INITIALIZED.load(Ordering::Relaxed) { return Err(()); }
    unsafe {
        for &b in data {
            if b == b'\n' { UART.write_byte(b'\r'); }
            UART.write_byte(b);
        }
    }
    Ok(())
}
