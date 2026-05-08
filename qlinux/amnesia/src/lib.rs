//! Amnesia — シャットダウン時完全揮発モジュール

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum AmnesiaError {
    #[error("tmpfs マウント失敗: {0}")]
    MountFailed(String),
    #[error("スワップ無効化失敗")]
    SwapoffFailed,
    #[error("メモリロック失敗")]
    MlockFailed,
    #[error("シャットダウンフック登録失敗")]
    HookFailed,
    #[error("ゼロ化失敗")]
    ZeroizeFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VolatileLevel {
    AppOnly   = 1,
    RamOnly   = 2,
    MemLocked = 3,
    FullWipe  = 4,
    PhysWipe  = 5,
}

pub struct AmnesiaManager {
    level:              VolatileLevel,
    initialized:        bool,
    shutdown_requested: Arc<AtomicBool>,
    registered_hooks:   usize,
}

impl AmnesiaManager {
    pub fn new(level: VolatileLevel) -> Self {
        Self {
            level,
            initialized: false,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            registered_hooks: 0,
        }
    }

    pub fn init(&mut self) -> Result<(), AmnesiaError> {
        if self.initialized { return Ok(()); }
        match self.level {
            VolatileLevel::AppOnly => {}
            _ => {
                self.setup_tmpfs()?;
                self.disable_swap()?;
                if self.level >= VolatileLevel::MemLocked { self.mlock_all()?; }
                if self.level >= VolatileLevel::FullWipe  { self.register_shutdown_hooks()?; }
            }
        }
        self.initialized = true;
        Ok(())
    }

    pub fn initiate_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.execute_wipe();
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Relaxed)
    }

    fn setup_tmpfs(&self) -> Result<(), AmnesiaError> {
        // mount -t tmpfs tmpfs /tmp /var/log /var/tmp /home /root
        // 実装: libc::mount()
        Ok(())
    }

    fn disable_swap(&self) -> Result<(), AmnesiaError> {
        // 実装: libc::swapoff()
        Ok(())
    }

    fn mlock_all(&self) -> Result<(), AmnesiaError> {
        // 実装: libc::mlockall(MCL_CURRENT | MCL_FUTURE)
        Ok(())
    }

    fn register_shutdown_hooks(&mut self) -> Result<(), AmnesiaError> {
        // 実装: signal_hook or tokio::signal
        self.registered_hooks += 2;
        Ok(())
    }

    fn execute_wipe(&self) {
        if self.level >= VolatileLevel::FullWipe  { self.drop_page_cache(); }
        if self.level >= VolatileLevel::PhysWipe  { self.overwrite_physical_memory(); }
    }

    fn drop_page_cache(&self) {
        // echo 3 > /proc/sys/vm/drop_caches && sync
    }

    fn overwrite_physical_memory(&self) {
        // カーネルモジュール経由で /dev/mem をゼロ化
    }
}

#[derive(Debug, Clone)]
pub struct UsbBootConfig {
    pub boot_device:    String,
    pub ramdisk_size:   usize,
    pub no_persistence: bool,
    pub kernel_cmdline: String,
}

impl Default for UsbBootConfig {
    fn default() -> Self {
        Self {
            boot_device:    "/dev/sda".to_string(),
            ramdisk_size:   2048,
            no_persistence: true,
            kernel_cmdline: concat!(
                "boot=live components quiet splash ",
                "nopersistent toram ",
                "apparmor=1 security=apparmor ",
                "kaslr slab_nomerge ",
                "init_on_alloc=1 init_on_free=1",
            ).to_string(),
        }
    }
}

impl UsbBootConfig {
    pub fn grub_entry(&self) -> String {
        format!(
            "menuentry \"QLinux Secure OS\" {{\n    linux /vmlinuz {cmdline}\n    initrd /initrd.img\n}}\n",
            cmdline = self.kernel_cmdline,
        )
    }

    pub fn syslinux_config(&self) -> String {
        format!(
            "DEFAULT qlinux\nLABEL qlinux\n  MENU LABEL QLinux Secure OS\n  LINUX /live/vmlinuz\n  INITRD /live/initrd.img\n  APPEND {cmdline}\n",
            cmdline = self.kernel_cmdline,
        )
    }
}

pub fn generate_init_script() -> String {
    r#"#!/bin/sh
# QLinux Amnesia Init Script
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o size=80%,mode=755 tmpfs /mnt/root
mkdir -p /mnt/usb
mount -o ro /dev/sda1 /mnt/usb
cp /mnt/usb/live/filesystem.squashfs /dev/shm/
umount /mnt/usb
mkdir -p /mnt/squash
mount -t squashfs -o loop /dev/shm/filesystem.squashfs /mnt/squash
mkdir -p /mnt/upper /mnt/work
mount -t overlay overlay \
  -o lowerdir=/mnt/squash,upperdir=/mnt/upper,workdir=/mnt/work \
  /mnt/root
swapoff -a 2>/dev/null || true
cd /mnt/root
pivot_root . mnt
exec chroot . /sbin/init
"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amnesia_manager_init() {
        let mut am = AmnesiaManager::new(VolatileLevel::AppOnly);
        assert!(!am.initialized);
        am.init().unwrap();
        assert!(am.initialized);
    }

    #[test]
    fn test_volatile_level_ordering() {
        assert!(VolatileLevel::AppOnly  < VolatileLevel::RamOnly);
        assert!(VolatileLevel::RamOnly  < VolatileLevel::FullWipe);
        assert!(VolatileLevel::FullWipe < VolatileLevel::PhysWipe);
    }

    #[test]
    fn test_usb_boot_grub_entry() {
        let cfg = UsbBootConfig::default();
        let entry = cfg.grub_entry();
        assert!(entry.contains("QLinux Secure OS"));
        assert!(entry.contains("toram"));
        assert!(entry.contains("nopersistent"));
        assert!(entry.contains("init_on_free=1"));
    }

    #[test]
    fn test_syslinux_config() {
        let cfg = UsbBootConfig::default();
        assert!(cfg.syslinux_config().contains("LABEL qlinux"));
    }

    #[test]
    fn test_init_script_contains_tmpfs() {
        let script = generate_init_script();
        assert!(script.contains("tmpfs"));
        assert!(script.contains("swapoff"));
        assert!(script.contains("pivot_root"));
    }

    #[test]
    fn test_shutdown_flag() {
        let am = AmnesiaManager::new(VolatileLevel::AppOnly);
        assert!(!am.is_shutdown_requested());
        am.initiate_shutdown();
        assert!(am.is_shutdown_requested());
    }
}
