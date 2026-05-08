//! USB ブートイメージビルダー

use amnesia::{UsbBootConfig, generate_init_script};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("ディレクトリ作成失敗: {0}")]
    DirCreate(String),
    #[error("ファイル書き込み失敗: {0}")]
    FileWrite(String),
    #[error("ISO 生成失敗: {0}")]
    IsoCreate(String),
    #[error("ツールが見つかりません: {0}")]
    ToolNotFound(String),
}

pub struct ImageBuilder {
    boot_config:  UsbBootConfig,
    output_path:  PathBuf,
    compress_lvl: u8,
}

impl ImageBuilder {
    pub fn new(output_path: PathBuf) -> Self {
        Self { boot_config: UsbBootConfig::default(), output_path, compress_lvl: 15 }
    }

    pub fn grub_cfg(&self) -> String {
        format!(
            "# QLinux Secure OS - GRUB2\nset default=0\nset timeout=5\n\n{entry}\nmenuentry \"QLinux (Failsafe)\" {{\n    linux /live/vmlinuz boot=live components nomodeset toram nopersistent\n    initrd /live/initrd.img\n}}\n",
            entry = self.boot_config.grub_entry(),
        )
    }

    pub fn live_build_config(&self) -> Vec<(String, String)> {
        vec![
            (
                "auto/config".to_string(),
                format!(
                    "#!/bin/sh\nlb config noauto \\\n    --architectures amd64 \\\n    --distribution bookworm \\\n    --binary-images iso-hybrid \\\n    --bootappend-live \"{}\" \\\n    --debian-installer false \\\n    \"${{@}}\"\n",
                    self.boot_config.kernel_cmdline,
                ),
            ),
            (
                "config/package-lists/qlinux.list.chroot".to_string(),
                "tor\ntorsocks\ncurl\nwget\ngnupg2\ncryptsetup\ntpm2-tools\nfirmware-linux-free\nlinux-image-amd64\nlive-boot\nlive-config\n".to_string(),
            ),
            (
                "config/hooks/live/0001-qlinux-setup.hook.chroot".to_string(),
                self.setup_hook(),
            ),
            (
                "config/includes.chroot/sbin/amnesia-init".to_string(),
                generate_init_script(),
            ),
        ]
    }

    fn setup_hook(&self) -> String {
        concat!(
            "#!/bin/sh\n",
            "systemctl mask swap.target\n",
            "cat >> /etc/fstab << 'EOF'\n",
            "tmpfs /tmp     tmpfs defaults,noatime,nosuid,nodev,mode=1777 0 0\n",
            "tmpfs /var/log tmpfs defaults,noatime,nosuid,nodev          0 0\n",
            "tmpfs /var/tmp tmpfs defaults,noatime,nosuid,nodev,mode=1777 0 0\n",
            "EOF\n",
            "systemctl enable apparmor\n",
            "echo 'kernel.dmesg_restrict=1' >> /etc/sysctl.d/99-qlinux.conf\n",
            "echo 'kernel.kptr_restrict=2'  >> /etc/sysctl.d/99-qlinux.conf\n",
            "echo 'net.ipv4.tcp_timestamps=0' >> /etc/sysctl.d/99-qlinux.conf\n",
            "echo 'vm.swappiness=0'          >> /etc/sysctl.d/99-qlinux.conf\n",
        ).to_string()
    }

    pub fn build_script(&self) -> String {
        format!(
            concat!(
                "#!/bin/bash\nset -euo pipefail\n",
                "OUTDIR=\"{outdir}\"\n",
                "for cmd in lb xorriso mksquashfs; do\n",
                "    command -v $cmd >/dev/null 2>&1 || {{ echo \"ERROR: $cmd not found\"; exit 1; }}\n",
                "done\n",
                "cargo build --release --workspace\n",
                "mkdir -p $OUTDIR && cd $OUTDIR\n",
                "lb clean 2>/dev/null || true\n",
                "bash auto/config\n",
                "mkdir -p config/includes.chroot/usr/local/bin\n",
                "cp ../../target/release/qonion config/includes.chroot/usr/local/bin/\n",
                "lb build\n",
                "echo \"ISO: $OUTDIR/live-image-amd64.hybrid.iso\"\n",
                "echo \"dd if=$OUTDIR/live-image-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress\"\n",
            ),
            outdir = self.output_path.display(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grub_cfg_security_params() {
        let b = ImageBuilder::new(PathBuf::from("/tmp/build"));
        let cfg = b.grub_cfg();
        assert!(cfg.contains("toram"));
        assert!(cfg.contains("nopersistent"));
        assert!(cfg.contains("init_on_free=1"));
        assert!(cfg.contains("kaslr"));
        assert!(cfg.contains("apparmor"));
    }

    #[test]
    fn test_live_build_config_files() {
        let b = ImageBuilder::new(PathBuf::from("/tmp/build"));
        let files = b.live_build_config();
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"auto/config"));
        assert!(paths.contains(&"config/package-lists/qlinux.list.chroot"));
        assert!(paths.iter().any(|p| p.contains("hook")));
    }

    #[test]
    fn test_setup_hook_security_params() {
        let b = ImageBuilder::new(PathBuf::from("/tmp/build"));
        let hook = b.setup_hook();
        assert!(hook.contains("kptr_restrict"));
        assert!(hook.contains("dmesg_restrict"));
        assert!(hook.contains("swappiness=0"));
        assert!(hook.contains("tmpfs"));
    }

    #[test]
    fn test_build_script() {
        let b = ImageBuilder::new(PathBuf::from("/tmp/build"));
        let script = b.build_script();
        assert!(script.contains("cargo build --release"));
        assert!(script.contains("dd if="));
    }
}
