#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "std_test")]
extern crate std;

pub mod nr {
    pub const SYS_READ:      usize = 0;
    pub const SYS_WRITE:     usize = 1;
    pub const SYS_OPEN:      usize = 2;
    pub const SYS_CLOSE:     usize = 3;
    pub const SYS_EXIT:      usize = 4;
    pub const SYS_GETPID:    usize = 5;
    pub const SYS_SLEEP:     usize = 6;
    pub const SYS_YIELD:     usize = 7;
    pub const SYS_IPC_SEND:  usize = 8;
    pub const SYS_IPC_RECV:  usize = 9;
    pub const SYS_MEM_ALLOC: usize = 10;
    pub const SYS_MEM_FREE:  usize = 11;
    // QTLS (カーネル内 L4 セキュアトランスポート)
    pub const SYS_QTLS_LISTEN:  usize = 12;
    pub const SYS_QTLS_CONNECT: usize = 13;
    pub const SYS_QTLS_ACCEPT:  usize = 14;
    pub const SYS_QTLS_SEND:    usize = 15;
    pub const SYS_QTLS_RECV:    usize = 16;
    pub const SYS_QTLS_CLOSE:   usize = 17;
    pub const SYS_QKEY_AVAIL:   usize = 18;
    pub const MAX_SYSCALL:      usize = 18;
}

pub mod errno {
    pub const EPERM:  i64 = -1;
    pub const ENOENT: i64 = -2;
    pub const EINVAL: i64 = -22;
    pub const EFAULT: i64 = -14;
    pub const ENOMEM: i64 = -12;
    pub const EBADF:  i64 = -9;
    pub const ENOSYS: i64 = -38;
    pub const EAGAIN: i64 = -11;
    pub const EBADMSG:      i64 = -74;
    pub const ENOTCONN:     i64 = -107;
    pub const EHOSTUNREACH: i64 = -113;
    pub const ENOKEY:       i64 = -126;
}

const USER_VIRT_MAX: usize = 0x0000_7FFF_FFFF_F000;
pub type SyscallResult = i64;

use core::sync::atomic::{AtomicUsize, Ordering};

// [FIX-3] カーネルイメージ (コード・静的データ・鍵を含む) の占有範囲 [lo, hi)。
// ページングが無いため、アドレス範囲チェックだけではカーネル下位アドレスを指す
// ユーザポインタを弾けない。この範囲と重なるポインタは拒否する。
// 本来はページテーブルで分離し SMAP/SMEP を有効化すべき暫定措置。
static KERNEL_LO: AtomicUsize = AtomicUsize::new(0);
static KERNEL_HI: AtomicUsize = AtomicUsize::new(0);

/// kernel_main が自身のイメージ範囲を登録する (リンカシンボル _skernel.._ekernel)
pub fn set_kernel_image(lo: usize, hi: usize) {
    KERNEL_LO.store(lo, Ordering::SeqCst);
    KERNEL_HI.store(hi, Ordering::SeqCst);
}

pub fn validate_user_ptr(ptr: usize, size: usize) -> Result<(), SyscallResult> {
    if ptr == 0 || size == 0 { return Err(errno::EFAULT); }
    let end = ptr.checked_add(size).ok_or(errno::EFAULT)?;
    if end > USER_VIRT_MAX { return Err(errno::EFAULT); }
    // [FIX-3] カーネルイメージと少しでも重なるなら拒否
    let (klo, khi) = (KERNEL_LO.load(Ordering::Relaxed), KERNEL_HI.load(Ordering::Relaxed));
    if khi > klo && ptr < khi && end > klo { return Err(errno::EFAULT); }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn syscall_dispatch(
    nr: usize,
    a0: usize, a1: usize, a2: usize,
    _a3: usize, _a4: usize, _a5: usize,
) -> SyscallResult {
    if nr > nr::MAX_SYSCALL { return errno::ENOSYS; }
    match nr {
        nr::SYS_READ      => sys_read(a0 as i32, a1, a2),
        nr::SYS_WRITE     => sys_write(a0 as i32, a1, a2),
        nr::SYS_OPEN      => sys_open(a0, a1 as u32),
        nr::SYS_CLOSE     => sys_close(a0 as i32),
        nr::SYS_EXIT      => sys_exit(a0 as i32),
        nr::SYS_GETPID    => sys_getpid(),
        nr::SYS_SLEEP     => sys_sleep(a0 as u64),
        nr::SYS_YIELD     => sys_yield(),
        nr::SYS_IPC_SEND  => sys_ipc_send(a0 as u32, a1),
        nr::SYS_IPC_RECV  => sys_ipc_recv(a0 as u32, a1),
        nr::SYS_MEM_ALLOC => sys_mem_alloc(a0),
        nr::SYS_MEM_FREE  => sys_mem_free(a0),
        nr::SYS_QTLS_LISTEN  => sys_qtls_listen(a0),
        nr::SYS_QTLS_CONNECT => sys_qtls_connect(a0 as u32, a1),
        nr::SYS_QTLS_ACCEPT  => sys_qtls_accept(a0),
        nr::SYS_QTLS_SEND    => sys_qtls_send(a0, a1, a2),
        nr::SYS_QTLS_RECV    => sys_qtls_recv(a0, a1, a2),
        nr::SYS_QTLS_CLOSE   => sys_qtls_close(a0),
        nr::SYS_QKEY_AVAIL   => sys_qkey_avail(a0 as u32),
        _                  => errno::ENOSYS,
    }
}

fn sys_read(fd: i32, buf_ptr: usize, count: usize) -> SyscallResult {
    if count == 0 { return 0; }
    if let Err(e) = validate_user_ptr(buf_ptr, count) { return e; }
    if fd < 0 { return errno::EBADF; }
    0
}

fn sys_write(fd: i32, buf_ptr: usize, count: usize) -> SyscallResult {
    if count == 0 { return 0; }
    if let Err(e) = validate_user_ptr(buf_ptr, count) { return e; }
    // [SEC-FIX-F] count overflow guard
    if count > i64::MAX as usize { return errno::EINVAL; }
    match fd {
        1 | 2 => {
            let slice = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };
            let _ = slice;
            count as SyscallResult
        }
        _ => errno::EBADF,
    }
}

fn sys_open(path_ptr: usize, _flags: u32) -> SyscallResult {
    if let Err(e) = validate_user_ptr(path_ptr, 1) { return e; }
    errno::ENOENT
}

fn sys_close(fd: i32) -> SyscallResult {
    if fd < 0 { return errno::EBADF; }
    0
}

fn sys_exit(code: i32) -> SyscallResult {
    let _ = code;
    // [SEC-FIX-E] hlt で CPU を停止
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt") };
    }
}

fn sys_getpid()           -> SyscallResult { 1 }
fn sys_sleep(_ms: u64)    -> SyscallResult { 0 }
fn sys_yield()            -> SyscallResult { 0 }

fn sys_ipc_send(queue_id: u32, msg_ptr: usize) -> SyscallResult {
    const MSG_SIZE: usize = 264;
    if let Err(e) = validate_user_ptr(msg_ptr, MSG_SIZE) { return e; }
    let _ = queue_id;
    0
}

fn sys_ipc_recv(queue_id: u32, buf_ptr: usize) -> SyscallResult {
    const MSG_SIZE: usize = 264;
    if let Err(e) = validate_user_ptr(buf_ptr, MSG_SIZE) { return e; }
    let _ = queue_id;
    errno::EAGAIN
}

fn sys_mem_alloc(size: usize) -> SyscallResult {
    if size == 0 || size > 128 * 1024 * 1024 { return errno::EINVAL; }
    0
}

fn sys_mem_free(addr: usize) -> SyscallResult {
    if addr == 0 { return errno::EINVAL; }
    0
}

// ─── QTLS ────────────────────────────────────────────────────────────────
// ネットワークスタックは同じアドレス空間にあり、関数呼び出しで直接操作する (モノリシック)

use net::{NetError, SessionHandle, KERNEL_NET};

fn net_errno(e: NetError) -> SyscallResult {
    match e {
        NetError::ArpPending | NetError::WouldBlock => errno::EAGAIN,
        NetError::NoPeer          => errno::EHOSTUNREACH,
        NetError::NoSession       => errno::EBADF,
        NetError::NotEstablished  => errno::ENOTCONN,
        NetError::AuthFailed      => errno::EBADMSG,
        NetError::Key(_)          => errno::ENOKEY,
        NetError::TableFull | NetError::DeviceFull => errno::ENOMEM,
        NetError::Malformed | NetError::PayloadTooLarge => errno::EINVAL,
    }
}

fn port_arg(p: usize) -> Result<u16, SyscallResult> {
    if p == 0 || p > u16::MAX as usize { Err(errno::EINVAL) } else { Ok(p as u16) }
}

fn sys_qtls_listen(port: usize) -> SyscallResult {
    let port = match port_arg(port) { Ok(p) => p, Err(e) => return e };
    KERNEL_NET.lock().listen(port).map_or_else(net_errno, |_| 0)
}

/// ip はネットワークバイトオーダの IPv4 アドレス
fn sys_qtls_connect(ip: u32, port: usize) -> SyscallResult {
    let port = match port_arg(port) { Ok(p) => p, Err(e) => return e };
    let mut s = KERNEL_NET.lock();
    s.poll();
    s.connect(ip.to_be_bytes(), port).map_or_else(net_errno, |h| h.0 as SyscallResult)
}

fn sys_qtls_accept(port: usize) -> SyscallResult {
    let port = match port_arg(port) { Ok(p) => p, Err(e) => return e };
    let mut s = KERNEL_NET.lock();
    s.poll();
    s.accept(port).map_or(errno::EAGAIN, |h| h.0 as SyscallResult)
}

fn sys_qtls_send(h: usize, buf_ptr: usize, len: usize) -> SyscallResult {
    if len == 0 { return 0; }
    if let Err(e) = validate_user_ptr(buf_ptr, len) { return e; }
    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
    KERNEL_NET.lock().send(SessionHandle(h), data).map_or_else(net_errno, |n| n as SyscallResult)
}

fn sys_qtls_recv(h: usize, buf_ptr: usize, len: usize) -> SyscallResult {
    if len == 0 { return 0; }
    if let Err(e) = validate_user_ptr(buf_ptr, len) { return e; }
    let out = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
    let mut s = KERNEL_NET.lock();
    s.poll();
    s.recv(SessionHandle(h), out).map_or_else(net_errno, |n| n as SyscallResult)
}

fn sys_qtls_close(h: usize) -> SyscallResult {
    KERNEL_NET.lock().close(SessionHandle(h)).map_or_else(net_errno, |_| 0)
}

/// 指定ピアへの送信に使える残り鍵バイト数
fn sys_qkey_avail(ip: u32) -> SyscallResult {
    KERNEL_NET.lock().key_available(ip.to_be_bytes()).map_or(errno::EHOSTUNREACH, |(tx, _)| tx as SyscallResult)
}

pub fn init() {}

#[cfg(all(test, feature = "std_test"))]
mod tests {
    use super::*;

    #[test]
    fn test_validate_null()        { assert_eq!(validate_user_ptr(0, 10), Err(errno::EFAULT)); }
    #[test]
    fn test_validate_kernel_addr() { assert_eq!(validate_user_ptr(0xFFFF_8000_0000_0000, 1), Err(errno::EFAULT)); }
    #[test]
    fn test_validate_ok()          { assert_eq!(validate_user_ptr(0x1000, 4096), Ok(())); }
    #[test]
    fn test_unknown_syscall()      { let r = unsafe { syscall_dispatch(9999,0,0,0,0,0,0) }; assert_eq!(r, errno::ENOSYS); }
    #[test]
    fn test_write_bad_fd()         { let buf = [0u8;8]; let r = unsafe { syscall_dispatch(nr::SYS_WRITE,99,buf.as_ptr() as usize,8,0,0,0) }; assert_eq!(r, errno::EBADF); }
    #[test]
    fn test_qtls_unknown_peer() { let r = unsafe { syscall_dispatch(nr::SYS_QTLS_CONNECT,0x0A00_0063,4433,0,0,0,0) }; assert_eq!(r, errno::EHOSTUNREACH); }
    #[test]
    fn test_qtls_bad_port()     { let r = unsafe { syscall_dispatch(nr::SYS_QTLS_LISTEN,70000,0,0,0,0,0) }; assert_eq!(r, errno::EINVAL); }
    #[test]
    fn test_qtls_send_bad_ptr() { let r = unsafe { syscall_dispatch(nr::SYS_QTLS_SEND,0,0,16,0,0,0) }; assert_eq!(r, errno::EFAULT); }
    #[test]
    fn test_mem_alloc_zero()       { let r = unsafe { syscall_dispatch(nr::SYS_MEM_ALLOC,0,0,0,0,0,0) }; assert_eq!(r, errno::EINVAL); }
}
