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
    pub const MAX_SYSCALL:   usize = 11;
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
}

const USER_VIRT_MAX: usize = 0x0000_7FFF_FFFF_F000;
pub type SyscallResult = i64;

pub fn validate_user_ptr(ptr: usize, size: usize) -> Result<(), SyscallResult> {
    if ptr == 0 { return Err(errno::EFAULT); }
    let end = ptr.checked_add(size).ok_or(errno::EFAULT)?;
    if end > USER_VIRT_MAX { return Err(errno::EFAULT); }
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
    fn test_mem_alloc_zero()       { let r = unsafe { syscall_dispatch(nr::SYS_MEM_ALLOC,0,0,0,0,0,0) }; assert_eq!(r, errno::EINVAL); }
}
