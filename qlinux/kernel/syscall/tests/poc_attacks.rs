//! 脆弱性 PoC → 修正検証: syscall ポインタ検証

use net::KERNEL_NET;
use syscall::{errno, set_kernel_image, validate_user_ptr};

/// [FIX-3] validate_user_ptr がカーネル静的データ (鍵を含む KERNEL_NET) を
/// 指すポインタを「ユーザポインタ」として通してしまう問題。
/// 修正: kernel_main が登録したカーネルイメージ範囲と重なるポインタを拒否する。
#[test]
fn fix3_kernel_static_is_rejected_by_user_ptr_check() {
    let kaddr = &KERNEL_NET as *const _ as usize;

    // 修正前の挙動: 範囲未登録ならカーネルアドレスが通ってしまう (= 脆弱)
    // ここでは kernel_main 相当の登録を行い、拒否されることを確認する。
    let size = core::mem::size_of_val(&KERNEL_NET);
    // KERNEL_NET を内包する保守的なカーネル範囲を登録 (実機では _skernel.._ekernel)
    set_kernel_image(kaddr, kaddr + size);

    let r = validate_user_ptr(kaddr, 64);
    println!("fix3: &KERNEL_NET={kaddr:#x} size={size} → validate_user_ptr={r:?}");
    assert_eq!(r, Err(errno::EFAULT), "カーネル静的データへのポインタは拒否される");

    // 末尾だけ範囲に食い込むケースも拒否
    assert_eq!(validate_user_ptr(kaddr - 32, 64), Err(errno::EFAULT));
    // 範囲外の (仮想的な) ユーザアドレスは従来どおり通る
    assert_eq!(validate_user_ptr(0x1000, 4096), Ok(()));
}
