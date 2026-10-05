//! 脆弱性 PoC → 修正検証: L1 鍵供給
//!
//! 修正前は「攻撃が成功する」ことを確認する PoC だった。修正後は同じ攻撃が
//! 「検出・無効化される」ことを確認する回帰テストに置き換えている。

use qphy::{ChannelModel, EntropySource, KeyMode, PhyError, SimQuantumLink, StateVec, XorShift64, QBER_ABORT_PPM};

/// [FIX-1] 高密度符号モードへのベル対すり替え中間者攻撃。
/// 修正: 鍵ラウンドと物理的に区別できない検査ラウンド (BBM92) を 1/4 混ぜたので、
/// Eve は伝送量子ビットに触れざるを得ず、検査ラウンドの QBER が閾値を超えて露見する。
#[test]
fn fix1_superdense_mitm_is_now_detected() {
    // Eve は「配送途中の量子ビット」を intercept-resend する。鍵ラウンドか検査ラウンドかを
    // 区別できないため、検査ラウンド (もつれ相関テスト) が必ず乱れる。
    let mut rng = XorShift64::new(1);
    let (mut checks, mut errors) = (0u32, 0u32);
    for _ in 0..8000 {
        let is_check = rng.chance_ppm(250_000);
        let mut s = StateVec::zero();
        s.bell_pair(0, 1); // q1 が A→B の伝送量子ビット
        // Eve: 伝送量子ビットを無作為基底で intercept-resend (すり替えの前提動作)
        let eb = rng.bit();
        let _ = s.measure_in(1, eb, &mut rng);
        if is_check {
            let (ba, bb) = (rng.bit(), rng.bit());
            let a = s.measure_in(0, ba, &mut rng);
            let b = s.measure_in(1, bb, &mut rng);
            if ba == bb { checks += 1; if a != b { errors += 1; } }
        }
    }
    let qber_ppm = errors * 1_000_000 / checks;
    println!("fix1: 検査ラウンド QBER={:.2}% (閾値 {:.0}%)", qber_ppm as f64 / 1e4, QBER_ABORT_PPM as f64 / 1e4);
    assert!(qber_ppm > QBER_ABORT_PPM, "中間者が検査ラウンドで露見する");

    // harvest 全体でも、intercept-resend する盗聴者は全モードで QberExceeded になる
    let eve = ChannelModel { depolarize_ppm: 0, eavesdropper: true };
    for mode in [KeyMode::Entanglement, KeyMode::SuperdenseCoding, KeyMode::Teleportation] {
        let mut link = SimQuantumLink::new(XorShift64::new(9), eve, mode);
        assert!(matches!(link.harvest(), Err(PhyError::QberExceeded { .. })), "{mode:?}");
    }
}

/// [FIX-2] プライバシー増幅の欠如による鍵漏洩。
/// 修正: Toeplitz ハッシュで RAW_BITS→出力に圧縮し、QBER 由来の盗聴者情報 h2(QBER)·n と
/// 誤り訂正の公開パリティを差し引く。削りきれない場合は InsufficientSecrecy で破棄する。
#[test]
fn fix2_high_qber_block_is_discarded_by_privacy_amplification() {
    // 閾値 (11%) 直下の QBER では、盗聴者情報 h2(0.10)≈0.47 が生鍵の約半分に達する。
    // 生鍵は出力の 2 倍しかないので、増幅後の安全ビットが出力長を下回り破棄される。
    let mut rejected_for_secrecy = 0;
    let mut usable = 0;
    for noise in [60_000u32, 70_000, 80_000] {
        let model = ChannelModel { depolarize_ppm: noise, eavesdropper: false };
        let mut link = SimQuantumLink::new(XorShift64::new(noise as u64), model, KeyMode::Entanglement);
        for _ in 0..6 {
            match link.harvest() {
                Err(PhyError::InsufficientSecrecy { secure_bits }) => {
                    assert!(secure_bits < 2048);
                    rejected_for_secrecy += 1;
                }
                Ok(_) => usable += 1,
                Err(_) => {} // QberExceeded / ReconciliationFailed も安全側
            }
        }
    }
    println!("fix2: 増幅で破棄 {rejected_for_secrecy} ブロック / 使用可 {usable} ブロック");
    assert!(rejected_for_secrecy > 0, "盗聴者情報を差し引いて破棄する経路が働く");
    assert_eq!(usable, 0, "閾値直下の高雑音ブロックを鍵として使わない");
}

/// 低雑音なら増幅後も十分な安全ビットが残り、両端の鍵は一致する
#[test]
fn fix2_low_noise_still_yields_matching_keys() {
    let model = ChannelModel { depolarize_ppm: 5_000, eavesdropper: false };
    let mut link = SimQuantumLink::new(XorShift64::new(42), model, KeyMode::Entanglement);
    let blk = link.harvest().unwrap();
    assert_eq!(blk.a, blk.b);
    assert!(blk.secure_bits >= 2048);
}
