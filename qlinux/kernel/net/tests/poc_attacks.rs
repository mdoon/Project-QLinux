//! 脆弱性 PoC → 修正検証: 鍵レーン同期

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use net::eth::MacAddr;
use net::{emergency_zeroize, NetDevice, NetError, NetStack, KERNEL_NET};
use qkey::LinkRole;

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
struct Nic { mac: MacAddr, tx: Queue, rx: Queue }
impl NetDevice for Nic {
    fn mac(&self) -> MacAddr { self.mac }
    fn transmit(&mut self, f: &[u8]) -> Result<(), NetError> { self.tx.borrow_mut().push_back(f.to_vec()); Ok(()) }
    fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        // 実ドライバと同じく buf を超えて書かない (NetDevice の契約)
        let f = self.rx.borrow_mut().pop_front()?;
        let n = f.len().min(buf.len());
        buf[..n].copy_from_slice(&f[..n]);
        Some(n)
    }
}

const A: [u8; 4] = [10, 0, 0, 1];
const B: [u8; 4] = [10, 0, 0, 2];

/// [FIX-4] 経路上のパケット破棄による鍵レーン恒久非同期。
/// 修正前: Alice だけが鍵を消費し、Bob の rx レーンが先に満杯 → LaneFull で片側だけ鍵を捨て
///         両端のオフセットがずれ、妨害停止後も二度と通信できなかった。
/// 修正後: deposit はスライディングウィンドウ化し (最古の未使用鍵を捨てる)、受信は
///         Poly1305 検証後に任意オフセットまで追従できる。妨害が止めば自動で再同期する。
#[test]
fn fix4_recovers_after_packet_drop_jamming() {
    let (ab, ba): (Queue, Queue) = Default::default();
    let mut a = Box::new(NetStack::new(Nic { mac: [2, 0, 0, 0, 0, 1], tx: ab.clone(), rx: ba.clone() }));
    let mut b = Box::new(NetStack::new(Nic { mac: [2, 0, 0, 0, 0, 2], tx: ba.clone(), rx: ab.clone() }));
    a.configure(A); b.configure(B);
    a.register_peer(B, LinkRole::A).unwrap();
    b.register_peer(A, LinkRole::B).unwrap();

    let mut seq = 0u64;
    let mut deposit = |a: &mut NetStack<Nic>, b: &mut NetStack<Nic>, seq: &mut u64| {
        let blk = [(*seq as u8).wrapping_mul(37).wrapping_add(1); 256];
        a.deposit_key_block(B, *seq, &blk).unwrap();
        b.deposit_key_block(A, *seq, &blk).unwrap();
        *seq += 1;
    };
    for _ in 0..8 { deposit(&mut a, &mut b, &mut seq); }

    b.listen(4433).unwrap();
    let _ = a.connect(B, 4433);
    for _ in 0..3 { a.poll(); b.poll(); }
    let h = a.connect(B, 4433).unwrap();
    for _ in 0..3 { a.poll(); b.poll(); }
    let sb = b.accept(4433).unwrap();

    // Eve: Alice→Bob の全フレームを落とす。L1 は鍵を補充し続ける (deposit は常に成功)
    for _ in 0..600 {
        while a.send(h, &[0u8; 200]).is_ok() { ab.borrow_mut().clear(); }
        deposit(&mut a, &mut b, &mut seq);
        b.poll();
    }

    // Eve が妨害をやめる。数ブロック鍵が流れたのち通信を再開
    for _ in 0..4 { deposit(&mut a, &mut b, &mut seq); }
    let mut ok = 0;
    for i in 0..5u8 {
        deposit(&mut a, &mut b, &mut seq);
        let msg = [b'R', i];
        if a.send(h, &msg).is_ok() {
            a.poll(); b.poll();
            let mut buf = [0u8; 64];
            if let Ok(n) = b.recv(sb, &mut buf) {
                if buf[..n] == msg { ok += 1; }
            }
        }
    }
    println!("fix4: 妨害停止後の受信成功 {ok}/5");
    assert!(ok >= 3, "妨害停止後に再同期して通信が回復する (実際 {ok}/5)");
}

/// [FIX-5] ネットワーク処理中 (ロック保持中) のパニックで鍵が消えない問題。
/// 修正: emergency_zeroize はロックを取れなければ強制消去にフォールバックする。
#[test]
fn fix5_emergency_zeroize_wipes_even_when_locked() {
    const PEER: [u8; 4] = [10, 0, 0, 2];
    {
        let mut s = KERNEL_NET.lock();
        s.register_peer(PEER, LinkRole::A).unwrap();
        s.deposit_key_block(PEER, 0, &[0xAB; 128]).unwrap();
        assert_eq!(s.key_available(PEER), Some((128, 0)));
        // ロックを握ったままパニックした状況を再現し、その場で緊急消去する
        emergency_zeroize();
        assert_eq!(s.key_available(PEER), Some((0, 0)), "ロック保持中でも鍵が消える");
    }
}

/// [FIX-OVF] 攻撃者が制御する QTLS key_offset による整数オーバーフロー。
/// peek_at はタグ検証前に呼ばれるため offset は完全に攻撃者制御。巨大な offset でも
/// パニック (debug) / チェックすり抜け (release) を起こさず、鍵も消費しないこと。
#[test]
fn fixovf_huge_key_offset_is_rejected_without_panic() {
    use net::qtls::{self, ContentType, MAX_RECORD_LEN};
    use qkey::KeyLane;

    let mut tx = Box::new(KeyLane::new());
    let mut rx = Box::new(KeyLane::new());
    let key: Vec<u8> = (0..1024u32).map(|i| i as u8).collect();
    tx.deposit(&key).unwrap();
    rx.deposit(&key).unwrap();

    let mut rec = [0u8; MAX_RECORD_LEN];
    let n = qtls::seal(&mut tx, ContentType::Data, 1, b"hello", &mut rec).unwrap();

    // key_offset (レコードのバイト 4..12) を u64::MAX に改ざん
    rec[4..12].copy_from_slice(&u64::MAX.to_be_bytes());

    let mut out = [0u8; 64];
    let r = qtls::open(&mut rx, &rec[..n], &mut out);
    assert!(r.is_err(), "巨大オフセットのレコードは拒否される");
    assert_eq!(rx.next_offset(), 0, "鍵は消費されない");
}

/// パーサのファズ: 乱数・切り詰めフレームを大量に流し込み、どの層でもパニックしないこと。
/// (debug ビルドは算術オーバーフローでパニックするので、オーバーフロー検出も兼ねる)
#[test]
fn fixovf_parser_fuzz_never_panics() {
    use net::eth::MAX_FRAME;

    let (ab, ba): (Queue, Queue) = Default::default();
    let mut a = Box::new(NetStack::new(Nic { mac: [2, 0, 0, 0, 0, 1], tx: ab.clone(), rx: ba.clone() }));
    a.configure([10, 0, 0, 1]);
    a.register_peer([10, 0, 0, 2], LinkRole::A).unwrap();
    a.deposit_key_block([10, 0, 0, 2], 0, &[0x5A; 256]).unwrap();
    a.listen(4433).unwrap();

    // 決定的な簡易 PRNG
    let mut s: u64 = 0x1234_5678_9abc_def0;
    let mut rnd = || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };

    for _ in 0..20_000 {
        let len = (rnd() as usize) % (MAX_FRAME + 4); // 時に MAX_FRAME 超も
        let mut f = Vec::with_capacity(len);
        // ときどき本物らしいヘッダを混ぜて深いパスへ到達させる
        if rnd() & 1 == 0 {
            f.extend_from_slice(&[2, 0, 0, 0, 0, 1]);          // dst = 自分
            f.extend_from_slice(&[2, 0, 0, 0, 0, 2]);          // src
            f.extend_from_slice(&(if rnd() & 1 == 0 { 0x0800u16 } else { 0x0806 }).to_be_bytes());
        }
        while f.len() < len { f.push(rnd() as u8); }
        ba.borrow_mut().push_back(f);
        a.poll(); // パニックしなければ合格
    }
}
