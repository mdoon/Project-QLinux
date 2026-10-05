//! 二台のノード (Alice 10.0.0.1 / Bob 10.0.0.2) の通信シミュレーション。
//!
//!   cargo run -p net --example two_node -- [entangle|dense|teleport] [雑音ppm]
//!
//! 量子リンク (qphy) で鍵を配り、Ethernet ケーブル上の全フレームを解析表示しながら
//! QTLS で通信する。後半で盗聴・改ざん・リプレイ・鍵枯渇の各攻撃を試す。

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use net::eth::{EthHeader, MacAddr, ETHERTYPE_ARP, ETHERTYPE_IPV4};
use net::ipv4::Ipv4Header;
use net::qtls::{self, RecordHeader, QTLS_PORT};
use net::udp::UdpHeader;
use net::{arp::ArpPacket, NetDevice, NetError, NetStack, SessionHandle, SessionState};
use qkey::LinkRole;
use qphy::{ChannelModel, KeyMode, SimQuantumLink, XorShift64};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct Nic { mac: MacAddr, tx: Queue, rx: Queue }

impl NetDevice for Nic {
    fn mac(&self) -> MacAddr { self.mac }
    fn transmit(&mut self, f: &[u8]) -> Result<(), NetError> { self.tx.borrow_mut().push_back(f.to_vec()); Ok(()) }
    fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        let f = self.rx.borrow_mut().pop_front()?;
        buf[..f.len()].copy_from_slice(&f);
        Some(f.len())
    }
}

const IP_A: [u8; 4] = [10, 0, 0, 1];
const IP_B: [u8; 4] = [10, 0, 0, 2];

#[derive(Clone, Copy, PartialEq)]
enum Tap { Pass, Tamper, Drop }

/// NIC の送信キューと受信キューの間にある「ケーブル」
struct Wire {
    a_out: Queue, a_in: Queue, b_out: Queue, b_in: Queue,
    tap: Tap,
    captured: Vec<Vec<u8>>,
}

struct Sim {
    a: Box<NetStack<Nic>>,
    b: Box<NetStack<Nic>>,
    wire: Wire,
    frame_no: usize,
}

fn ip(a: [u8; 4]) -> String { format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]) }
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

/// フレームを L2 → L4 まで解析して 1 行で表示
fn describe(f: &[u8]) -> String {
    let Some((eth, l3)) = EthHeader::parse(f) else { return "??".into() };
    match eth.ethertype {
        ETHERTYPE_ARP => {
            let a = ArpPacket::parse(l3).unwrap();
            if a.op == 1 { format!("ARP  who-has {} tell {}", ip(a.tpa), ip(a.spa)) }
            else { format!("ARP  {} is-at {}", ip(a.spa), hex(&a.sha)) }
        }
        ETHERTYPE_IPV4 => {
            let Some((h, l4)) = Ipv4Header::parse(l3) else { return "IPv4 (broken header)".into() };
            let Some((u, rec)) = UdpHeader::parse(h.src, h.dst, l4) else { return format!("IPv4 {}→{} UDP (checksum NG)", ip(h.src), ip(h.dst)) };
            match RecordHeader::parse(rec) {
                Ok(r) => {
                    let ct = &rec[qtls::RECORD_HDR_LEN..qtls::RECORD_HDR_LEN + r.length as usize];
                    format!("IPv4 {}:{}→{}:{} UDP | QTLS {:<8} sid={} key_off={:<5} len={:<3} ct={}",
                        ip(h.src), u.src_port, ip(h.dst), u.dst_port, format!("{:?}", r.ctype),
                        r.session_id, r.key_offset, r.length, hex(&ct[..ct.len().min(12)]))
                }
                Err(_) => "QTLS (malformed)".into(),
            }
        }
        t => format!("ethertype {t:#06x}"),
    }
}

impl Sim {
    fn new() -> Self {
        let q = || -> Queue { Default::default() };
        let (a_out, a_in, b_out, b_in) = (q(), q(), q(), q());
        let mut a = Box::new(NetStack::new(Nic { mac: [2, 0, 0, 0, 0, 0xA1], tx: a_out.clone(), rx: a_in.clone() }));
        let mut b = Box::new(NetStack::new(Nic { mac: [2, 0, 0, 0, 0, 0xB2], tx: b_out.clone(), rx: b_in.clone() }));
        a.configure(IP_A);
        b.configure(IP_B);
        a.register_peer(IP_B, LinkRole::A).unwrap();
        b.register_peer(IP_A, LinkRole::B).unwrap();
        Self { a, b, wire: Wire { a_out, a_in, b_out, b_in, tap: Tap::Pass, captured: vec![] }, frame_no: 0 }
    }

    /// L1: 量子リンクで鍵ブロックを配る
    fn distribute_keys(&mut self, link: &mut SimQuantumLink<XorShift64>, blocks: usize) {
        for _ in 0..blocks {
            match link.harvest() {
                Ok(blk) => {
                    println!("  [L1] block #{:<2} {} B  QBER={:.2}%  EC公開パリティ={}  lane={}  先頭={}…",
                        blk.seq, blk.a.len(), blk.qber_ppm as f64 / 1e4, blk.leaked_bits,
                        if blk.seq % 2 == 0 { "Alice→Bob" } else { "Bob→Alice" }, hex(&blk.a[..6]));
                    assert_eq!(blk.a, blk.b);
                    self.a.deposit_key_block(IP_B, blk.seq, &blk.a).unwrap();
                    self.b.deposit_key_block(IP_A, blk.seq, &blk.b).unwrap();
                }
                Err(e) => println!("  [L1] ✗ ブロック破棄: {e:?}"),
            }
        }
        self.show_keys();
    }

    fn show_keys(&self) {
        let (atx, arx) = self.a.key_available(IP_B).unwrap();
        let (btx, brx) = self.b.key_available(IP_A).unwrap();
        println!("  [鍵] Alice tx={atx:<5} rx={arx:<5} | Bob tx={btx:<5} rx={brx:<5}");
    }

    /// ケーブル上のフレームを相手に届ける (表示・改ざん付き)
    fn carry(&mut self, from_out: bool, mut f: Vec<u8>) {
        self.frame_no += 1;
        let arrow = if from_out { "Alice ─▶ Bob  " } else { "Bob   ─▶ Alice" };
        let mut note = "";
        if self.wire.tap == Tap::Tamper && f.len() > 80 {
            let i = f.len() - qtls::TAG_LEN - 1;
            f[i] ^= 0x01;
            f[14 + 20 + 6] = 0; f[14 + 20 + 7] = 0; // UDP チェックサムも辻褄合わせ (無効化)
            note = "  ⚡改ざん";
        }
        println!("  #{:<3} {arrow} {}{note}", self.frame_no, describe(&f));
        if self.wire.tap == Tap::Drop { println!("        └ 経路上で消失"); return; }
        self.wire.captured.push(f.clone());
        let dst = if from_out { &self.wire.b_in } else { &self.wire.a_in };
        dst.borrow_mut().push_back(f);
    }

    /// 全キューが空になるまで「送る → 届ける → 処理」を繰り返す
    fn run(&mut self) {
        loop {
            let mut moved = false;
            loop {
                let f = self.wire.a_out.borrow_mut().pop_front();
                let Some(f) = f else { break };
                moved = true;
                self.carry(true, f);
            }
            loop {
                let f = self.wire.b_out.borrow_mut().pop_front();
                let Some(f) = f else { break };
                moved = true;
                self.carry(false, f);
            }
            let n = self.a.poll() + self.b.poll();
            if !moved && n == 0 && self.wire.a_out.borrow().is_empty() && self.wire.b_out.borrow().is_empty() { break; }
        }
    }

    fn connect(&mut self) -> (SessionHandle, SessionHandle) {
        self.b.listen(QTLS_PORT).unwrap();
        loop {
            match self.a.connect(IP_B, QTLS_PORT) {
                Ok(h) => { self.run(); let s = self.b.accept(QTLS_PORT).expect("accept"); return (h, s); }
                Err(NetError::ArpPending) => { println!("  [Alice] connect → ARP 解決待ち"); self.run(); }
                Err(e) => panic!("connect: {e:?}"),
            }
        }
    }
}

fn say(sim: &mut Sim, from_alice: bool, h: SessionHandle, peer_h: SessionHandle, msg: &str) {
    let who = if from_alice { "Alice" } else { "Bob" };
    println!("  [{who}] send \"{msg}\"");
    let r = if from_alice { sim.a.send(h, msg.as_bytes()) } else { sim.b.send(h, msg.as_bytes()) };
    if let Err(e) = r { println!("  [{who}] ✗ 送信拒否: {e:?}"); return; }
    sim.run();
    let mut buf = [0u8; 1500];
    let rx = if from_alice { sim.b.recv(peer_h, &mut buf) } else { sim.a.recv(peer_h, &mut buf) };
    match rx {
        Ok(n) => println!("  [{}] recv \"{}\"", if from_alice { "Bob" } else { "Alice" }, String::from_utf8_lossy(&buf[..n])),
        Err(e) => println!("  [{}] ✗ 受信なし: {e:?}", if from_alice { "Bob" } else { "Alice" }),
    }
}

fn section(t: &str) { println!("\n━━━ {t} {}", "━".repeat(60usize.saturating_sub(t.chars().count() * 2))); }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = match args.get(1).map(String::as_str) {
        Some("dense") => KeyMode::SuperdenseCoding,
        Some("teleport") => KeyMode::Teleportation,
        _ => KeyMode::Entanglement,
    };
    let noise: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5_000);
    let model = ChannelModel { depolarize_ppm: noise, eavesdropper: false };

    println!("QLinux 二台通信シミュレーション   L1モード={mode:?}  量子チャネル雑音={:.2}%", noise as f64 / 1e4);
    println!("  Alice {} (LinkRole::A)   ⇄   Bob {} (LinkRole::B)", ip(IP_A), ip(IP_B));

    // ── 1. 正常系 ──
    section("1. L1 量子鍵配送");
    let mut sim = Sim::new();
    let mut link = SimQuantumLink::new(XorShift64::new(2026), model, mode);
    sim.distribute_keys(&mut link, 6);

    let (atx, arx) = sim.a.key_available(IP_B).unwrap();
    if atx < qtls::key_cost(0) || arx < qtls::key_cost(0) {
        println!("
  鍵が両方向に揃わないため QTLS は開始できません (雑音を下げてください)");
        return;
    }

    section("2. ARP + QTLS ハンドシェイク");
    let (ca, sb) = sim.connect();
    println!("  セッション確立: Alice={:?} Bob={:?}", sim.a.state(ca), sim.b.state(sb));
    sim.show_keys();

    section("3. データ通信");
    say(&mut sim, true, ca, sb, "Hello Bob, this is Alice over QTLS");
    say(&mut sim, false, sb, ca, "Hi Alice! OTP key never reused.");
    say(&mut sim, true, ca, sb, "送金 100 円");
    sim.show_keys();
    let leak = sim.wire.captured.iter().any(|f| f.windows(5).any(|w| w == b"Hello"));
    println!("  ケーブル上に平文 \"Hello\" が現れたか: {}", if leak { "YES ✗" } else { "NO ✓" });

    // ── 2. 攻撃 ──
    section("4. 攻撃: 古典回線上の改ざん");
    sim.wire.tap = Tap::Tamper;
    say(&mut sim, true, ca, sb, "送金 100 円");
    sim.wire.tap = Tap::Pass;
    println!("  → Poly1305 タグ不一致で破棄。鍵は消費されないので再送は通る:");
    say(&mut sim, true, ca, sb, "送金 100 円 (再送)");

    section("5. 攻撃: リプレイ");
    let old = sim.wire.captured.iter().rev()
        .find(|f| describe(f).contains("Data")).unwrap().clone();
    println!("  Eve が過去のフレームを再注入: {}", describe(&old));
    sim.wire.b_in.borrow_mut().push_back(old);
    sim.b.poll();
    match sim.b.recv(sb, &mut [0u8; 64]) {
        Err(NetError::WouldBlock) => println!("  → Bob: 消費済み key_offset のため破棄 ✓"),
        r => println!("  → Bob: 想定外 {r:?}"),
    }

    section("6. 攻撃: 量子チャネルの盗聴 (intercept-resend)");
    let mut eve_link = SimQuantumLink::new(XorShift64::new(7), ChannelModel { eavesdropper: true, ..model }, mode);
    sim.distribute_keys(&mut eve_link, 3);
    println!("  → 盗聴された鍵は一切レーンに積まれない");

    section("7. 鍵の枯渇");
    let (tx, _) = sim.a.key_available(IP_B).unwrap();
    println!("  Alice の送信用残り鍵 {tx} B に対し 200 B (鍵消費 {} B) の送信を連続実行", qtls::key_cost(200));
    let big = vec![b'x'; 200];
    let mut sent = 0;
    loop {
        match sim.a.send(ca, &big) {
            Ok(_) => { sent += 1; sim.wire.a_out.borrow_mut().clear(); }
            Err(e) => { println!("  {sent} レコード送信後に拒否: {e:?} (古典暗号へのフォールバックなし)"); break; }
        }
    }
    println!("  再び L1 から鍵を供給 (Alice→Bob レーンが埋まるまで):");
    let before = sim.a.key_available(IP_B).unwrap().0;
    while sim.a.key_available(IP_B).unwrap().0 == before { sim.distribute_keys(&mut link, 1); }
    sim.wire.b_in.borrow_mut().clear();
    say(&mut sim, true, ca, sb, "鍵補充後のメッセージ");

    section("8. 切断");
    sim.a.close(ca).unwrap();
    sim.run();
    println!("  Bob 側セッション: {:?}", sim.b.state(sb));
    assert_eq!(sim.b.state(sb), SessionState::Closed);
    println!("\n合計 {} フレームがケーブルを通過", sim.frame_no);
}
