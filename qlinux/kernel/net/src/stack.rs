//! カーネル内ネットワークスタック: Ethernet → ARP/IPv4 → UDP → QTLS

use qkey::{LinkRole, PeerKeys};
use zeroize::Zeroize;

use crate::arp::{ArpCache, ArpPacket, ARP_LEN, OP_REPLY, OP_REQUEST};
use crate::device::NetDevice;
use crate::eth::{EthHeader, MacAddr, BROADCAST, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETH_HDR_LEN, MAX_FRAME};
use crate::ipv4::{Ipv4Addr, Ipv4Header, IPV4_HDR_LEN, PROTO_UDP};
use crate::qtls::{self, ContentType, MAX_RECORD_LEN, MAX_RECORD_PAYLOAD};
use crate::udp::{UdpHeader, UDP_HDR_LEN};
use crate::NetError;

pub const MAX_PEERS: usize = 2;
pub const MAX_SESSIONS: usize = 4;
const MAX_LISTEN: usize = 4;
const RX_SLOTS: usize = 4;
const EPHEMERAL_BASE: u16 = 49152;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHandle(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState { Free, HelloSent, Established, Closed }

struct RxQueue {
    msgs:  [[u8; MAX_RECORD_PAYLOAD]; RX_SLOTS],
    lens:  [usize; RX_SLOTS],
    head:  usize,
    count: usize,
}

impl RxQueue {
    const fn new() -> Self { Self { msgs: [[0; MAX_RECORD_PAYLOAD]; RX_SLOTS], lens: [0; RX_SLOTS], head: 0, count: 0 } }

    fn push(&mut self, data: &[u8]) -> bool {
        if self.count == RX_SLOTS { return false; }
        let s = (self.head + self.count) % RX_SLOTS;
        self.msgs[s][..data.len()].copy_from_slice(data);
        self.lens[s] = data.len();
        self.count += 1;
        true
    }

    fn pop(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.count == 0 { return None; }
        let n = self.lens[self.head];
        if out.len() < n { return None; }
        out[..n].copy_from_slice(&self.msgs[self.head][..n]);
        self.msgs[self.head].zeroize();
        self.head = (self.head + 1) % RX_SLOTS;
        self.count -= 1;
        Some(n)
    }

    fn wipe(&mut self) {
        for m in self.msgs.iter_mut() { m.zeroize(); }
        self.count = 0;
    }
}

struct Session {
    state:      SessionState,
    id:         u16,
    peer_ip:    Ipv4Addr,
    peer_port:  u16,
    local_port: u16,
    accepted:   bool,
    rx:         RxQueue,
}

impl Session {
    const fn empty() -> Self {
        Self { state: SessionState::Free, id: 0, peer_ip: [0; 4], peer_port: 0, local_port: 0, accepted: true, rx: RxQueue::new() }
    }
}

struct Peer {
    ip:   Option<Ipv4Addr>,
    keys: PeerKeys,
}

pub struct NetStack<D: NetDevice> {
    dev:          D,
    ip:           Ipv4Addr,
    arp:          ArpCache,
    peers:        [Peer; MAX_PEERS],
    sessions:     [Session; MAX_SESSIONS],
    listen:       [u16; MAX_LISTEN],
    ip_id:        u16,
    next_session: u16,
}

impl<D: NetDevice> NetStack<D> {
    pub const fn new(dev: D) -> Self {
        const PEER: Peer = Peer { ip: None, keys: PeerKeys::new(LinkRole::A) };
        const SESSION: Session = Session::empty();
        Self {
            dev, ip: [0; 4], arp: ArpCache::new(),
            peers: [PEER; MAX_PEERS], sessions: [SESSION; MAX_SESSIONS],
            listen: [0; MAX_LISTEN], ip_id: 1, next_session: 1,
        }
    }

    pub fn configure(&mut self, ip: Ipv4Addr) { self.ip = ip; }
    pub fn ip(&self) -> Ipv4Addr { self.ip }
    pub fn device(&mut self) -> &mut D { &mut self.dev }

    // ─── L1 鍵供給との接続 ─────────────────────────────────────────────

    /// 量子リンクで繋がったピアを登録する。role は L1 リンク上の自ノードの役割
    pub fn register_peer(&mut self, ip: Ipv4Addr, role: LinkRole) -> Result<(), NetError> {
        if self.peer_index(ip).is_some() { return Ok(()); }
        let p = self.peers.iter_mut().find(|p| p.ip.is_none()).ok_or(NetError::TableFull)?;
        p.ip = Some(ip);
        p.keys.role = role;
        Ok(())
    }

    /// L1 ドライバが生成した鍵ブロックを積む
    pub fn deposit_key_block(&mut self, peer: Ipv4Addr, seq: u64, key: &[u8]) -> Result<(), NetError> {
        let i = self.peer_index(peer).ok_or(NetError::NoPeer)?;
        self.peers[i].keys.deposit_block(seq, key).map_err(NetError::Key)
    }

    /// (送信可能鍵, 受信用鍵) のバイト数
    pub fn key_available(&self, peer: Ipv4Addr) -> Option<(usize, usize)> {
        let k = &self.peers[self.peer_index(peer)?].keys;
        Some((k.tx_ref().available(), k.rx_ref().available()))
    }

    pub fn wipe_keys(&mut self) {
        for p in self.peers.iter_mut() { p.keys.wipe(); }
        for s in self.sessions.iter_mut() { s.rx.wipe(); }
    }

    fn peer_index(&self, ip: Ipv4Addr) -> Option<usize> {
        self.peers.iter().position(|p| p.ip == Some(ip))
    }

    // ─── QTLS ソケット API (syscall 層から呼ばれる) ─────────────────────

    pub fn listen(&mut self, port: u16) -> Result<(), NetError> {
        if self.listen.contains(&port) { return Ok(()); }
        let slot = self.listen.iter_mut().find(|p| **p == 0).ok_or(NetError::TableFull)?;
        *slot = port;
        Ok(())
    }

    pub fn connect(&mut self, peer_ip: Ipv4Addr, port: u16) -> Result<SessionHandle, NetError> {
        let pi = self.peer_index(peer_ip).ok_or(NetError::NoPeer)?;
        self.resolve(peer_ip)?;
        let si = self.sessions.iter().position(|s| s.state == SessionState::Free).ok_or(NetError::TableFull)?;
        let id = self.next_session;
        self.next_session = self.next_session.wrapping_add(1).max(1);
        let local_port = EPHEMERAL_BASE + id % 16384;
        self.sessions[si] = Session { state: SessionState::HelloSent, id, peer_ip, peer_port: port, local_port, accepted: true, rx: RxQueue::new() };
        if let Err(e) = self.send_record(pi, si, ContentType::Hello, &[]) {
            self.sessions[si].state = SessionState::Free;
            return Err(e);
        }
        Ok(SessionHandle(si))
    }

    /// サーバ側: 確立済みで未取得のセッションを返す
    pub fn accept(&mut self, port: u16) -> Option<SessionHandle> {
        let si = self.sessions.iter().position(|s| {
            s.state == SessionState::Established && !s.accepted && s.local_port == port
        })?;
        self.sessions[si].accepted = true;
        Some(SessionHandle(si))
    }

    pub fn state(&self, h: SessionHandle) -> SessionState {
        self.sessions.get(h.0).map_or(SessionState::Free, |s| s.state)
    }

    pub fn send(&mut self, h: SessionHandle, data: &[u8]) -> Result<usize, NetError> {
        let s = self.sessions.get(h.0).ok_or(NetError::NoSession)?;
        if s.state != SessionState::Established { return Err(NetError::NotEstablished); }
        let pi = self.peer_index(s.peer_ip).ok_or(NetError::NoPeer)?;
        let n = data.len().min(MAX_RECORD_PAYLOAD);
        self.send_record(pi, h.0, ContentType::Data, &data[..n])?;
        Ok(n)
    }

    pub fn recv(&mut self, h: SessionHandle, out: &mut [u8]) -> Result<usize, NetError> {
        let s = self.sessions.get_mut(h.0).ok_or(NetError::NoSession)?;
        if let Some(n) = s.rx.pop(out) { return Ok(n); }
        match s.state {
            SessionState::Closed => Ok(0),
            SessionState::Free   => Err(NetError::NoSession),
            _                    => Err(NetError::WouldBlock),
        }
    }

    pub fn close(&mut self, h: SessionHandle) -> Result<(), NetError> {
        let s = self.sessions.get(h.0).ok_or(NetError::NoSession)?;
        if s.state == SessionState::Established {
            if let Some(pi) = self.peer_index(s.peer_ip) {
                let _ = self.send_record(pi, h.0, ContentType::Close, &[]);
            }
        }
        self.sessions[h.0].rx.wipe();
        self.sessions[h.0] = Session::empty();
        Ok(())
    }

    // ─── 受信処理 ─────────────────────────────────────────────────────

    /// NIC の受信キューを空になるまで処理し、処理したフレーム数を返す
    pub fn poll(&mut self) -> usize {
        let mut frame = [0u8; MAX_FRAME];
        let mut n = 0;
        while let Some(len) = self.dev.receive(&mut frame) {
            self.handle_frame(&frame[..len]);
            n += 1;
        }
        frame.zeroize();
        n
    }

    fn handle_frame(&mut self, frame: &[u8]) {
        let Some((eth, payload)) = EthHeader::parse(frame) else { return };
        if eth.dst != self.dev.mac() && eth.dst != BROADCAST { return; }
        match eth.ethertype {
            ETHERTYPE_ARP  => self.handle_arp(payload),
            ETHERTYPE_IPV4 => self.handle_ipv4(payload),
            _ => {}
        }
    }

    fn handle_arp(&mut self, p: &[u8]) {
        let Some(arp) = ArpPacket::parse(p) else { return };
        if arp.tpa != self.ip { return; }
        // [HARDENING] ARP キャッシュ汚染を抑えるため、鍵を共有している登録済みピアの
        // IP についてのみ学習する。未知の相手の MAC は保持しない。
        // (たとえ経路を奪われても QTLS の暗号文は復号されないが、妨害を減らす)
        if self.peer_index(arp.spa).is_some() {
            self.arp.insert(arp.spa, arp.sha);
        }
        if arp.op == OP_REQUEST {
            let reply = ArpPacket { op: OP_REPLY, sha: self.dev.mac(), spa: self.ip, tha: arp.sha, tpa: arp.spa };
            let _ = self.send_arp(arp.sha, &reply);
        }
    }

    fn handle_ipv4(&mut self, p: &[u8]) {
        let Some((ip, seg)) = Ipv4Header::parse(p) else { return };
        if ip.dst != self.ip || ip.protocol != PROTO_UDP { return; }
        let Some((udp, rec)) = UdpHeader::parse(ip.src, ip.dst, seg) else { return };
        self.handle_qtls(ip.src, udp.src_port, udp.dst_port, rec);
    }

    fn handle_qtls(&mut self, src: Ipv4Addr, src_port: u16, dst_port: u16, rec: &[u8]) {
        // 量子リンクで鍵を共有していない相手とは一切通信しない
        let Some(pi) = self.peer_index(src) else { return };
        let Ok(hdr) = qtls::RecordHeader::parse(rec) else { return };

        let existing = self.sessions.iter().position(|s| {
            s.state != SessionState::Free && s.peer_ip == src && s.peer_port == src_port
                && s.local_port == dst_port && s.id == hdr.session_id
        });
        let fresh_hello = hdr.ctype == ContentType::Hello && existing.is_none() && self.listen.contains(&dst_port);
        if existing.is_none() && !fresh_hello { return; }

        let mut pt = [0u8; MAX_RECORD_PAYLOAD];
        let Ok((hdr, len)) = qtls::open(self.peers[pi].keys.rx(), rec, &mut pt) else { return };

        match (hdr.ctype, existing) {
            (ContentType::Hello, None) => {
                let Some(si) = self.sessions.iter().position(|s| s.state == SessionState::Free) else { return };
                self.sessions[si] = Session {
                    state: SessionState::Established, id: hdr.session_id, peer_ip: src,
                    peer_port: src_port, local_port: dst_port, accepted: false, rx: RxQueue::new(),
                };
                // クライアントの MAC は直前の ARP 要求で学習済み
                let _ = self.send_record(pi, si, ContentType::HelloAck, &[]);
            }
            (ContentType::HelloAck, Some(si)) if self.sessions[si].state == SessionState::HelloSent => {
                self.sessions[si].state = SessionState::Established;
            }
            (ContentType::Data, Some(si)) if self.sessions[si].state == SessionState::Established => {
                let _ = self.sessions[si].rx.push(&pt[..len]);
            }
            (ContentType::Close, Some(si)) => self.sessions[si].state = SessionState::Closed,
            _ => {}
        }
        pt.zeroize();
    }

    // ─── 送信処理 ─────────────────────────────────────────────────────

    fn send_record(&mut self, pi: usize, si: usize, ctype: ContentType, data: &[u8]) -> Result<(), NetError> {
        let (peer_ip, sport, dport, id) = {
            let s = &self.sessions[si];
            (s.peer_ip, s.local_port, s.peer_port, s.id)
        };
        // 送信前に宛先 MAC を確定させる (鍵を消費した後に送れないのを防ぐ)
        let dst_mac = self.resolve(peer_ip)?;
        let mut rec = [0u8; MAX_RECORD_LEN];
        let n = qtls::seal(self.peers[pi].keys.tx(), ctype, id, data, &mut rec)?;
        let r = self.send_udp(dst_mac, peer_ip, sport, dport, &rec[..n]);
        rec.zeroize();
        r
    }

    /// ARP 解決。未解決なら要求をブロードキャストして ArpPending を返す
    fn resolve(&mut self, ip: Ipv4Addr) -> Result<MacAddr, NetError> {
        if let Some(mac) = self.arp.lookup(ip) { return Ok(mac); }
        let req = ArpPacket { op: OP_REQUEST, sha: self.dev.mac(), spa: self.ip, tha: [0; 6], tpa: ip };
        self.send_arp(BROADCAST, &req)?;
        Err(NetError::ArpPending)
    }

    fn send_arp(&mut self, dst: MacAddr, pkt: &ArpPacket) -> Result<(), NetError> {
        let mut f = [0u8; ETH_HDR_LEN + ARP_LEN];
        let o = EthHeader { dst, src: self.dev.mac(), ethertype: ETHERTYPE_ARP }.write(&mut f);
        pkt.write(&mut f[o..]);
        self.dev.transmit(&f)
    }

    fn send_udp(&mut self, dst_mac: MacAddr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Result<(), NetError> {
        const L3: usize = ETH_HDR_LEN;
        const L4: usize = L3 + IPV4_HDR_LEN;
        const L7: usize = L4 + UDP_HDR_LEN;
        let total = L7 + payload.len();
        if total > MAX_FRAME { return Err(NetError::PayloadTooLarge); }
        let mut f = [0u8; MAX_FRAME];
        EthHeader { dst: dst_mac, src: self.dev.mac(), ethertype: ETHERTYPE_IPV4 }.write(&mut f);
        f[L7..total].copy_from_slice(payload);
        let udp_len = UdpHeader { src_port: sport, dst_port: dport }.finish(self.ip, dst, payload.len(), &mut f[L4..]);
        let id = self.ip_id;
        self.ip_id = self.ip_id.wrapping_add(1);
        Ipv4Header::write(self.ip, dst, PROTO_UDP, id, udp_len, &mut f[L3..]);
        let r = self.dev.transmit(&f[..total]);
        f.zeroize();
        r
    }
}
