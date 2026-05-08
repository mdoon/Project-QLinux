//! QOnion — End-to-End セキュアパイプライン

use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroizing;

use qtor::{QTorNode, Circuit, CircuitState, CIRCUIT_HOPS, QTorError};
use key_pool::{KeyPoolManager, KeyPoolError};
use wc_auth::{WcAuthSession, SessionRole, WcAuthError};

#[derive(Debug, Error)]
pub enum QOnionError {
    #[error("認証失敗")]
    AuthFailed,
    #[error("回路構築失敗: {0}")]
    CircuitBuild(#[from] QTorError),
    #[error("鍵プールエラー: {0}")]
    KeyPool(#[from] KeyPoolError),
    #[error("WC認証エラー: {0}")]
    WcAuth(#[from] WcAuthError),
    #[error("SOCKS5プロトコルエラー")]
    Socks5Protocol,
    #[error("接続タイムアウト")]
    Timeout,
    #[error("パイプライン初期化失敗")]
    InitFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Socks5Cmd { Connect = 1, Bind = 2, UdpAssoc = 3 }

#[derive(Debug, Clone)]
pub enum Socks5Addr {
    Ipv4([u8; 4]),
    Domain(String),
    Ipv6([u8; 16]),
}

#[derive(Debug, Clone)]
pub struct Socks5Request {
    pub cmd:  Socks5Cmd,
    pub addr: Socks5Addr,
    pub port: u16,
}

impl Socks5Request {
    pub fn parse(buf: &[u8]) -> Result<Self, QOnionError> {
        if buf.len() < 7 { return Err(QOnionError::Socks5Protocol); }
        if buf[0] != 5   { return Err(QOnionError::Socks5Protocol); }
        if buf[2] != 0   { return Err(QOnionError::Socks5Protocol); }

        let cmd = match buf[1] {
            1 => Socks5Cmd::Connect,
            2 => Socks5Cmd::Bind,
            3 => Socks5Cmd::UdpAssoc,
            _ => return Err(QOnionError::Socks5Protocol),
        };

        let (addr, port_offset) = match buf[3] {
            1 => {
                if buf.len() < 10 { return Err(QOnionError::Socks5Protocol); }
                (Socks5Addr::Ipv4([buf[4], buf[5], buf[6], buf[7]]), 8)
            }
            3 => {
                let len = buf[4] as usize;
                if buf.len() < 5 + len + 2 { return Err(QOnionError::Socks5Protocol); }
                let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
                (Socks5Addr::Domain(domain), 5 + len)
            }
            4 => {
                if buf.len() < 22 { return Err(QOnionError::Socks5Protocol); }
                let mut a = [0u8; 16];
                a.copy_from_slice(&buf[4..20]);
                (Socks5Addr::Ipv6(a), 20)
            }
            _ => return Err(QOnionError::Socks5Protocol),
        };

        let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
        Ok(Self { cmd, addr, port })
    }
}

pub struct QOnionConfig {
    pub socks5_listen: SocketAddr,
    pub node_addrs:    [SocketAddr; CIRCUIT_HOPS],
    pub min_key_bytes: usize,
}

impl Default for QOnionConfig {
    fn default() -> Self {
        Self {
            socks5_listen: "127.0.0.1:9050".parse().unwrap(),
            node_addrs: [
                "127.0.0.1:9001".parse().unwrap(),
                "127.0.0.1:9002".parse().unwrap(),
                "127.0.0.1:9003".parse().unwrap(),
            ],
            min_key_bytes: 1024 * 1024,
        }
    }
}

pub struct QOnionPipeline {
    config:        QOnionConfig,
    key_pool:      Arc<KeyPoolManager>,
    authenticated: bool,
    node:          Option<QTorNode>,
}

impl QOnionPipeline {
    pub fn new(config: QOnionConfig, key_pool: Arc<KeyPoolManager>) -> Self {
        Self { config, key_pool, authenticated: false, node: None }
    }

    pub fn complete_auth(&mut self) -> Result<(), QOnionError> {
        self.authenticated = true;
        Ok(())
    }

    pub fn build_circuit(&mut self, circuit_id: u32) -> Result<(), QOnionError> {
        if !self.authenticated { return Err(QOnionError::AuthFailed); }

        let mut hops = Vec::with_capacity(CIRCUIT_HOPS);
        for (i, &addr) in self.config.node_addrs.iter().enumerate() {
            let (_key_id, hop_key) = self.key_pool.acquire(32)?;
            let session = WcAuthSession::new(
                Zeroizing::new(hop_key.to_vec()), 0, SessionRole::Sender,
            )?;
            hops.push(qtor::HopContext { session, addr, hop_idx: i });
        }

        let circuit = Circuit { id: circuit_id, hops, state: CircuitState::Ready };
        let node = self.node.get_or_insert_with(|| {
            QTorNode::new(self.config.socks5_listen, Arc::clone(&self.key_pool))
        });
        node.register_circuit(circuit)?;
        Ok(())
    }

    pub fn send(&mut self, circuit_id: u32, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, QOnionError> {
        let node = self.node.as_mut().ok_or(QOnionError::InitFailed)?;
        let circuit = node.get_circuit_mut(circuit_id).ok_or(QTorError::CircuitNotFound)?;
        Ok(circuit.onion_encrypt(data)?)
    }

    pub fn close_circuit(&mut self, circuit_id: u32) {
        if let Some(node) = self.node.as_mut() { node.close_circuit(circuit_id); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_parse_ipv4() {
        let buf = [5u8, 1, 0, 1, 93, 184, 216, 34, 0, 80];
        let req = Socks5Request::parse(&buf).unwrap();
        assert_eq!(req.cmd, Socks5Cmd::Connect);
        assert_eq!(req.port, 80);
        match req.addr {
            Socks5Addr::Ipv4(a) => assert_eq!(a, [93, 184, 216, 34]),
            _ => panic!("wrong addr type"),
        }
    }

    #[test]
    fn test_socks5_parse_domain() {
        let domain = b"example.com";
        let mut buf = vec![5u8, 1, 0, 3, domain.len() as u8];
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&[0u8, 80]);
        let req = Socks5Request::parse(&buf).unwrap();
        match req.addr {
            Socks5Addr::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("wrong addr type"),
        }
    }

    #[test]
    fn test_socks5_bad_version() {
        let buf = [4u8, 1, 0, 1, 0, 0, 0, 0, 0, 80];
        assert!(Socks5Request::parse(&buf).is_err());
    }

    #[test]
    fn test_pipeline_requires_auth() {
        let pool = Arc::new(KeyPoolManager::new(64).unwrap());
        let mut pipeline = QOnionPipeline::new(QOnionConfig::default(), pool);
        assert!(matches!(pipeline.build_circuit(1), Err(QOnionError::AuthFailed)));
    }
}
