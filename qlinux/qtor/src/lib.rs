//! QTor — Quantum-keyed Onion Router

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use wc_auth::{WcAuthSession, WcAuthError};
use key_pool::{KeyPoolManager, KeyPoolError};

pub const CELL_SIZE:       usize = 512;
pub const CELL_HEADER_LEN: usize = 5;
pub const CELL_PAYLOAD:    usize = CELL_SIZE - CELL_HEADER_LEN;
pub const CIRCUIT_HOPS:    usize = 3;
pub const MAX_CIRCUITS:    usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellCmd {
    Create  = 1,
    Created = 2,
    Relay   = 3,
    Destroy = 4,
    Padding = 7,
}

impl TryFrom<u8> for CellCmd {
    type Error = QTorError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Create),
            2 => Ok(Self::Created),
            3 => Ok(Self::Relay),
            4 => Ok(Self::Destroy),
            7 => Ok(Self::Padding),
            _ => Err(QTorError::UnknownCommand(v)),
        }
    }
}

#[derive(Debug, Error)]
pub enum QTorError {
    #[error("回路が見つかりません")]
    CircuitNotFound,
    #[error("ホップ数が不正です")]
    InvalidHopCount,
    #[error("セルサイズが不正です")]
    InvalidCellSize,
    #[error("不明なコマンド: {0}")]
    UnknownCommand(u8),
    #[error("OTP鍵エラー: {0}")]
    KeyPool(#[from] KeyPoolError),
    #[error("WC認証エラー: {0}")]
    WcAuth(#[from] WcAuthError),
    #[error("最大回路数超過")]
    TooManyCircuits,
    #[error("ノードへの接続失敗")]
    ConnectionFailed,
}

#[derive(Zeroize)]
pub struct Cell {
    pub circuit_id: u32,
    pub cmd:        u8,
    pub payload:    [u8; CELL_PAYLOAD],
}

impl Cell {
    pub fn new(circuit_id: u32, cmd: CellCmd) -> Self {
        Self { circuit_id, cmd: cmd as u8, payload: [0u8; CELL_PAYLOAD] }
    }

    pub fn from_bytes(raw: &[u8; CELL_SIZE]) -> Result<Self, QTorError> {
        let circuit_id = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        let cmd = raw[4];
        let mut payload = [0u8; CELL_PAYLOAD];
        payload.copy_from_slice(&raw[5..]);
        Ok(Self { circuit_id, cmd, payload })
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; CELL_SIZE]> {
        let mut out = Zeroizing::new([0u8; CELL_SIZE]);
        out[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        out[4] = self.cmd;
        out[5..].copy_from_slice(&self.payload);
        out
    }

    pub fn apply_otp(&mut self, key: &[u8]) -> Result<(), QTorError> {
        if key.len() < CELL_PAYLOAD { return Err(QTorError::InvalidCellSize); }
        for (b, k) in self.payload.iter_mut().zip(key.iter()) { *b ^= k; }
        Ok(())
    }
}

pub struct HopContext {
    pub session: WcAuthSession,
    pub addr:    SocketAddr,
    pub hop_idx: usize,
}

pub struct Circuit {
    pub id:    u32,
    pub hops:  Vec<HopContext>,
    pub state: CircuitState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState { Building, Ready, Closed }

impl Circuit {
    pub fn onion_encrypt(&mut self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, QTorError> {
        if self.hops.len() != CIRCUIT_HOPS { return Err(QTorError::InvalidHopCount); }
        let mut data = plaintext.to_vec();
        for hop in self.hops.iter_mut().rev() {
            let wrapped = hop.session.seal(&data)?;
            data = wrapped.to_vec();
        }
        Ok(Zeroizing::new(data))
    }

    pub fn onion_peel(session: &mut WcAuthSession, cell_data: &[u8]) -> Result<Zeroizing<Vec<u8>>, QTorError> {
        Ok(session.open(cell_data)?)
    }
}

pub struct QTorNode {
    pub listen_addr: SocketAddr,
    pub key_pool:    Arc<KeyPoolManager>,
    circuits:        HashMap<u32, Circuit>,
}

impl QTorNode {
    pub fn new(listen_addr: SocketAddr, key_pool: Arc<KeyPoolManager>) -> Self {
        Self { listen_addr, key_pool, circuits: HashMap::new() }
    }

    pub fn register_circuit(&mut self, circuit: Circuit) -> Result<(), QTorError> {
        if self.circuits.len() >= MAX_CIRCUITS { return Err(QTorError::TooManyCircuits); }
        self.circuits.insert(circuit.id, circuit);
        Ok(())
    }

    pub fn get_circuit_mut(&mut self, id: u32) -> Option<&mut Circuit> {
        self.circuits.get_mut(&id)
    }

    pub fn close_circuit(&mut self, id: u32) {
        self.circuits.remove(&id);
    }

    pub fn make_padding_cell(circuit_id: u32) -> Cell {
        Cell::new(circuit_id, CellCmd::Padding)
    }
}

#[derive(Debug, Clone)]
pub struct NodeDescriptor {
    pub addr:     SocketAddr,
    pub node_id:  [u8; 32],
    pub key_hint: [u8; 8],
    pub role:     NodeRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole { Guard, Middle, Exit, Any }

pub struct Directory { nodes: Vec<NodeDescriptor> }

impl Directory {
    pub fn new() -> Self { Self { nodes: Vec::new() } }

    pub fn add_node(&mut self, node: NodeDescriptor) { self.nodes.push(node); }

    pub fn candidates(&self, role: NodeRole) -> Vec<&NodeDescriptor> {
        self.nodes.iter()
            .filter(|n| n.role == role || n.role == NodeRole::Any)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_serialize_deserialize() {
        let mut cell = Cell::new(0xDEADBEEF, CellCmd::Relay);
        cell.payload[0] = 0x42;
        let bytes = cell.to_bytes();
        let parsed = Cell::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.circuit_id, 0xDEADBEEF);
        assert_eq!(parsed.cmd, CellCmd::Relay as u8);
        assert_eq!(parsed.payload[0], 0x42);
    }

    #[test]
    fn test_cell_otp_xor_roundtrip() {
        let mut cell = Cell::new(1, CellCmd::Relay);
        cell.payload[0] = 0xFF;
        let key = vec![0xABu8; CELL_PAYLOAD];
        cell.apply_otp(&key).unwrap();
        assert_eq!(cell.payload[0], 0xFF ^ 0xAB);
        cell.apply_otp(&key).unwrap();
        assert_eq!(cell.payload[0], 0xFF);
    }

    #[test]
    fn test_cell_cmd_conversion() {
        assert_eq!(CellCmd::try_from(3u8).unwrap(), CellCmd::Relay);
        assert!(CellCmd::try_from(99u8).is_err());
    }

    #[test]
    fn test_circuit_state() {
        assert_eq!(CircuitState::Building, CircuitState::Building);
        assert_ne!(CircuitState::Ready, CircuitState::Closed);
    }

    #[test]
    fn test_directory_candidates() {
        let mut dir = Directory::new();
        dir.add_node(NodeDescriptor {
            addr: "127.0.0.1:9001".parse().unwrap(),
            node_id: [0u8; 32], key_hint: [0u8; 8], role: NodeRole::Guard,
        });
        dir.add_node(NodeDescriptor {
            addr: "127.0.0.1:9002".parse().unwrap(),
            node_id: [1u8; 32], key_hint: [1u8; 8], role: NodeRole::Any,
        });
        assert_eq!(dir.candidates(NodeRole::Guard).len(), 2);
    }
}
