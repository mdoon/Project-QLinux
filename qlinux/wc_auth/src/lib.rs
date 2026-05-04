use thiserror::Error;
use uhf::{ct_eq_16, Poly1305, Poly1305Key, UhfError, POLY1305_KEY_LEN, POLY1305_TAG_LEN};
use zeroize::{Zeroize, Zeroizing};

pub const WORD_BYTES: usize = 8;
pub const MAR_HEADER_LEN: usize = 8 + 4 + POLY1305_TAG_LEN;
pub const MAX_MSG_LEN: usize = 65536;
const SESSION_KEY_LEN: usize = POLY1305_KEY_LEN;
const CONTEXT_LABEL: &[u8] = b"qlinux-wc-auth-v1";

#[derive(Debug, Error)]
pub enum WcAuthError {
    #[error("認証タグが一致しません")]
    TagMismatch,
    #[error("word_count が期待値と不一致")]
    WordCountMismatch,
    #[error("メッセージが長すぎます")]
    MessageTooLong,
    #[error("MAR フォーマットが不正です")]
    InvalidMar,
    #[error("空のメッセージ")]
    EmptyMessage,
    #[error("鍵が不正です")]
    InvalidKey,
    #[error("word_count がオーバーフローします")]
    WordCountOverflow,
}

impl From<UhfError> for WcAuthError {
    fn from(e: UhfError) -> Self {
        match e {
            UhfError::TagMismatch      => Self::TagMismatch,
            UhfError::InvalidKeyLength => Self::InvalidKey,
            _                          => Self::InvalidMar,
        }
    }
}

pub struct Mar {
    pub word_count: u64,
    pub msg_len:    u32,
    pub tag:        [u8; POLY1305_TAG_LEN],
    pub payload:    Zeroizing<Vec<u8>>,
}

impl Mar {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, WcAuthError> {
        if raw.len() < MAR_HEADER_LEN { return Err(WcAuthError::InvalidMar); }
        let word_count = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let msg_len    = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let tag: [u8; POLY1305_TAG_LEN] = raw[12..12 + POLY1305_TAG_LEN].try_into().unwrap();
        let ps = MAR_HEADER_LEN;
        if raw.len() < ps + msg_len as usize { return Err(WcAuthError::InvalidMar); }
        let payload = Zeroizing::new(raw[ps..ps + msg_len as usize].to_vec());
        Ok(Self { word_count, msg_len, tag, payload })
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(MAR_HEADER_LEN + self.payload.len()));
        out.extend_from_slice(&self.word_count.to_le_bytes());
        out.extend_from_slice(&self.msg_len.to_le_bytes());
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.payload);
        out
    }
}

fn derive_subkey(master: &[u8; SESSION_KEY_LEN], word_count: u64) -> Zeroizing<[u8; SESSION_KEY_LEN]> {
    const LABEL_R: &[u8] = b"qlinux-wc-auth-v1-r";
    const LABEL_S: &[u8] = b"qlinux-wc-auth-v1-s";

    let mut input_r = Zeroizing::new(Vec::with_capacity(8 + LABEL_R.len()));
    input_r.extend_from_slice(&word_count.to_le_bytes());
    input_r.extend_from_slice(LABEL_R);
    let tag_r = Poly1305::mac(&Poly1305Key::new(master), &input_r);

    let mut input_s = Zeroizing::new(Vec::with_capacity(8 + LABEL_S.len()));
    input_s.extend_from_slice(&word_count.to_le_bytes());
    input_s.extend_from_slice(LABEL_S);
    let tag_s = Poly1305::mac(&Poly1305Key::new(master), &input_s);

    let mut subkey = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    subkey[..16].copy_from_slice(&tag_r);
    subkey[16..].copy_from_slice(&tag_s);
    subkey
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole { Sender, Receiver }

pub struct WcAuthSession {
    master_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    word_count: u64,
    role:       SessionRole,
}

impl Drop for WcAuthSession {
    fn drop(&mut self) { self.master_key.zeroize(); self.word_count = 0; }
}

impl WcAuthSession {
    pub fn new(master_key: Zeroizing<Vec<u8>>, initial_wc: u64, role: SessionRole) -> Result<Self, WcAuthError> {
        if master_key.len() != SESSION_KEY_LEN { return Err(WcAuthError::InvalidKey); }
        let mut key_arr = Zeroizing::new([0u8; SESSION_KEY_LEN]);
        key_arr.copy_from_slice(&master_key);
        Ok(Self { master_key: key_arr, word_count: initial_wc, role })
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WcAuthError> {
        if self.role != SessionRole::Sender   { return Err(WcAuthError::InvalidKey); }
        if plaintext.is_empty()               { return Err(WcAuthError::EmptyMessage); }
        if plaintext.len() > MAX_MSG_LEN      { return Err(WcAuthError::MessageTooLong); }
        let wc = self.word_count;
        let subkey = derive_subkey(&self.master_key, wc);
        let tag = Self::compute_tag(&Poly1305Key::new(&subkey), wc, plaintext);
        let mar = Mar { word_count: wc, msg_len: plaintext.len() as u32, tag,
                        payload: Zeroizing::new(plaintext.to_vec()) };
        self.word_count = self.word_count.checked_add(Self::bytes_to_words(plaintext.len()))
            .ok_or(WcAuthError::WordCountOverflow)?;
        Ok(mar.to_bytes())
    }

    pub fn open(&mut self, raw_mar: &[u8]) -> Result<Zeroizing<Vec<u8>>, WcAuthError> {
        if self.role != SessionRole::Receiver { return Err(WcAuthError::InvalidKey); }
        let mar = Mar::from_bytes(raw_mar)?;
        if mar.word_count != self.word_count  { return Err(WcAuthError::WordCountMismatch); }
        if mar.payload.is_empty()             { return Err(WcAuthError::EmptyMessage); }
        if mar.payload.len() > MAX_MSG_LEN    { return Err(WcAuthError::MessageTooLong); }
        let subkey = derive_subkey(&self.master_key, mar.word_count);
        let expected_tag = Self::compute_tag(&Poly1305Key::new(&subkey), mar.word_count, &mar.payload);
        if !ct_eq_16(&expected_tag, &mar.tag) { return Err(WcAuthError::TagMismatch); }
        self.word_count = self.word_count.checked_add(Self::bytes_to_words(mar.payload.len()))
            .ok_or(WcAuthError::WordCountOverflow)?;
        Ok(mar.payload)
    }

    pub fn current_word_count(&self) -> u64 { self.word_count }

    fn compute_tag(key: &Poly1305Key, word_count: u64, payload: &[u8]) -> [u8; POLY1305_TAG_LEN] {
        let mut ctx = Poly1305::new(key);
        ctx.update(&word_count.to_le_bytes());
        ctx.update(&(payload.len() as u32).to_le_bytes());
        ctx.update(payload);
        ctx.finalize()
    }

    pub fn bytes_to_words(bytes: usize) -> u64 {
        ((bytes + WORD_BYTES - 1) / WORD_BYTES) as u64
    }
}

pub fn create_session_pair(master_key: Zeroizing<Vec<u8>>) -> Result<(WcAuthSession, WcAuthSession), WcAuthError> {
    if master_key.len() != SESSION_KEY_LEN { return Err(WcAuthError::InvalidKey); }
    let key2 = Zeroizing::new(master_key.to_vec());
    let sender   = WcAuthSession::new(master_key, 0, SessionRole::Sender)?;
    let receiver = WcAuthSession::new(key2,       0, SessionRole::Receiver)?;
    Ok((sender, receiver))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_key() -> Zeroizing<Vec<u8>> { Zeroizing::new(vec![0x5Au8; SESSION_KEY_LEN]) }

    #[test]
    fn test_seal_open_roundtrip() {
        let (mut s, mut r) = create_session_pair(make_key()).unwrap();
        let mar = s.seal(b"Hello WC Auth").unwrap();
        assert_eq!(r.open(&mar).unwrap().as_slice(), b"Hello WC Auth");
    }

    #[test]
    fn test_replay_rejected() {
        let (mut s, mut r) = create_session_pair(make_key()).unwrap();
        let mar = s.seal(b"msg").unwrap();
        r.open(&mar).unwrap();
        assert!(matches!(r.open(&mar), Err(WcAuthError::WordCountMismatch)));
    }

    #[test]
    fn test_tag_tamper_rejected() {
        let (mut s, mut r) = create_session_pair(make_key()).unwrap();
        let mut mar = s.seal(b"tamper").unwrap().to_vec();
        mar[12] ^= 0xFF;
        assert!(matches!(r.open(&mar), Err(WcAuthError::TagMismatch)));
    }

    #[test]
    fn test_empty_rejected() {
        let (mut s, _) = create_session_pair(make_key()).unwrap();
        assert!(matches!(s.seal(b""), Err(WcAuthError::EmptyMessage)));
    }

    #[test]
    fn test_bytes_to_words() {
        assert_eq!(WcAuthSession::bytes_to_words(0), 0);
        assert_eq!(WcAuthSession::bytes_to_words(8), 1);
        assert_eq!(WcAuthSession::bytes_to_words(9), 2);
    }
}
