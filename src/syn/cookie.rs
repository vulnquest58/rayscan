use std::hash::Hasher;

use rand::RngCore;
use siphasher::sip::SipHasher13;

/// 128-bit key for SipHash-based SYN cookies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CookieKey([u8; 16]);

impl CookieKey {
    /// Generate a new cryptographically random cookie key.
    pub fn random() -> Self {
        let mut key = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    /// Construct a cookie key from explicit bytes (useful for deterministic tests).
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Encode target and source metadata into a 32-bit initial sequence number (ISN).
    ///
    /// Computes SipHash-1-3 over `(dst_ip, dst_port, src_port)` and folds the
    /// resulting 64-bit digest into a 32-bit sequence number.
    pub fn encode(&self, dst_ip: u32, dst_port: u16, src_port: u16) -> u32 {
        let mut hasher = SipHasher13::new_with_key(&self.0);
        hasher.write_u32(dst_ip);
        hasher.write_u16(dst_port);
        hasher.write_u16(src_port);
        let hash = hasher.finish();
        (hash as u32) ^ ((hash >> 32) as u32)
    }

    /// Validate whether an ACK number corresponds to our sent SYN packet.
    ///
    /// In a standard TCP handshake, the SYN-ACK acknowledges `ISN + 1`.
    /// Subtracting 1 (with wrapping) must equal our encoded ISN.
    pub fn validate(&self, dst_ip: u32, dst_port: u16, src_port: u16, ack: u32) -> bool {
        ack.wrapping_sub(1) == self.encode(dst_ip, dst_port, src_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_encode_is_deterministic() {
        let key = CookieKey::from_bytes([1; 16]);
        let seq1 = key.encode(0x7f000001, 80, 61000);
        let seq2 = key.encode(0x7f000001, 80, 61000);
        assert_eq!(seq1, seq2);
    }

    #[test]
    fn cookie_validation_succeeds_on_ack_plus_one() {
        let key = CookieKey::random();
        let dst_ip = 0x0a000001;
        let dst_port = 443;
        let src_port = 61234;
        let seq = key.encode(dst_ip, dst_port, src_port);
        let ack = seq.wrapping_add(1);

        assert!(key.validate(dst_ip, dst_port, src_port, ack));
        assert!(!key.validate(dst_ip, dst_port, src_port, ack.wrapping_add(1)));
        assert!(!key.validate(dst_ip, dst_port, src_port, seq));
        assert!(!key.validate(dst_ip, dst_port + 1, src_port, ack));
        assert!(!key.validate(dst_ip, dst_port, src_port + 1, ack));
        assert!(!key.validate(dst_ip + 1, dst_port, src_port, ack));
    }
}
