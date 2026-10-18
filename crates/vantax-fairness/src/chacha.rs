//! The ChaCha20 block function (RFC 8439, section 2.3).
//!
//! Written out here, rather than pulled from a dependency, so the whole
//! outcome derivation is in one readable place and anyone can check it
//! against the RFC's test vectors (see the tests below).

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One 64-byte ChaCha20 block for `key`, block `counter` and 96-bit `nonce`.
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CONSTANTS);
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&working[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

/// A ChaCha20 keystream read as little-endian `u32` words.
#[derive(Clone)]
pub struct KeyStream {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    buf: [u8; 64],
    pos: usize,
}

impl KeyStream {
    /// A keystream starting at block `counter`.
    pub fn new(key: [u8; 32], nonce: [u8; 12], counter: u32) -> Self {
        Self {
            key,
            nonce,
            counter,
            buf: [0; 64],
            pos: 64,
        }
    }

    /// The next 4 keystream bytes as a little-endian `u32`.
    pub fn next_u32(&mut self) -> u32 {
        if self.pos == 64 {
            self.buf = block(&self.key, self.counter, &self.nonce);
            self.counter = self.counter.wrapping_add(1);
            self.pos = 0;
        }
        let v = u32::from_le_bytes(
            self.buf[self.pos..self.pos + 4]
                .try_into()
                .expect("4 bytes"),
        );
        self.pos += 4;
        v
    }
}

impl Drop for KeyStream {
    fn drop(&mut self) {
        // The key is derived from the server seed; do not leave it lying around.
        zeroize::Zeroize::zeroize(&mut self.key);
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    /// RFC 8439, section 2.3.2.
    #[test]
    fn rfc8439_block_function() {
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let out = block(&rfc_key(), 1, &nonce);
        assert_eq!(
            hex::encode(out),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    /// RFC 8439, section 2.4.2: the keystream XORed with the sample plaintext.
    #[test]
    fn rfc8439_encryption() {
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ks = KeyStream::new(rfc_key(), nonce, 1);
        let mut out = Vec::new();
        for chunk in plaintext.chunks(4) {
            let w = ks.next_u32().to_le_bytes();
            for (p, k) in chunk.iter().zip(w) {
                out.push(p ^ k);
            }
        }
        assert_eq!(
            hex::encode(&out),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d"
        );
    }
}
