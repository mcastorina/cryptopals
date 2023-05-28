use crate::aes::{self, *};
use crate::b64::*;
use crate::rng;

// A constant plaintext that gets appended during each encryption.
pub const SUFFIX: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

// Creates a new vulnerable system to exploit.
pub fn new() -> VulnEcbSuffix {
    VulnEcbSuffix { key: rng::gen() }
}

pub struct VulnEcbSuffix {
    key: aes::Key128,
}

impl VulnEcbSuffix {
    // Generate a ciphertext with an unknown suffix and fixed key.
    pub fn gen_cipher(&self, input: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
        input.chain(SUFFIX.b64_decode()).aes_ecb_encrypt(self.key)
    }
}
