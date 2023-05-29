use crate::aes::{self, *};
use crate::b64::*;
use crate::rng;

// A constant plaintext that gets appended during each encryption.
pub const SUFFIX: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

// Creates a new vulnerable system to exploit.
pub fn new() -> VulnEcbPrefix {
    VulnEcbPrefix {
        key: rng::gen(),
        prefix: rng::gen(),
        count: rng::range(1..16),
    }
}

pub struct VulnEcbPrefix {
    key: aes::Key128,
    prefix: [u8; 16],
    count: usize,
}

impl VulnEcbPrefix {
    // Generate a ciphertext with an unknown prefix and suffix using a fixed key.
    pub fn gen_cipher<'a>(
        &'a self,
        input: impl Iterator<Item = u8> + 'a,
    ) -> impl Iterator<Item = u8> + '_ {
        let prefix = self.prefix[..self.count].iter().copied();
        prefix
            .chain(input)
            .chain(SUFFIX.b64_decode())
            .aes_ecb_encrypt(self.key)
    }
}
