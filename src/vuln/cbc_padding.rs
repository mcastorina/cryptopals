use crate::aes::{self, *};
use crate::b64::*;
use crate::rng;
use std::borrow::Borrow;

const CIPHERS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

// Creates a new vulnerable system to exploit.
pub fn new() -> VulnCbcPadding {
    VulnCbcPadding {
        key: rng::gen(),
        iv: rng::gen(),
        // plain: CIPHERS[rng::range(0..10)],
        plain: CIPHERS[rng::range(0..10)].b64_decode().collect(),
    }
}

pub struct VulnCbcPadding {
    key: aes::Key128,
    iv: [u8; aes::BLOCK_SIZE],
    pub plain: Vec<u8>,
}

impl VulnCbcPadding {
    pub fn cipher(&self) -> (Vec<u8>, [u8; aes::BLOCK_SIZE]) {
        let cipher = self
            .plain
            .iter()
            .aes_cbc_encrypt(self.key, self.iv)
            .collect();
        (cipher, self.iv)
    }

    pub fn valid_padding<I>(&self, cipher: I) -> bool
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Borrow<u8>,
    {
        cipher
            .into_iter()
            .try_aes_cbc_decrypt::<Vec<_>>(self.key, self.iv)
            .is_ok()
    }

    pub fn solve(&self, plain: &Vec<u8>) -> bool {
        &self.plain == plain
    }
}

#[cfg(test)]
mod tests {}
