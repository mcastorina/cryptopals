use crate::aes::{self, *};
use crate::rng;

pub fn new(input: impl Iterator<Item = u8>) -> VulnAesMode {
    let (cipher, mode) = VulnAesMode::gen_cipher(input);
    VulnAesMode { cipher, mode }
}

pub struct VulnAesMode {
    pub cipher: Vec<u8>,
    mode: &'static str,
}

impl VulnAesMode {
    // Method to check our guess.
    pub fn is(&self, mode: &str) -> bool {
        self.mode == mode
    }

    // Helper function to randomly generate a ciphertext given the input.
    fn gen_cipher(input: impl Iterator<Item = u8>) -> (Vec<u8>, &'static str) {
        let prefix = rng::stream().take(rng::range(5..=10));
        let suffix = rng::stream().take(rng::range(5..=10));
        let plain = prefix.chain(input).chain(suffix);
        let key: aes::Key128 = rng::gen();
        if rng::gen() {
            (plain.aes_ecb_encrypt(key).collect(), "ECB")
        } else {
            (plain.aes_cbc_encrypt(key, rng::gen()).collect(), "CBC")
        }
    }
}
