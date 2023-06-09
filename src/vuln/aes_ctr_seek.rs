use crate::aes::{self, *};
use crate::b64::*;
use crate::rng;
use crate::xor::*;
use std::borrow::Borrow;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn new() -> VulnAesCtrSeek {
    let (key, nonce) = rng::gen();
    VulnAesCtrSeek {
        key,
        nonce,
        cipher: include_str!("../data/set25.txt")
            .b64_decode()
            .aes_ecb_decrypt(*b"YELLOW SUBMARINE")
            .aes_ctr(key, nonce)
            .collect(),
    }
}

pub struct VulnAesCtrSeek {
    key: aes::Key128,
    nonce: u64,
    cipher: Vec<u8>,
}

impl VulnAesCtrSeek {
    pub fn read(&self) -> &Vec<u8> {
        &self.cipher
    }
    pub fn edit<I>(&mut self, offset: usize, new_plaintext: I) -> Result<usize, &str>
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Borrow<u8>,
    {
        let new_cipher = aes::ctr(self.key, self.nonce)
            .skip(offset)
            .xor_bytewise(new_plaintext)
            .collect::<Vec<_>>();
        // Extend the vector if the edit goes past the end.
        let size = new_cipher.len();
        if offset + size > self.cipher.len() {
            self.cipher.resize_with(offset + size, Default::default);
        }
        // Splice the vector, ignoring the returned removed elements.
        let _ = self.cipher.splice(offset..offset + size, new_cipher);
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit() {
        let mut vuln = new();
        let _ = vuln.edit(0, b"Hello world!").unwrap();
        assert_eq!(
            vuln.cipher
                .iter()
                .aes_ctr(vuln.key, vuln.nonce)
                .take(12)
                .map(char::from)
                .collect::<String>(),
            "Hello world!",
        );
    }
}
