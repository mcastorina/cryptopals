use crate::freq;
use crate::rng;
use crate::xor;
use std::iter;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn new() -> VulnMtStream {
    VulnMtStream {
        seed: rng::gen(),
        reset_token_key: rng::gen(),
    }
}

pub struct VulnMtStream {
    seed: u16,
    reset_token_key: [u8; 8],
}

impl VulnMtStream {
    pub fn gen_blob(&self, plain: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
        self.encrypt(
            iter::from_fn(rng::gen)
                .take(rng::range(1..=10))
                .chain(plain),
        )
    }

    pub fn password_reset_token(&self) -> impl Iterator<Item = u8> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.password_reset_token_at(current_time as u32)
    }

    fn password_reset_token_at(&self, time: u32) -> impl Iterator<Item = u8> {
        let stream = rng::MersenneTwister::new(time);
        xor::bytewise(self.reset_token_key, stream.into_iter::<u8>())
    }

    pub fn valid_reset_token(&self, token: impl Iterator<Item = u8>) -> bool {
        let cipher_stream: Vec<u8> = xor::bytewise(self.reset_token_key, token).collect();
        // Find the seed that outputs the given cipher stream.
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        (current_time - 5 * 60..=current_time).rev().any(|seed| {
            freq::hamming(
                rng::MersenneTwister::new(seed).into_iter::<u8>(),
                &cipher_stream,
            ) == 0
        })
    }

    pub fn check_seed(&self, other: u16) -> bool {
        self.seed == other
    }

    fn xor(&self, plain: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
        let stream = rng::MersenneTwister::new(self.seed as u32);
        xor::bytewise(plain, stream.into_iter::<u8>())
    }

    fn encrypt(&self, plain: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
        self.xor(plain)
    }

    fn decrypt(&self, plain: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
        self.xor(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt() {
        let vuln = new();

        let plain = "hello world foo bar baz";
        assert_eq!(
            vuln.decrypt(vuln.encrypt(plain.bytes()))
                .map(char::from)
                .collect::<String>(),
            plain
        );
    }

    #[test]
    fn test_password_reset_token() {
        let vuln = new();

        let token = vuln.password_reset_token();
        assert!(vuln.valid_reset_token(token));
        assert!(!vuln.valid_reset_token(iter::repeat(b'A').take(8)));

        let old_token = vuln.password_reset_token_at(1337);
        assert!(!vuln.valid_reset_token(old_token));
    }
}
