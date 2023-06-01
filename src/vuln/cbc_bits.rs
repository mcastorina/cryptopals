use crate::aes::{self, *};
use crate::b64::*;
use crate::rng;

// Creates a new vulnerable system to exploit.
pub fn new() -> VulnCbcBits {
    rng::gen()
}

#[derive(Copy, Clone)]
pub struct VulnCbcBits {
    key: aes::Key128,
    iv: [u8; aes::BLOCK_SIZE],
}

impl VulnCbcBits {
    fn encrypt(&self, data: impl Iterator<Item = u8>) -> String {
        data.aes_cbc_encrypt(self.key, self.iv).b64_collect()
    }

    fn decrypt(&self, cookie: &str) -> Option<String> {
        let decrypted: Vec<u8> = cookie
            .b64_decode()
            .try_aes_cbc_decrypt(self.key, self.iv)
            .ok()?;
        Some(String::from_utf8_lossy(&decrypted).into())
    }

    // Generate a cookie with the provided user data.
    pub fn cookie_for(&self, data: impl AsRef<str>) -> Option<String> {
        let data = data.as_ref();
        if data.contains([';', '=']) {
            return None;
        }
        let prefix = "comment1=cooking%20MCs;userdata=".bytes();
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".bytes();
        Some(self.encrypt(prefix.chain(data.bytes()).chain(suffix)))
    }

    // Check if a cookie has the admin attribute set to true.
    pub fn is_admin(&self, cookie: impl AsRef<str>) -> Option<bool> {
        let cookie = self.decrypt(cookie.as_ref())?;
        Some(
            cookie
                .split(';')
                .filter_map(|kv| kv.split_once('='))
                .any(|(key, val)| key == "admin" && val == "true"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;

    #[test]
    fn test_is_admin() {
        let vuln = new();
        let cookie = vuln.encrypt("foo=bar;admin=true;bar=baz".bytes());
        assert!(vuln.is_admin(&cookie).unwrap());
    }

    #[test]
    fn test_decrypt() {
        let vuln = new();
        let invalid_encrypt: String = "foo"
            .bytes()
            .aes_cbc_encrypt(vuln.key, vuln.iv)
            .take(15)
            .chain(iter::once(0xff))
            .b64_collect();
        assert_eq!(vuln.decrypt(&invalid_encrypt), None);
    }
}
