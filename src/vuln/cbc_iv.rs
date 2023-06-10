use crate::aes::{self, *};
use crate::b64::*;
use crate::rng;

// Creates a new vulnerable system to exploit.
pub fn new() -> VulnCbcIv {
    rng::gen()
}

#[derive(Copy, Clone, Debug)]
pub struct VulnCbcIv {
    key: [u8; aes::BLOCK_SIZE],
}

impl VulnCbcIv {
    fn encrypt(&self, data: impl Iterator<Item = u8>) -> String {
        data.aes_cbc_encrypt(self.key, self.key).b64_collect()
    }

    fn decrypt(&self, cookie: &str) -> Result<String, String> {
        let decrypted: Vec<u8> = cookie
            .b64_decode()
            .try_aes_cbc_decrypt(self.key, self.key)?;
        let output =
            String::from_utf8(decrypted.clone()).map_err(|_| format!("not utf8: {decrypted:?}"))?;
        if !output.is_ascii() {
            return Err(format!(
                "unexpected bytes found during decryption: {output}"
            ));
        }
        Ok(output)
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
    pub fn is_admin(&self, cookie: impl AsRef<str>) -> Result<bool, String> {
        let cookie = self.decrypt(cookie.as_ref())?;
        Ok(cookie
            .split(';')
            .filter_map(|kv| kv.split_once('='))
            .any(|(key, val)| key == "admin" && val == "true"))
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
            .aes_cbc_encrypt(vuln.key, vuln.key)
            .take(15)
            .chain(iter::once(0xff))
            .b64_collect();
        assert!(vuln.decrypt(&invalid_encrypt).is_err());
    }
}
