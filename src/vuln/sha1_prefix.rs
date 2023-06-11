use crate::b64::*;
use crate::hex::*;
use crate::rng;
use crate::hash::sha1;
use std::borrow::Borrow;

// Creates a new vulnerable system to exploit.
pub fn new() -> VulnSha1Prefix {
    VulnSha1Prefix {
        key: rng::gen(),
        prefix_size: rng::range(10..=40),
    }
}

pub struct VulnSha1Prefix {
    key: [u8; 64],
    prefix_size: usize,
}

impl VulnSha1Prefix {
    fn mac<I>(&self, msg: I) -> impl Iterator<Item = u8>
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Borrow<u8>,
    {
        let key = self.key.into_iter().take(self.prefix_size);
        let msg = msg.into_iter().map(|b| *b.borrow());
        sha1::sum(key.chain(msg)).into_iter()
    }

    // Generate a cookie with the provided user data.
    pub fn cookie_for(&self, data: impl AsRef<str>) -> Option<(String, String)> {
        let data = data.as_ref();
        if data.contains([';', '=']) {
            return None;
        }
        // Build the message.
        let prefix = "comment1=cooking%20MCs;userdata=";
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        let msg = format!("{prefix}{data}{suffix}");
        // Build the message authentication code.
        let mac = self.mac(msg.bytes()).hex_collect();
        Some((msg.bytes().b64_collect(), mac))
    }

    // Check if a cookie has the admin attribute set to true.
    pub fn is_admin(
        &self,
        cookie: impl AsRef<str>,
        provided_mac: impl AsRef<str>,
    ) -> Result<bool, String> {
        let cookie: Vec<_> = cookie.as_ref().b64_decode().collect();
        let calculated_mac = self.mac(cookie.iter()).hex_collect::<String>();
        if calculated_mac != provided_mac.as_ref() {
            return Err(String::from("invalid message"));
        }
        Ok(String::from_utf8_lossy(&cookie)
            .split(';')
            .filter_map(|kv| kv.split_once('='))
            .any(|(key, val)| key == "admin" && val == "true"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
