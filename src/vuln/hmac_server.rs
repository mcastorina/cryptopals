use crate::hash::Sha1;
use crate::hex::*;
use crate::mac::hmac;
use crate::rng;
use std::thread;
use std::time::Duration;

#[derive(Copy, Clone)]
pub struct VulnHmacServer {
    key: [u8; 32],
}

pub fn new() -> VulnHmacServer {
    VulnHmacServer { key: rng::gen() }
}

impl VulnHmacServer {
    // Verify the provided file contents have a valid HMAC.
    pub fn verify(&self, file: impl AsRef<[u8]>, hmac: impl AsRef<str>) -> bool {
        let calculated = self.hmac(file).into_iter().hex_collect::<String>();
        let provided = hmac.as_ref();
        Self::insecure_compare(provided.as_bytes(), calculated.as_bytes())
    }

    fn hmac(&self, input: impl AsRef<[u8]>) -> Sha1 {
        hmac::new::<Sha1>(self.key, input)
    }

    // Byte at a time comparison with a time delay.
    fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
        for (l, r) in a.iter().zip(b.iter()) {
            if l != r {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
        a.len() == b.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify() {
        let vuln = new();
        let h = vuln.hmac("hello");
        assert_eq!(
            vuln.verify("hello", h.into_iter().hex_collect::<String>()),
            true
        );
    }
}
