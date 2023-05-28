use crate::aes::{self, *};
use crate::b64::*;
use crate::rng;

// Creates a new vulnerable system to exploit.
pub fn new() -> VulnEcbCookie {
    VulnEcbCookie { key: rng::gen() }
}

pub struct VulnEcbCookie {
    key: aes::Key128,
}

impl VulnEcbCookie {
    // Generate a profile for the provided email, uid, and role.
    fn profile_for(email: impl AsRef<str>, uid: u32, role: &str) -> Option<String> {
        let email = email.as_ref();
        (!email.contains(['&', '='])).then(|| format!("email={email}&uid={uid}&role={role}"))
    }

    // Helper function to base64 decode and decrypt the provided cookie.
    fn parse_cookie(&self, cookie: impl AsRef<str>) -> String {
        // This will panic if the cookie is malformed.
        // TODO: Make a safe aes::ecb_decrypt function.
        cookie
            .b64_decode()
            .aes_ecb_decrypt(self.key)
            .map(char::from)
            .collect()
    }

    // Helper function to generate a cookie by encrypting the payload with our secret key and
    // base64 encoding the output.
    fn generate_cookie(&self, payload: &str) -> String {
        payload.bytes().aes_ecb_encrypt(self.key).b64_collect()
    }

    // Generate a cookie for the provided email. None is returned if there are invalid characters
    // in the email (namely `=` and `&`).
    pub fn cookie_for(&self, email: impl AsRef<str>) -> Option<String> {
        let profile = Self::profile_for(email, 10, "user")?;
        Some(self.generate_cookie(&profile))
    }

    // Check if the provided cookie's role is admin.
    pub fn is_admin(&self, cookie: impl AsRef<str>) -> bool {
        self.parse_cookie(cookie)
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .any(|(key, val)| key == "role" && val == "admin")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookie() {
        let vuln = new();
        assert_eq!(
            vuln.parse_cookie(vuln.cookie_for("me@example.com").unwrap()),
            "email=me@example.com&uid=10&role=user"
        );
    }

    #[test]
    fn test_is_admin() {
        let vuln = new();
        let profile = VulnEcbCookie::profile_for("me@example.com", 10, "admin").unwrap();
        let cookie = vuln.generate_cookie(&profile);
        assert!(vuln.is_admin(cookie));
    }
}
