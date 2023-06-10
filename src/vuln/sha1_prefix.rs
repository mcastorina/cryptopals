use crate::aes::{self, *};
use crate::b64::*;
use crate::rng;
use crate::sha1;

// Creates a new vulnerable system to exploit.
pub fn new() -> VulnSha1Prefix {
    VulnSha1Prefix { key: rng::gen() }
}

pub struct VulnSha1Prefix {
    key: [u8; 32],
}

impl VulnSha1Prefix {
    pub fn mac(&self, msg: impl AsRef<str>) -> impl Iterator<Item = u8> {
        let key = self.key.into_iter();
        let msg = msg.as_ref().bytes();
        sha1::sum(key.chain(msg)).into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
