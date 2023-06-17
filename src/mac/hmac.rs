use crate::hash::Hash;
use crate::xor::*;
use std::iter;

// Compute the HMAC using the provided Hash algorithm.
pub fn new<H: Hash>(key: impl AsRef<[u8]>, msg: impl AsRef<[u8]>) -> H::Output {
    let msg = msg.as_ref().iter().copied();

    // If the key is longer than the block size, hash it.
    let mut key = key.as_ref().to_vec();
    if key.len() > H::BLOCK_SIZE {
        key = H::sum(key.iter()).as_ref().to_vec();
    }
    // Pad the key with trailing 0s for a full block size.
    let key = key
        .into_iter()
        .chain(iter::repeat(0))
        .take(H::BLOCK_SIZE)
        .collect::<Vec<_>>();

    let opad = key.iter().xor_repeat(0x5c);
    let ipad = key.iter().xor_repeat(0x36);

    let inner_hash = H::sum(ipad.chain(msg)).as_ref().to_owned();
    H::sum(opad.chain(inner_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha1::{self, Sha1};
    use crate::hex::*;

    #[test]
    fn test_hmac() {
        let hmac = new::<Sha1>("key", "The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hmac.into_iter().hex_collect::<String>(),
            "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        );
    }
}
