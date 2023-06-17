use crate::hash;
use crate::hash::{Hash, MdPadding};

#[derive(Debug, Clone)]
pub struct Mac<H: Hash + MdPadding> {
    message: Vec<u8>,
    hash: H::Output,
}

impl<H: Hash + MdPadding> Mac<H> {
    pub fn from_message(message: impl AsRef<str>) -> Self {
        let message = message.as_ref().as_bytes().to_vec();
        Self {
            hash: H::sum(&message),
            message,
        }
    }

    pub fn from_hash(hash: H::Output) -> Self {
        Self {
            hash,
            message: vec![],
        }
    }

    pub fn extend(&self, add: impl AsRef<str>) -> Self {
        self.extend_with(add, self.message.len())
    }

    // given mac, original message length, new message
    // extend mac by hashing the new message padded to 64 bytes with a length of (orginial message length + new message length)
    // extend message with original message padding and new message
    pub fn extend_with(&self, add: impl AsRef<str>, original_length: usize) -> Self {
        let add = add.as_ref();

        // Calculate the padding for the original message length.
        let original_padding = H::md_padding(original_length, original_length);

        // Calculate the total message length, including the padding length as that's now part of
        // the full message.
        let total_length = original_length + original_padding.iter().count() + add.len();

        // Extend our message with the original padding and the new message.
        let new_message = {
            let mut message = self.message.clone();
            message.extend(original_padding.iter().copied().chain(add.bytes()));
            message
        };

        // Calculate the padding for the additional message, but encode the full message length.
        let add_padding = H::md_padding(add.len(), total_length);
        // The new hash is a continuation of the original hash with the new message and padding.
        let hash = unsafe { H::sum_nopad_with_state(add.bytes().chain(add_padding), self.hash) };
        Self {
            message: new_message,
            hash,
        }
    }
}

impl<H: Hash + MdPadding> From<(&str, H::Output)> for Mac<H> {
    fn from((message, hash): (&str, H::Output)) -> Self {
        let message = message.as_bytes().to_vec();
        Self { message, hash }
    }
}

impl<H: Hash + MdPadding> From<(String, H::Output)> for Mac<H> {
    fn from((message, hash): (String, H::Output)) -> Self {
        let message = message.as_bytes().to_vec();
        Self { message, hash }
    }
}

impl<H: Hash + MdPadding> From<(Vec<u8>, H::Output)> for Mac<H> {
    fn from((message, hash): (Vec<u8>, H::Output)) -> Self {
        Self { message, hash }
    }
}

impl<H: Hash + MdPadding> From<Mac<H>> for (Vec<u8>, H::Output) {
    fn from(mac: Mac<H>) -> Self {
        (mac.message, mac.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha1::{self, Sha1};

    #[test]
    fn test_extend() {
        let mut mac: Mac<Sha1> = Mac::from_message("abc");
        let new_mac = mac.extend("test");
        assert_eq!(sha1::sum(new_mac.message), new_mac.hash);
    }
}
