pub mod md4;
pub mod sha1;

use std::iter;

// Generate Merkle–Damgård padding for a message of len bytes.
pub fn md_padding_be(len: usize) -> impl Iterator<Item = u8> {
    let ml = (len * 8) as u64;
    md_padding(len, ml.to_be_bytes())
}

// Generate Merkle–Damgård padding for a message of len bytes.
pub fn md_padding_le(len: usize) -> impl Iterator<Item = u8> {
    let ml = (len * 8) as u64;
    md_padding(len, ml.to_le_bytes())
}

pub fn md_padding(len: usize, encoded_size: [u8; 8]) -> impl Iterator<Item = u8> {
    // Always pad with one bit.
    // Then pad enough 0 bits to get the length 64 bits less than a multiple of 512.
    // Then always pad with the encoded message length in bits.
    iter::once(0x80)
        .chain(iter::repeat(0).take(63 - ((len + 8) % 64)))
        .chain(encoded_size.into_iter())
}
