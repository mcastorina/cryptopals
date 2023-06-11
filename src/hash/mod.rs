pub mod md4;
pub mod sha1;

use std::iter;

// Generate Merkle–Damgård padding for a message of len bytes.
pub fn md_padding(len: usize) -> impl Iterator<Item = u8> {
    // Always pad with one bit.
    // Then pad enough 0 bits to get the length 64 bits less than a multiple of 512.
    // Then always pad with the message length.
    iter::once(0x80)
        .chain(iter::repeat(0).take(63 - ((len + 8) % 64)))
        .chain((8 * len as u64).to_be_bytes().into_iter())
}
