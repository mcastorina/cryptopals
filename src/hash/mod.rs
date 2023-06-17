pub mod md4;
pub mod sha1;

use std::borrow::Borrow;
use std::iter;

pub trait Hash {
    type Output: Copy + AsRef<[u8]>;

    fn sum<I>(input: I) -> Self::Output
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Borrow<u8>;

    unsafe fn sum_nopad_with_state<I>(input: I, state: Self::Output) -> Self::Output
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Borrow<u8>;
}

pub trait MdPadding {
    fn md_padding(message_len: usize, size_to_encode: usize) -> Vec<u8>;
}

// Generate Merkle–Damgård padding for a message of len bytes.
pub fn md_padding_be(len: usize) -> impl Iterator<Item = u8> + Clone {
    let ml = (len * 8) as u64;
    md_padding(len, ml.to_be_bytes())
}

// Generate Merkle–Damgård padding for a message of len bytes.
pub fn md_padding_le(len: usize) -> impl Iterator<Item = u8> + Clone {
    let ml = (len * 8) as u64;
    md_padding(len, ml.to_le_bytes())
}

// Generate Merkle–Damgård padding for a message of len bytes with the provided trailing message
// size. This encoded size can differ from the first argument in cases where only a subset of the
// message is being padded.
pub fn md_padding(len: usize, encoded_size: [u8; 8]) -> impl Iterator<Item = u8> + Clone {
    // Always pad with one bit.
    // Then pad enough 0 bits to get the length 64 bits less than a multiple of 512.
    // Then always pad with the encoded message length in bits.
    iter::once(0x80)
        .chain(iter::repeat(0).take(63 - ((len + 8) % 64)))
        .chain(encoded_size.into_iter())
}

// Helper function to convert [u8; N*4] to [u32; N].
pub fn bytes_to_u32<const N: usize>(input: impl AsRef<[u8]>, f: fn([u8; 4]) -> u32) -> [u32; N] {
    let mut arr = [0; N];
    let mut iter = input.as_ref().into_iter().copied();
    let chunks = iter::from_fn(|| Some([iter.next()?, iter.next()?, iter.next()?, iter.next()?]));
    for (i, chunk) in chunks.enumerate() {
        arr[i] = f(chunk);
    }
    arr
}
