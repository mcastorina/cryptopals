use crate::hash::{self, Hash, MdPadding};
use std::borrow::Borrow;
use std::num::Wrapping as W;

const HASH_SIZE: usize = 16;
pub type Md4 = [u8; HASH_SIZE];

#[rustfmt::skip]
// Initial hash state.
const START: Md4 = [
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10,
];

impl Hash for Md4 {
    const OUTPUT_SIZE: usize = HASH_SIZE;
    const BLOCK_SIZE: usize = 64;
    type Output = Self;

    // Perform the hash function on any arbitrary iterator of bytes.
    fn sum<I>(input: I) -> Md4
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Borrow<u8>,
    {
        let mut input: Vec<_> = input.into_iter().map(|b| *b.borrow()).collect();
        // Pad our input to be a multiple of 64 bytes.
        input.extend(Self::md_padding(input.len(), input.len()));
        unsafe { Self::sum_nopad_with_state(input.iter(), START) }
    }
    // Perform the hash function on the input bytes initialized with the provided state.
    // The input is assumed to be padded to a multiple of 64 bytes. If it is not, the last N bytes will
    // be ignored.
    unsafe fn sum_nopad_with_state<I>(input: I, state: Md4) -> Md4
    where
        I: IntoIterator,
        <I as IntoIterator>::Item: Borrow<u8>,
    {
        // Prepare input and state arrays.
        let input: Vec<_> = input.into_iter().map(|b| *b.borrow()).collect();
        let state = hash::bytes_to_u32::<4>(state, u32::from_le_bytes);

        let (mut h0, mut h1, mut h2, mut h3) = (W(state[0]), W(state[1]), W(state[2]), W(state[3]));
        let (f, g, h) = (w(f), w(g), w(h));

        for chunk in input.chunks_exact(Self::BLOCK_SIZE) {
            let mut words = [W(0); 16];
            for (i, bytes) in chunk.chunks_exact(4).enumerate() {
                words[i] = W(u32::from_le_bytes(bytes.try_into().unwrap()));
            }

            let (mut a, mut b, mut c, mut d) = (h0, h1, h2, h3);
            // Round 1
            for i in [0, 4, 8, 12] {
                a = W((a + f(b, c, d) + words[i + 0]).0.rotate_left(3));
                d = W((d + f(a, b, c) + words[i + 1]).0.rotate_left(7));
                c = W((c + f(d, a, b) + words[i + 2]).0.rotate_left(11));
                b = W((b + f(c, d, a) + words[i + 3]).0.rotate_left(19));
            }
            // Round 2
            for i in [0, 1, 2, 3] {
                a = W((a + g(b, c, d) + words[i + 0] + W(0x5a827999))
                    .0
                    .rotate_left(3));
                d = W((d + g(a, b, c) + words[i + 4] + W(0x5a827999))
                    .0
                    .rotate_left(5));
                c = W((c + g(d, a, b) + words[i + 8] + W(0x5a827999))
                    .0
                    .rotate_left(9));
                b = W((b + g(c, d, a) + words[i + 12] + W(0x5a827999))
                    .0
                    .rotate_left(13));
            }
            // Round 3
            for i in [0, 2, 1, 3] {
                a = W((a + h(b, c, d) + words[i + 0] + W(0x6ed9eba1))
                    .0
                    .rotate_left(3));
                d = W((d + h(a, b, c) + words[i + 8] + W(0x6ed9eba1))
                    .0
                    .rotate_left(9));
                c = W((c + h(d, a, b) + words[i + 4] + W(0x6ed9eba1))
                    .0
                    .rotate_left(11));
                b = W((b + h(c, d, a) + words[i + 12] + W(0x6ed9eba1))
                    .0
                    .rotate_left(15));
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
        }

        // Construct the final output.
        let mut output = [0; 16];
        [h0, h1, h2, h3]
            .iter()
            .flat_map(|h| h.0.to_le_bytes())
            .enumerate()
            .for_each(|(i, byte)| {
                output[i] = byte;
            });
        output
    }
}

impl MdPadding for Md4 {
    fn md_padding(message_len: usize, size_to_encode: usize) -> Vec<u8> {
        hash::md_padding(message_len, (size_to_encode * 8).to_le_bytes()).collect()
    }
}

// Perform the hash function on any arbitrary iterator of bytes.
pub fn sum<I>(input: I) -> [u8; 16]
where
    I: IntoIterator,
    <I as IntoIterator>::Item: Borrow<u8>,
{
    Md4::sum(input)
}

// Helper function to convert non-wrapped functions into wrapped ones.
fn w(f: fn(u32, u32, u32) -> u32) -> impl Fn(W<u32>, W<u32>, W<u32>) -> W<u32> {
    move |a: W<u32>, b: W<u32>, c: W<u32>| -> W<u32> { W(f(a.0, b.0, c.0)) }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

// Trait extension to md4sum method to any iterator.
pub trait Md4HashExt: Iterator {
    fn md4sum(self) -> std::array::IntoIter<u8, 16>
    where
        Self: Sized,
        Self::Item: Borrow<u8>,
    {
        sum(self).into_iter()
    }
}

impl<I: Iterator> Md4HashExt for I {}

// Trait extension to add md4sum method to anything that can be &str.
pub trait Md4HashStrExt: AsRef<str> {
    fn md4sum(&self) -> std::array::IntoIter<u8, 16>
    where
        Self: Sized,
    {
        sum(self.as_ref().bytes()).into_iter()
    }
}

impl<S: AsRef<str>> Md4HashStrExt for S {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::*;

    #[test]
    fn test_sum() {
        let tests = vec![
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ];
        for (input, expected) in tests {
            assert_eq!(
                input.md4sum().hex_collect::<String>(),
                expected,
                "failed test for input {input:?}"
            );
        }
    }
}
