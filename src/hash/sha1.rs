use std::borrow::Borrow;
use std::iter;
use std::mem;
use std::num::Wrapping;

// Initial hash values.
const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

// Perform the hash function on any arbitrary iterator of bytes.
pub fn sum<I>(input: I) -> [u8; 20]
where
    I: IntoIterator,
    <I as IntoIterator>::Item: Borrow<u8>,
{
    let mut input: Vec<_> = input.into_iter().map(|b| *b.borrow()).collect();
    // Pad our input to be a multiple of 64 bytes.
    input.extend(md_padding(input.len()));
    unsafe { sum_nopad_with_state(input, [H0, H1, H2, H3, H4]) }
}

// Perform the hash function on the input bytes initialized with the provided state.
// The input is assumed to be padded to a multiple of 64 bytes. If it is not, the last N bytes will
// be ignored.
pub unsafe fn sum_nopad_with_state(input: Vec<u8>, state: [u32; 5]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
        Wrapping(state[0]),
        Wrapping(state[1]),
        Wrapping(state[2]),
        Wrapping(state[3]),
        Wrapping(state[4]),
    );
    // Operate on chunks of 512 bits (64 bytes).
    for chunk in input.chunks_exact(64) {
        let mut words = [0; 80];
        for (i, bytes) in chunk.chunks_exact(4).enumerate() {
            words[i] = u32::from_be_bytes(bytes.try_into().unwrap());
        }

        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }
        // Initialize hash value for this chunk:
        let (mut a, mut b, mut c, mut d, mut e) = (h0.0, h1.0, h2.0, h3.0, h4.0);

        for i in 0..80 {
            let (f, k): (u32, u32) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };
            let temp = Wrapping(a.rotate_left(5))
                + Wrapping(f)
                + Wrapping(e)
                + Wrapping(k)
                + Wrapping(words[i]);
            (e, d, c, b, a) = (d, c, b.rotate_left(30), a, temp.0);
        }
        h0 += Wrapping(a);
        h1 += Wrapping(b);
        h2 += Wrapping(c);
        h3 += Wrapping(d);
        h4 += Wrapping(e);
    }

    // Construct the final output.
    let mut output = [0; 20];
    [h0, h1, h2, h3, h4]
        .iter()
        .flat_map(|h| h.0.to_be_bytes())
        .enumerate()
        .for_each(|(i, byte)| {
            output[i] = byte;
        });
    output
}

// Generate Merkle–Damgård padding for a message of len bytes.
pub fn md_padding(len: usize) -> impl Iterator<Item = u8> {
    // Always pad with one bit.
    // Then pad enough 0 bits to get the length 64 bits less than a multiple of 512.
    // Then always pad with the message length.
    iter::once(0x80)
        .chain(iter::repeat(0).take(63 - ((len + 8) % 64)))
        .chain((8 * len as u64).to_be_bytes().into_iter())
}

pub struct Sha1Hash<I: Iterator> {
    upstream: Option<I>,
    hash: Option<[u8; 20]>,
    index: usize,
}

impl<I: Iterator> Iterator for Sha1Hash<I>
where
    I::Item: Borrow<u8>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        // If we don't have the hash yet, consume the iterator and generate the hash.
        if self.hash.is_none() {
            let upstream = mem::replace(&mut self.upstream, None)?;
            self.hash = Some(sum(upstream));
        }
        if self.index >= 20 {
            return None;
        }
        // Hash will always be Some, but safely unwrap anyway.
        let ret = self.hash?[self.index];
        self.index += 1;
        Some(ret)
    }
}

pub trait Sha1HashExt: Iterator {
    fn sha1sum(self) -> Sha1Hash<Self>
    where
        Self: Sized,
    {
        Sha1Hash {
            upstream: Some(self),
            hash: None,
            index: 0,
        }
    }
}

impl<I: Iterator> Sha1HashExt for I {}

// Trait extension to add sha1sum method to anything that can be &str.
pub trait Sha1HashStrExt<I> {
    fn sha1sum(&self) -> Sha1Hash<std::str::Bytes<'_>>
    where
        I: Iterator<Item = u8>;
}

impl<S: AsRef<str>> Sha1HashStrExt<std::str::Bytes<'_>> for S {
    fn sha1sum(&self) -> Sha1Hash<std::str::Bytes<'_>> {
        Sha1Hash {
            upstream: Some(self.as_ref().bytes()),
            hash: None,
            index: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::*;

    #[test]
    fn test_sum() {
        assert_eq!(
            sum(b"").into_iter().hex_collect::<String>(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        );
        assert_eq!(
            sum(b"abc").into_iter().hex_collect::<String>(),
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        );
        assert_eq!(
            sum(iter::repeat(b'A').take(1024))
                .into_iter()
                .hex_collect::<String>(),
            "746c3f4d286c531e065e8af76e0ac0868831c6b4",
        );
        assert_eq!(
            sum(iter::repeat(b'A').take(55))
                .into_iter()
                .hex_collect::<String>(),
            "5021b3d42aa093bffc34eedd7a1455f3624bc552",
        );
        assert_eq!(
            sum(iter::repeat(b'A').take(119))
                .into_iter()
                .hex_collect::<String>(),
            "293e3964d2b4d4ba9d21991b8388283b4f09b935",
        );
    }

    #[test]
    fn test_extensions() {
        assert_eq!(
            "abc".sha1sum().hex_collect::<String>(),
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        );
    }
}
