use std::borrow::Borrow;
use std::num::Wrapping as W;

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
    input.extend(super::md_padding_be(input.len()));
    unsafe { sum_nopad_with_state(input, [H0, H1, H2, H3, H4]) }
}

// Perform the hash function on the input bytes initialized with the provided state.
// The input is assumed to be padded to a multiple of 64 bytes. If it is not, the last N bytes will
// be ignored.
pub unsafe fn sum_nopad_with_state(input: Vec<u8>, state: [u32; 5]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
        W(state[0]),
        W(state[1]),
        W(state[2]),
        W(state[3]),
        W(state[4]),
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
            let temp = W(a.rotate_left(5)) + W(f) + W(e) + W(k) + W(words[i]);
            (e, d, c, b, a) = (d, c, b.rotate_left(30), a, temp.0);
        }
        h0 += W(a);
        h1 += W(b);
        h2 += W(c);
        h3 += W(d);
        h4 += W(e);
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

// Trait extension to sha1sum method to any iterator.
pub trait Sha1HashExt: Iterator {
    fn sha1sum(self) -> std::array::IntoIter<u8, 20>
    where
        Self: Sized,
        Self::Item: Borrow<u8>,
    {
        sum(self).into_iter()
    }
}

impl<I: Iterator> Sha1HashExt for I {}

// Trait extension to add sha1sum method to anything that can be &str.
pub trait Sha1HashStrExt: AsRef<str> {
    fn sha1sum(&self) -> std::array::IntoIter<u8, 20>
    where
        Self: Sized,
    {
        sum(self.as_ref().bytes()).into_iter()
    }
}

impl<S: AsRef<str>> Sha1HashStrExt for S {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::*;
    use std::iter;

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
