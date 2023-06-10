use std::borrow::Borrow;
use std::iter;
use std::num::Wrapping;

// Initial hash values.
const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

// Perform the hash function on any arbitrary iterator of bytes.
fn sum<I>(input: I) -> [u8; 20]
where
    I: IntoIterator,
    <I as IntoIterator>::Item: Borrow<u8>,
{
    let mut input: Vec<_> = input.into_iter().map(|b| *b.borrow()).collect();
    // Message length in bits.
    let ml: u64 = 8 * input.len() as u64;
    // Append a single bit.
    input.push(0x80);
    // Append enough 0 bits to get the length 64 bits less than a multiple of 512.
    input.extend(iter::repeat(0).take((64 - ((input.len() + 8) % 64)) % 64));
    // Append the 64-bit length (8 bytes).
    input.extend_from_slice(&ml.to_be_bytes());
    // At this point, we have 512 bits (64 bytes).

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
        Wrapping(H0),
        Wrapping(H1),
        Wrapping(H2),
        Wrapping(H3),
        Wrapping(H4),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::*;

    #[test]
    fn test_sum() {
        assert_eq!(
            sum("abc".bytes()).into_iter().hex_collect::<String>(),
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
}
