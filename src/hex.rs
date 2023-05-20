// An iterator to convert hex-encoded characters into bytes.
pub struct HexDecoder<I>
where
    I: Iterator,
{
    upstream: I,
}

impl<I> HexDecoder<I>
where
    I: Iterator,
    I::Item: Into<char>,
{
    // Get the next nibble from the upstream iterator. This function panics if it's not a hex
    // digit. If there are no more items, None is returned.
    fn next_nibble(&mut self) -> Option<u8> {
        let c = self.upstream.next()?.into();
        // Intentionally panic if it's not a hex digit.
        Some(c.to_digit(16).expect("not a hex digit") as u8)
    }
}

// Implement Iterator trait for HexDecoder.
impl<I> Iterator for HexDecoder<I>
where
    I: Iterator,
    I::Item: Into<char>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let n1 = self.next_nibble()?;
        // Intentionally panic if it's an odd length string.
        let n2 = self.next_nibble().expect("unexpected odd length string");
        Some(n1 << 4 | n2)
    }
}

// Trait extension to add hex_decode method to any iterator.
pub trait HexDecoderExt: Iterator {
    fn hex_decode(self) -> HexDecoder<Self>
    where
        Self: Sized,
    {
        HexDecoder { upstream: self }
    }
}

impl<I: Iterator> HexDecoderExt for I {}

pub struct HexEncoder<I>
where
    I: Iterator,
{
    upstream: I,
    nibble: Option<u8>,
}

// An iterator to convert bytes into hex-encoded characters.
impl<I> HexEncoder<I>
where
    I: Iterator,
    I::Item: Into<u8>,
{
    const LUT: [u8; 16] = *b"0123456789abcdef";
}

// Implement Iterator trait for HexEncoder.
impl<I> Iterator for HexEncoder<I>
where
    I: Iterator,
    I::Item: Into<u8>,
{
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = match self.nibble {
            Some(n) => {
                // Clear and emit the stored nibble.
                self.nibble = None;
                n as usize
            }
            None => {
                // Read a byte and store the lower half for the next read.
                let n = self.upstream.next()?.into();
                self.nibble = Some(n & 0b1111);
                (n >> 4) as usize
            }
        };
        Some(Self::LUT[idx] as char)
    }
}

// Trait extension to add hex_encode method to any iterator.
pub trait HexEncoderExt: Iterator {
    fn hex_encode(self) -> HexEncoder<Self>
    where
        Self: Sized,
    {
        HexEncoder {
            upstream: self,
            nibble: None,
        }
    }
}

impl<I: Iterator> HexEncoderExt for I {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes() {
        let result: Vec<_> = "000102030405".bytes().hex_decode().collect();
        assert_eq!(result, &[0, 1, 2, 3, 4, 5]);
        let result: Vec<_> = "000102030405".chars().hex_decode().collect();
        assert_eq!(result, &[0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn bytes_to_hex() {
        let result: String = [0u8, 1, 2, 3, 4, 5].into_iter().hex_encode().collect();
        assert_eq!(result, "000102030405");
    }
}
