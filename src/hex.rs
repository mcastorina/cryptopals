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
    fn next_nibble<F>(mut source: F) -> Option<u8>
    where
        F: FnMut() -> Option<I::Item>,
    {
        let c = source()?.into();
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
        let mut next = || self.upstream.next();
        let n1 = Self::next_nibble(&mut next)?;
        // Intentionally panic if it's an odd length string.
        let n2 = Self::next_nibble(&mut next).expect("unexpected odd length string");
        Some(n1 << 4 | n2)
    }
}

// Implement Iterator trait for HexDecoder.
impl<I> DoubleEndedIterator for HexDecoder<I>
where
    I: DoubleEndedIterator,
    I::Item: Into<char>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        let mut next_back = || self.upstream.next_back();
        let n1 = Self::next_nibble(&mut next_back)?;
        // Zero pad if we only find one nibble.
        let n2 = Self::next_nibble(&mut next_back).unwrap_or(0);
        Some(n2 << 4 | n1)
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

// Trait extension to add hex_decode method to anything that can be &str.
pub trait HexDecoderStrExt<I> {
    fn hex_decode(&self) -> HexDecoder<std::str::Bytes<'_>>
    where
        I: Iterator<Item = u8>;
}

impl<S: AsRef<str>> HexDecoderStrExt<std::str::Bytes<'_>> for S {
    fn hex_decode(&self) -> HexDecoder<std::str::Bytes<'_>> {
        HexDecoder {
            upstream: self.as_ref().bytes(),
        }
    }
}

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

// Trait extension to add hex_collect method to any iterator.
pub trait HexCollecterExt: Iterator {
    fn hex_collect<B>(self) -> B
    where
        Self: Sized,
        Self::Item: Into<u8>,
        B: std::iter::FromIterator<char>,
    {
        self.hex_encode().collect()
    }
}

impl<I: Iterator> HexCollecterExt for I {}

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
