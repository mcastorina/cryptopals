struct HexDecoder<I>
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
    fn next_nibble(&mut self) -> Option<u8> {
        let c = self.upstream.next()?.into();
        // Intentionally panic if it's not a hex digit.
        Some(c.to_digit(16).expect("not a hex digit") as u8)
    }
}

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

trait HexDecoderExt: Iterator {
    fn hex_decode(self) -> HexDecoder<Self>
    where
        Self: Sized,
    {
        HexDecoder { upstream: self }
    }
}

impl<I: Iterator> HexDecoderExt for I {}

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
}
