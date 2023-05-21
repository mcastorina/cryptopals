use std::borrow::Borrow;

// An iterator to convert bytes into base64 encoded chars.
pub struct B64Encoder<I>
where
    I: Iterator,
{
    upstream: I,
    buffer: [Option<u8>; 3],
    idx: usize,
}

impl<I> B64Encoder<I>
where
    I: Iterator,
    I::Item: Borrow<u8>,
{
    const LUT: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const PADDING: u8 = b'=';

    // Find the next index into the LUT. If there are no more bytes from the upstream iterator,
    // None is returned.
    fn next_index(&mut self) -> Option<usize> {
        if self.idx == 0 {
            self.refill_buffer();
        }
        if self.buffer.iter().all(Option::is_none) {
            return None;
        }
        // 0      1      2      3
        // 000000 001111 111122 222222
        // Given the three bytes, get the 6 bits that represent the index.
        let result = match self.idx {
            0 => self.buffer[0]? >> 2,
            1 => (self.buffer[0]? << 4) | (self.buffer[1].unwrap_or(0) >> 4),
            2 => (self.buffer[1]? << 2) | (self.buffer[2].unwrap_or(0) >> 6),
            3 => self.buffer[2]?,
            _ => unreachable!(),
        } & 0b00111111;
        self.idx = (self.idx + 1) % 4;
        Some(result as usize)
    }

    // Read three bytes from the upstream iterator and store in the internal buffer.
    fn refill_buffer(&mut self) {
        for i in 0..self.buffer.len() {
            self.buffer[i] = self.upstream.next().map(|b| *b.borrow());
        }
    }
}

// Implement Iterator trait for B64Encoder.
impl<I> Iterator for B64Encoder<I>
where
    I: Iterator,
    I::Item: Borrow<u8>,
{
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.next_index(), self.idx) {
            (Some(idx), _) => Some(Self::LUT[idx] as char),
            (None, 0) => None,
            (None, _) => {
                self.idx = (self.idx + 1) % 4;
                Some(Self::PADDING as char)
            }
        }
    }
}

// Trait extension to add b64_encode method to any iterator.
pub trait B64EncoderExt: Iterator {
    fn b64_encode(self) -> B64Encoder<Self>
    where
        Self: Sized,
    {
        B64Encoder {
            upstream: self,
            buffer: [None, None, None],
            idx: 0,
        }
    }
}

impl<I: Iterator> B64EncoderExt for I {}

// Trait extension to add b64_collect method to any iterator.
pub trait B64CollecterExt: Iterator {
    fn b64_collect<B>(self) -> B
    where
        Self: Sized,
        Self::Item: Borrow<u8>,
        B: std::iter::FromIterator<char>,
    {
        self.b64_encode().collect()
    }
}

impl<I: Iterator> B64CollecterExt for I {}

// An iterator to convert bytes into base64 encoded chars.
pub struct B64Decoder<I>
where
    I: Iterator,
{
    upstream: I,
    buffer: [Option<u8>; 4],
    idx: usize,
}

impl<I> B64Decoder<I>
where
    I: Iterator,
    I::Item: Borrow<char>,
{
    const LUT: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const PADDING: u8 = b'=';
    const CR: u8 = b'\n';
    const LF: u8 = b'\r';

    // Find the next index into the LUT. If there are no more bytes from the upstream iterator,
    // None is returned.
    fn next_byte(&mut self) -> Option<u8> {
        if self.idx == 0 {
            self.refill_buffer();
        }
        if self.buffer.iter().all(Option::is_none) {
            return None;
        }
        // 0      1      2      3
        // 000000 001111 111122 222222
        // Given the four characters, get the 8 bits of the data.
        let result = match self.idx {
            0 => (self.buffer[0]? << 2) | (self.buffer[1]? >> 4),
            1 => (self.buffer[1]? << 4) | (self.buffer[2]? >> 2),
            2 => (self.buffer[2]? << 6) | self.buffer[3]?,
            _ => unreachable!(),
        };
        self.idx = (self.idx + 1) % 3;
        Some(result)
    }

    // Read three bytes from the upstream iterator and store in the internal buffer.
    fn refill_buffer(&mut self) {
        for i in 0..self.buffer.len() {
            self.buffer[i] = self
                .next_non_crlf_char()
                .map(|b| b as u8)
                .filter(|&b| b != Self::PADDING)
                .map(|b| {
                    Self::LUT
                        .iter()
                        .position(|&i| i == b)
                        // Intentionally panic if it's not a base64 character.
                        .expect("invalid character") as u8
                });
        }
    }

    // Read the next non-crlf character from upstream.
    fn next_non_crlf_char(&mut self) -> Option<char> {
        loop {
            let c = *self.upstream.next()?.borrow();
            if c == Self::CR as char || c == Self::LF as char {
                continue;
            }
            return Some(c);
        }
    }
}

// Implement Iterator trait for B64Decoder.
impl<I> Iterator for B64Decoder<I>
where
    I: Iterator,
    I::Item: Borrow<char>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_byte()
    }
}

// Trait extension to add b64_decode method to any iterator.
pub trait B64DecoderExt: Iterator {
    fn b64_decode(self) -> B64Decoder<Self>
    where
        Self: Sized,
    {
        B64Decoder {
            upstream: self,
            buffer: [None, None, None, None],
            idx: 0,
        }
    }
}

impl<I: Iterator> B64DecoderExt for I {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_base64() {
        let result: String = "a".bytes().b64_encode().collect();
        assert_eq!(result, "YQ==");
        let result: String = "ab".bytes().b64_encode().collect();
        assert_eq!(result, "YWI=");
        let result: String = "abc".bytes().b64_encode().collect();
        assert_eq!(result, "YWJj");
    }

    #[test]
    fn base64_to_bytes() {
        let result: String = "YQ==".chars().b64_decode().map(char::from).collect();
        assert_eq!(result, "a");
        let result: String = "YWI=".chars().b64_decode().map(char::from).collect();
        assert_eq!(result, "ab");
        let result: String = "YWJj".chars().b64_decode().map(char::from).collect();
        assert_eq!(result, "abc");
    }

    #[test]
    fn base64_encode_decode() {
        let data = &[0u8, 1, 2, 0xff, 0xfe, 13, 37];
        for i in 0..data.len() {
            let data = &data[..i];
            assert_eq!(
                data.iter().b64_encode().b64_decode().collect::<Vec<u8>>(),
                data,
            );
        }
    }
}
