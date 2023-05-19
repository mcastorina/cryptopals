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
    I::Item: Into<u8>,
{
    const LUT: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const PADDING: u8 = b'=';

    fn next_index(&mut self) -> Option<usize> {
        if self.idx == 0 {
            self.refill_buffer();
        }
        if self.buffer.iter().all(Option::is_none) {
            return None;
        }
        // 0      1      2      3
        // 000000 001111 111122 222222
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

    fn refill_buffer(&mut self) {
        for i in 0..self.buffer.len() {
            self.buffer[i] = self.upstream.next().map(Into::into);
        }
    }
}

impl<I> Iterator for B64Encoder<I>
where
    I: Iterator,
    I::Item: Into<u8>,
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
}