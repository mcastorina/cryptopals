use std::borrow::Borrow;
use std::iter::{self, Cycle, Repeat};

// Performs a byte-wise xor of two u8 iterators.
pub fn bytewise<A, B>(a: A, b: B) -> impl Iterator<Item = u8>
where
    A: IntoIterator,
    <A as IntoIterator>::Item: Borrow<u8>,
    B: IntoIterator,
    <B as IntoIterator>::Item: Borrow<u8>,
{
    a.into_iter()
        .zip(b.into_iter())
        .map(|(a, b)| a.borrow() ^ b.borrow())
}

pub fn fixed<const SIZE: usize>(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> [u8; SIZE] {
    let mut output = [0; SIZE];
    for (i, v) in bytewise(a.as_ref(), b.as_ref()).enumerate() {
        output[i] = v;
    }
    output
}

// An iterator to emit xor bytes of two iterators.
pub struct XorCycler<I, J>
where
    I: Iterator,
    J: Iterator,
{
    upstream: I,
    key: J,
}

// Implement Iterator trait for XorCycler.
impl<I, J> Iterator for XorCycler<I, J>
where
    I: Iterator,
    I::Item: Borrow<u8>,
    J: Iterator,
    J::Item: Borrow<u8>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.upstream.next()?.borrow() ^ self.key.next()?.borrow())
    }
}

// Trait extension to add xor_cycle method to any iterator.
pub trait XorCyclerExt: Iterator {
    fn xor_cycle<I>(self, key: I) -> XorCycler<Self, Cycle<<I as IntoIterator>::IntoIter>>
    where
        Self: Sized,
        I: IntoIterator,
        <I as IntoIterator>::IntoIter: Clone,
        <I as IntoIterator>::Item: Borrow<u8>,
    {
        XorCycler {
            upstream: self,
            key: key.into_iter().cycle(),
        }
    }
}

impl<I: Iterator> XorCyclerExt for I {}

pub trait XorRepeaterExt: Iterator {
    fn xor_repeat<T>(self, key: T) -> XorCycler<Self, Repeat<T>>
    where
        Self: Sized,
        T: Clone,
    {
        XorCycler {
            upstream: self,
            key: iter::repeat(key),
        }
    }
}

impl<I: Iterator> XorRepeaterExt for I {}

pub fn search<T>(data: T) -> Option<(f64, u8)>
where
    T: IntoIterator,
    <T as IntoIterator>::Item: Borrow<u8>,
{
    use super::freq::*;
    let data: Vec<_> = data.into_iter().map(|b| *b.borrow()).collect();
    (0x00..=0xff)
        .map(|key| (data.iter().xor_repeat(key).ascii_freq_score(), key))
        .max_by(|(a, _), (b, _)| a.total_cmp(b))
}
