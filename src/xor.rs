use std::borrow::Borrow;
use std::iter::Cycle;

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
