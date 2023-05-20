use std::borrow::Borrow;

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
