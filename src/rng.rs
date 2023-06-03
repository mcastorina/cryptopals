use std::io::{self, Read};
use std::{alloc, fs, marker, mem, ops, slice};

// Generates a random object using a cryptographically secure pseudorandom number generator
// (CSPRNG). This implementation currently reads from /dev/urandom, which is not performant, but
// gets the job done.
pub fn gen<T: Copy>() -> T {
    let size = mem::size_of::<T>();
    if size == 0 {
        panic!("cannot allocate 0-sized type");
    }
    // TODO: Look into Blum Blum Shub when we have a BigNumber module.
    let mut f = fs::File::open("/dev/urandom").unwrap();
    unsafe {
        // Allocate memory for T using the global allocator.
        let layout = alloc::Layout::new::<T>();
        let ptr = alloc::alloc(layout);
        if ptr.is_null() {
            // Abort on error.
            alloc::handle_alloc_error(layout);
        }
        // Convert raw pointer into a slice of u8.
        let mut slice = slice::from_raw_parts_mut(ptr, size);
        // Fill the slice with bytes from /dev/urandom.
        f.read_exact(&mut slice).unwrap();
        // Copy the data into a local variable, deallocate the heap space, and return the result.
        let result = *(ptr as *mut T);
        alloc::dealloc(ptr, layout);
        result
    }
}

// Provides a random T within a range. This function panics if you give it stupid ranges.
pub fn range<T>(range: impl ops::RangeBounds<T>) -> T
where
    T: ops::Rem<Output = T> + ops::Add<Output = T> + ops::Sub<Output = T>,
    T: Copy + PartialOrd + Default + std::fmt::Debug,
{
    ensure_range(gen(), range)
}

// Ensures the provided value is in the provided range. This function can easily panic when
// operating on the less useful cases (like at the max bound, or an empty range).
fn ensure_range<T>(mut value: T, range: impl ops::RangeBounds<T>) -> T
where
    T: ops::Rem<Output = T> + ops::Add<Output = T> + ops::Sub<Output = T>,
    T: Copy + PartialOrd + Default,
{
    use ops::Bound::*;
    match (range.start_bound(), range.end_bound()) {
        (Included(&start), Included(&end)) => {
            if value % end == T::default() {
                end
            } else {
                let count = end - start;
                while value < start {
                    value = value + count;
                }
                value % count + start
            }
        }
        (Included(&start), Excluded(&end)) => {
            let count = end - start;
            while value < start {
                value = value + count;
            }
            value % count + start
        }
        (Included(&start), Unbounded) => {
            if value >= start {
                value
            } else {
                value + start
            }
        }
        (Unbounded, Included(&end)) => {
            if value <= end {
                value
            } else {
                value % end
            }
        }
        (Unbounded, Excluded(&end)) => value % end,
        (Unbounded, Unbounded) => value,
        (Excluded(_), _) => unimplemented!(),
    }
}

// Produces an endless iterator of random items of type T.
pub fn stream<T: Copy>() -> impl Iterator<Item = T> {
    let size = mem::size_of::<T>();
    if size == 0 {
        panic!("cannot allocate 0-sized type");
    }
    Stream {
        source: fs::File::open("/dev/urandom").unwrap(),
        size,
        phantom: marker::PhantomData,
    }
}

struct Stream<T: Copy> {
    source: fs::File,
    size: usize,
    phantom: marker::PhantomData<T>,
}

impl<T: Copy> Stream<T> {
    fn gen(&mut self) -> T {
        unsafe {
            // Allocate memory for T using the global allocator.
            let layout = alloc::Layout::new::<T>();
            let ptr = alloc::alloc(layout);
            if ptr.is_null() {
                // Abort on error.
                alloc::handle_alloc_error(layout);
            }
            // Convert raw pointer into a slice of u8.
            let mut slice = slice::from_raw_parts_mut(ptr, self.size);
            // Fill the slice with bytes from /dev/urandom.
            self.source.read_exact(&mut slice).unwrap();
            // Copy the data into a local variable, deallocate the heap space, and return the result.
            let result = *(ptr as *mut T);
            alloc::dealloc(ptr, layout);
            result
        }
    }
}

impl<T: Copy> Iterator for Stream<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.gen())
    }
}

const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;
const R: u32 = 31;
const A: u32 = 0x9908b0df;
const U: u32 = 11;
const D: u32 = 0xffffffff;
const S: u32 = 7;
const B: u32 = 0x9d2c5680;
const T: u32 = 15;
const C: u32 = 0xefc60000;
const L: u32 = 18;
const F: u32 = 1812433253;

const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

pub struct MersenneTwister {
    state: [u32; N],
    index: usize,
}

impl MersenneTwister {
    pub fn new(seed: u32) -> Self {
        let mut state = [0; N];
        state[0] = seed;
        for i in 1..N {
            let (next, _) = F.overflowing_mul(state[i - 1] ^ (state[i - 1] >> (W - 2)));
            state[i] = next + i as u32;
        }
        Self { state, index: N }
    }

    pub fn next(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }

        let mut y = self.state[self.index];
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..N {
            let x = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= A;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }
        self.index = 0;
    }

    pub fn into_iter<T: Copy>(self) -> impl Iterator<Item = T> {
        MersenneTwisterIter {
            mt: self,
            buffer: [0; 4],
            index: 0,
            phantom: marker::PhantomData,
        }
    }
}

pub struct MersenneTwisterIter<T: Copy> {
    mt: MersenneTwister,
    buffer: [u8; 4],
    index: usize,
    phantom: marker::PhantomData<T>,
}

impl<T: Copy> MersenneTwisterIter<T> {
    const SIZE: usize = mem::size_of::<T>();

    fn next_byte(&mut self) -> u8 {
        if self.index == 0 {
            // Refill buffer.
            self.buffer = self.mt.next().to_be_bytes();
        }
        let ret = self.buffer[self.index];
        self.index = (self.index + 1) % 4;
        ret
    }
}

impl<T: Copy> Iterator for MersenneTwisterIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        // Allocate an unitialized instance of Self::Item.
        let item = unsafe { mem::MaybeUninit::uninit().assume_init() };

        // Get a mutable [u8] representation of it.
        let slice = unsafe {
            let ptr = mem::transmute::<&T, *mut u8>(&item);
            slice::from_raw_parts_mut(ptr, Self::SIZE)
        };

        // Fill the slice with bytes from MersenneTwister.
        for i in 0..slice.len() {
            slice[i] = self.next_byte();
        }
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen() {
        let got = (0..1000).map(|_| gen::<bool>()).filter(|&b| b).count();
        assert!((400..=600).contains(&dbg!(got)));
    }

    #[test]
    fn test_stream() {
        let got = stream::<bool>().take(1000).filter(|&b| b).count();
        assert!((400..=600).contains(&dbg!(got)));
    }

    #[test]
    fn test_ensure_range() {
        for start in 1..=2337 {
            assert!((start..).contains(&ensure_range::<u32>(1337, start..)));
            assert!((..start).contains(&ensure_range::<u32>(1337, ..start)));
            assert!((..=start).contains(&ensure_range::<u32>(1337, ..=start)));
            for end in start + 1..=2337 {
                assert!((start..end).contains(&ensure_range::<u32>(1337, start..end)));
                assert!((start..=end).contains(&ensure_range::<u32>(1337, start..=end)));
            }
        }
    }

    #[test]
    fn test_range() {
        let mut results = [false; 10];
        for _ in 0..1_000 {
            let got = range(1_i8..=10);
            results[(got - 1) as usize] |= true;
            assert!((1_i8..=10).contains(&got));
        }
        assert!(results.iter().all(|&e| e));
    }

    #[test]
    fn test_mersenne() {
        let mut mt = MersenneTwister::new(0);
        assert_eq!(mt.next(), 2357136044);
        assert_eq!(mt.next(), 2546248239);
        assert_eq!(mt.next(), 3071714933);
        assert_eq!(mt.next(), 3626093760);
        assert_eq!(mt.next(), 2588848963);
        assert_eq!(mt.next(), 3684848379);
        assert_eq!(mt.next(), 2340255427);
        assert_eq!(mt.next(), 3638918503);
        assert_eq!(mt.next(), 1819583497);
        assert_eq!(mt.next(), 2678185683);
    }

    #[test]
    fn test_mersenne_into_iter() {
        assert_eq!(
            MersenneTwister::new(0)
                .into_iter()
                .take(2)
                .collect::<Vec<u16>>(),
            [0x7f8c, 0xac0a],
        );
    }
}
