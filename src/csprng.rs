use std::{alloc, fs, io::Read, marker, mem, ops, slice};

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
        for start in (1..=2337) {
            assert!((start..).contains(&ensure_range::<u32>(1337, start..)));
            assert!((..start).contains(&ensure_range::<u32>(1337, ..start)));
            assert!((..=start).contains(&ensure_range::<u32>(1337, ..=start)));
            for end in (start + 1..=2337) {
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
}
