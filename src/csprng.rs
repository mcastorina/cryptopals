use std::{alloc, fs, io::Read, mem, slice};

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
            alloc::handle_alloc_error(layout);
        }
        // Convert raw pointer into a slice of u8.
        let mut slice = slice::from_raw_parts_mut(ptr, size);
        // Fill the slice with bytes from /dev/urandom.
        f.read_exact(&mut slice).unwrap();
        *(ptr as *mut T)
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
}
