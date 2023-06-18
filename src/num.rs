use std::cmp::{self, Ordering};
use std::iter;
use std::ops::{Add, Neg, Sub};

// Stored as little endian (first byte is smallest).
#[derive(Debug)]
struct BigNum {
    neg: bool,
    num: Vec<u8>,
}

impl BigNum {
    fn from_raw(data: impl AsRef<[u8]>) -> Self {
        Self {
            neg: false,
            num: data.as_ref().to_vec(),
        }
    }

    fn abs(mut self) -> Self {
        self.neg = false;
        self
    }
}

impl Neg for BigNum {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            neg: !self.neg,
            ..self
        }
    }
}

impl Sub for BigNum {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        match (self.neg, other.neg) {
            (_, true) => return self + -other,
            (true, false) => return -(-self + other),
            (false, false) if self < other => return -(other - self),
            (false, false) => (),
        }
        let left = self.num;
        let right = other.num;
        let max = cmp::max(left.len(), right.len());

        let mut output = Vec::with_capacity(max);
        let mut carry = 0;
        for (a, b) in zip_longest(left.into_iter(), right.into_iter()) {
            let (diff, ab_over) = a.overflowing_sub(b);
            let (diff, c_over) = diff.overflowing_sub(carry);
            output.push(diff);
            carry = u8::from(ab_over || c_over);
        }
        Self::from((false, output))
    }
}

impl Add for BigNum {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        match (self.neg, other.neg) {
            (true, false) => return other - -self,
            (false, true) => return self - -other,
            _ => (),
        }
        let left = self.num;
        let right = other.num;
        let max = cmp::max(left.len(), right.len());

        let mut output = Vec::with_capacity(max + 1);
        let mut carry = 0;
        for (a, b) in zip_longest(left.into_iter(), right.into_iter()) {
            let (sum, ab_over) = a.overflowing_add(b);
            let (sum, c_over) = sum.overflowing_add(carry);
            output.push(sum);
            carry = u8::from(ab_over || c_over);
        }
        output.push(carry);
        Self::from((false, output))
    }
}

impl PartialEq for BigNum {
    fn eq(&self, other: &Self) -> bool {
        let mut or = 0;
        for (a, b) in zip_longest(self.num.iter().copied(), other.num.iter().copied()) {
            if a != b {
                return false;
            }
            or = or | a | b;
        }
        // At this point, all elements are equal. We need to check for 0 and matching signs.

        if or == 0 {
            // All elements are 0, so they are equal regardless of sign.
            return true;
        }
        self.neg == other.neg
    }
}

impl Eq for BigNum {}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigNum {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match (self.neg, other.neg) {
            (true, false) => return cmp::Ordering::Less,
            (false, true) => return cmp::Ordering::Greater,
            _ => (),
        }
        let (a, b) = zip_longest(self.num.iter().copied(), other.num.iter().copied())
            .rev()
            .find(|(a, b)| a != b)
            .unwrap_or((0, 0));
        if self.neg {
            b.cmp(&a)
        } else {
            a.cmp(&b)
        }
    }
}

fn zip_longest<T: Default, U: Default>(
    mut left: impl Iterator<Item = T>,
    mut right: impl Iterator<Item = U>,
) -> impl DoubleEndedIterator<Item = (T, U)> {
    iter::from_fn(move || match (left.next(), right.next()) {
        (None, None) => None,
        (Some(t), None) => Some((t, Default::default())),
        (None, Some(u)) => Some((Default::default(), u)),
        (Some(t), Some(u)) => Some((t, u)),
    })
    .collect::<Vec<_>>()
    .into_iter()
}

macro_rules! impl_from_u {
    ($($t:tt),*) => {
        $(
        impl From<$t> for BigNum {
            fn from(n: $t) -> Self {
                Self{ neg: false, num: n.to_le_bytes().to_vec() }
            }
        }
        )*
    };
}

macro_rules! impl_from_i {
    ($($t:tt),*) => {
        $(
        impl From<$t> for BigNum {
            fn from(n: $t) -> Self {
                Self{ neg: n < 0, num: n.unsigned_abs().to_le_bytes().to_vec() }
            }
        }
        )*
    };
}

impl_from_u!(u8, u16, u32, u64, u128);
impl_from_i!(i8, i16, i32, i64, i128);

impl From<(bool, Vec<u8>)> for BigNum {
    fn from((neg, num): (bool, Vec<u8>)) -> Self {
        BigNum { neg, num }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! big_num {
        ($($x:expr),*) => {
            ($(BigNum::from($x),)*)
        };
    }

    #[test]
    fn test_equal() {
        for (a, b) in [
            (BigNum::from((false, vec![])), BigNum::from((true, vec![]))),
            (
                BigNum::from((false, vec![0, 0])),
                BigNum::from((true, vec![0])),
            ),
            (
                BigNum::from((true, vec![0, 0])),
                BigNum::from((true, vec![0])),
            ),
            (
                BigNum::from((false, vec![0])),
                BigNum::from((false, vec![0])),
            ),
            big_num!(0, 0),
            big_num!(123_u8, 123_u16),
            big_num!(-123, -123),
        ] {
            assert_eq!(a, b);
            assert_eq!(b, a);
        }
    }

    #[test]
    fn test_add() {
        for (a, b, expected) in [
            big_num!(1, 2, 3),
            big_num!(255, 255, 255 + 255),
            big_num!(
                12451012849018_u128,
                8412940199248_u128,
                12451012849018_u128 + 8412940199248_u128
            ),
        ] {
            assert_eq!(a + b, expected);
        }
    }

    #[test]
    fn test_add_big() {
        let a = BigNum::from(u128::MAX);
        let b = BigNum::from(u128::MAX);
        let c = BigNum::from_raw([
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x01,
        ]);
        assert_eq!(a + b, c);
    }

    #[test]
    fn test_sub() {
        for (a, b, expected) in [
            big_num!(1, 2, -1),
            big_num!(200_u8, -55_i8, 255_u8),
            big_num!(10, 1, 9),
            big_num!(12390, 12390, 0),
            big_num!(-123, -456, -123 + 456),
            big_num!(-456, -123, -456 + 123),
            big_num!(-1337, 7664, -9001),
            big_num!(-1337, 3, -1340),
        ] {
            assert_eq!(a - b, expected);
        }
    }
}
