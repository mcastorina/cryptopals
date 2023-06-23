use crate::hex::*;
use std::cmp::{self, Ordering};
use std::iter;
use std::ops::{Add, Div, Mul, Neg, Rem, Shl, Shr, Sub};

// Stored as little endian (first byte is smallest).
#[derive(Debug, Default, Clone)]
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

    fn from_hex(input: impl AsRef<str>) -> Self {
        Self {
            neg: false,
            num: input.as_ref().hex_decode().rev().collect(),
        }
    }

    fn abs(mut self) -> Self {
        self.neg = false;
        self
    }

    fn trim_leading(&mut self) {
        while self.num.get(self.num.len() - 1).unwrap_or(&1) == &0 {
            self.num.pop();
        }
    }

    // Compute (num / den, num % den) for
    fn div_rem(mut self, mut den: Self) -> (Self, Self) {
        if self.neg ^ den.neg {
            let (d, mut m) = self.abs().div_rem(den.clone().abs());
            if !den.neg {
                m = den - m;
            }
            return (-d, m);
        }
        (self, den) = (self.abs(), den.abs());
        match self.cmp(&den) {
            Ordering::Equal => return (1.into(), 0.into()),
            Ordering::Less => return (0.into(), self),
            _ => (),
        }
        self.trim_leading();
        den.trim_leading();
        let num = self.clone();

        let n = 8 * self.num.len() as u16;
        let d = den.clone() << n;
        let mut r = self;
        let mut q = BigNum::from(0);
        for i in (0..n).rev() {
            r = (r << 1) - d.clone();
            if r >= 0.into() {
                q = q + (BigNum::from(1) << i);
            } else {
                r = r + d.clone();
            }
        }
        (q.clone(), num - q * den)
    }

    fn exp_rem(mut self, mut exp: Self, modulus: Self) -> Self {
        // Sanity check:  Verify that the exponent is not negative:
        assert!(exp >= BigNum::from(0));

        if exp == BigNum::from(0) {
            return BigNum::from(1);
        }

        // Now do the modular exponentiation algorithm:
        let mut result = BigNum::from(1);
        let mut base = self % modulus.clone();

        // Loop until we can return out result:
        loop {
            if exp.clone() % BigNum::from(2) == BigNum::from(1) {
                result = (result * base.clone()) % modulus.clone();
            }

            if exp == BigNum::from(1) {
                return result;
            }

            exp = exp >> 1;
            base = (base.clone() * base.clone()) % modulus.clone();
        }
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

impl Mul for BigNum {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        let mut total = BigNum::from(0);
        for (shift, x) in self.num.iter().enumerate() {
            let mut step = BigNum {
                neg: false,
                num: vec![0; shift],
            };
            let mut carry = 0;
            for y in &other.num {
                let result = (*x as u16) * (*y as u16) + carry;
                step.num.push((result & 0xff) as u8);
                carry = result >> 8;
            }
            step.num.push((carry & 0xff) as u8);
            total = total + step;
        }
        total.neg = self.neg ^ other.neg;
        total
    }
}

impl Shl<u16> for BigNum {
    type Output = Self;

    fn shl(mut self, rhs: u16) -> Self::Output {
        let (buckets, ofs) = (rhs / 8, rhs % 8);
        let mask = (1_u8 << ofs) - 1;
        let mut num = vec![0_u8; buckets as usize];
        let mut carry = 0;
        for b in self.num {
            num.push((b << ofs) | carry);
            carry = b.rotate_left(ofs.into()) & mask;
        }
        num.push(carry);
        self.num = num;
        self
    }
}

impl Shr<u16> for BigNum {
    type Output = Self;

    fn shr(mut self, rhs: u16) -> Self::Output {
        let (buckets, ofs) = (rhs / 8, rhs % 8);
        if buckets as usize >= self.num.len() {
            // We are shifting more than the data we have.
            self.num.clear();
            return self;
        }
        let mask = (1_u8 << ofs) - 1;
        let mut num = Vec::with_capacity(self.num.len() - buckets as usize);
        for (i, b) in self.num.iter().enumerate().skip(buckets as usize) {
            let carry = self.num.get(i + 1).unwrap_or(&0) & mask;
            let b = (b >> ofs) | (carry.rotate_right(ofs.into()));
            num.push(b);
        }
        self.num = num;
        self
    }
}

impl Div for BigNum {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        self.div_rem(other).0
    }
}

impl Rem for BigNum {
    type Output = Self;

    fn rem(self, other: Self) -> Self::Output {
        self.div_rem(other).1
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

impl From<Vec<u8>> for BigNum {
    fn from(num: Vec<u8>) -> Self {
        BigNum::from((false, num))
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

    #[test]
    fn test_mul() {
        for (a, b, expected) in [
            big_num!(0, 123, 0),
            big_num!(1, 2, 2),
            big_num!(120491, 8589320, 1034935756120_u128),
            big_num!(
                u128::MAX,
                u128::MAX,
                (
                    false,
                    vec![
                        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    ]
                )
            ),
            big_num!(-123, 2, -246),
            big_num!(-1, -3, 3),
        ] {
            assert_eq!(a.clone() * b.clone(), expected);
            assert_eq!(b * a, expected);
        }
    }

    #[test]
    fn test_shl() {
        for i in 0..128 {
            assert_eq!(BigNum::from(1) << i, BigNum::from(1_u128 << i));
            assert_eq!(BigNum::from(0) << i, BigNum::from(0));
            assert_eq!(BigNum::from(i) << 0, BigNum::from(i));
            if i < 120 {
                assert_eq!(BigNum::from(0xa5) << i, BigNum::from(0xa5_u128 << i));
            }
        }
        assert_eq!(
            BigNum::from_raw([1, 2, 3]) << 256,
            BigNum::from_raw(
                iter::repeat(0)
                    .take(32)
                    .chain([1, 2, 3])
                    .collect::<Vec<_>>(),
            ),
        );
    }

    #[test]
    fn test_shr() {
        const pattern: u128 = 0xf3209a08ab02891283e51e278e07e456;
        for i in 0..128 {
            assert_eq!(BigNum::from(u128::MAX) >> i, BigNum::from(u128::MAX >> i));
            assert_eq!(BigNum::from(0) >> i, BigNum::from(0));
            assert_eq!(BigNum::from(i) >> 0, BigNum::from(i));
            assert_eq!(BigNum::from(pattern) >> i, BigNum::from(pattern >> i));
        }
        assert_eq!(
            BigNum::from_raw(
                iter::repeat(0)
                    .take(32)
                    .chain([1, 2, 3])
                    .collect::<Vec<_>>(),
            ) >> 256,
            BigNum::from_raw([1, 2, 3]),
        );
    }

    #[test]
    fn test_div() {
        for (a, b, expected) in [
            big_num!(
                10480192830192088419741029_u128,
                1241072947109048102_u128,
                8444461
            ),
            big_num!(0, 1, 0),
            big_num!(1240129, 1240129, 1),
        ] {
            assert_eq!(a.clone() / b.clone(), expected);
            assert_eq!((-a.clone()) / (-b.clone()), expected);
            assert_eq!((-a.clone()) / b.clone(), (-expected.clone()));
            assert_eq!(a / (-b), (-expected));
        }
    }

    #[test]
    fn test_rem() {
        for (a, b, expected) in [
            big_num!(
                10480192830192088419741029_u128,
                1241072947109048102_u128,
                730174668975278007_u128
            ),
            big_num!(
                -10480192830192088419741029_i128,
                1241072947109048102_u128,
                510898278133770095_u128
            ),
            big_num!(0, 1, 0),
            big_num!(1240129, 1240129, 0),
            big_num!(1240129, 1240130, 1240129),
            big_num!(1240129, 1240128, 1),
        ] {
            assert_eq!(a % b, expected);
        }
        for (a, b) in [
            (-8_i32, 5_i32),
            (8, 5),
            (8, -5),
            // TODO: Not sure why (-8) % (-5) == 2 in std.
            // (-8, -5),
        ] {
            assert_eq!(
                BigNum::from(a) % BigNum::from(b),
                BigNum::from(a.rem_euclid(b))
            );
        }
    }

    #[test]
    fn test_exp_rem() {
        use crate::hex::*;
        let a = BigNum::from_hex("6ed80fface4df443c2e9a56155272b9004e01f5dabe5f2181a603da3eb");
        let b = BigNum::from_hex("5737df12ecacc95ff94e28463b3cd1de0c674cb5d079bd3f4c037e48ff");
        let m = BigNum::from_hex("1d6329f1c35ca4bfabb9f5610000000000");
        let expected = BigNum::from_hex("47cf5cc72a26166f482742959483cf0c3");

        assert_eq!(a.exp_rem(b, m), expected);
    }
}
