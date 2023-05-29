use crate::xor;
use std::borrow::Borrow;
use std::iter::Peekable;

// AES supports three key sizes: 128-bit, 224-bit, and 256-bit. This implementation is only for
// 128-bit (16-byte) key sizes.
const KEY_SIZE: usize = 16;

// AES, regardless of key size, always operates on a 4x4 matrix of bytes.
pub const BLOCK_SIZE: usize = 16;

// Substitution look-up table used during encryption rounds.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// Inverse substitution look-up table used during decryption rounds.
const INVERSE_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// Constants used during round key expansion.
const ROUND_CONSTANTS: [u32; 11] = [
    0x00_00_00_00,
    0x01_00_00_00,
    0x02_00_00_00,
    0x04_00_00_00,
    0x08_00_00_00,
    0x10_00_00_00,
    0x20_00_00_00,
    0x40_00_00_00,
    0x80_00_00_00,
    0x1B_00_00_00,
    0x36_00_00_00,
];

// Wrapper Key128 type for a better organized API.
#[derive(Copy, Clone)]
pub struct Key128([u8; KEY_SIZE]);

// Alias for a better organized API.
type RoundKey = [u8; BLOCK_SIZE];

impl Key128 {
    // Generate the round keys given the initial 128-bit key. For 128-bit keys, 11 round keys are
    // generated.
    fn round_keys(self) -> [RoundKey; 11] {
        let key = self.as_words();
        // Calculate each key word.
        let mut gen_keys: [u32; 44] = [0; 44];
        for i in 0..44 {
            gen_keys[i] = if i < key.len() {
                key[i]
            } else if i % 4 == 0 {
                gen_keys[i - 4]
                    ^ sub_word(gen_keys[i - 1].rotate_left(8))
                    ^ ROUND_CONSTANTS[(i / 4) as usize]
            } else {
                gen_keys[i - 4] ^ gen_keys[i - 1]
            };
        }

        // Create iterator over each byte of the flattened words.
        let mut bytes = gen_keys
            .chunks(4)
            .flat_map(|chunk| chunk.iter().copied().flat_map(u32::to_be_bytes));

        // Build the array of RoundKeys one byte at a time.
        let mut round_keys = [[0; BLOCK_SIZE]; 11];
        for key in 0..round_keys.len() {
            for byte in 0..BLOCK_SIZE {
                // It's safe to unwrap here.
                // We are iterating over exactly 176 bytes (4 * 44 = 11 * 16).
                round_keys[key][byte] = bytes.next().unwrap();
            }
        }
        round_keys
    }

    // Convert [u8; 16] into [u32; 4] for easier processing during round key generation.
    fn as_words(self) -> [u32; 4] {
        let buf = self.0;
        [
            u32::from_be_bytes([buf[0x0], buf[0x1], buf[0x2], buf[0x3]]),
            u32::from_be_bytes([buf[0x4], buf[0x5], buf[0x6], buf[0x7]]),
            u32::from_be_bytes([buf[0x8], buf[0x9], buf[0xa], buf[0xb]]),
            u32::from_be_bytes([buf[0xc], buf[0xd], buf[0xe], buf[0xf]]),
        ]
    }
}

impl From<[u8; KEY_SIZE]> for Key128 {
    fn from(block: [u8; KEY_SIZE]) -> Self {
        Self(block)
    }
}

// Polynomial multiplication performed in GF(2^8) with modulus x^8 + x^4 + x^3 + x + 1.
// The bits in a and b represent the coefficients of the polynomial.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut prod = 0;

    for _ in 0..8 {
        if (b & 0x1) != 0 {
            prod ^= a;
        }

        let high_a = (a & 0x80) != 0;
        a <<= 1;

        if high_a {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    prod
}

// Optimized gmul by x.
fn gmul_x(a: u8) -> u8 {
    let high_bit = (a & 0x80) != 0;
    let mut b = a << 1;
    if high_bit {
        b ^= 0x1b;
    }
    b
}

// Optimized gmul by x + 1.
fn gmul_x_plus_1(a: u8) -> u8 {
    a ^ gmul_x(a)
}

// Helper function to substitute each of the 4 bytes in a word.
fn sub_word(input: u32) -> u32 {
    let indices = input.to_be_bytes();
    u32::from_be_bytes([
        SBOX[indices[0] as usize],
        SBOX[indices[1] as usize],
        SBOX[indices[2] as usize],
        SBOX[indices[3] as usize],
    ])
}

// Substitute all the bytes in a block using SBOX.
fn sub_bytes(mut matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    for i in 0..matrix.len() {
        matrix[i] = SBOX[matrix[i] as usize];
    }
    matrix
}

// Substitute all the bytes in a block using INVERSE_SBOX.
fn inv_sub_bytes(mut matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    for i in 0..matrix.len() {
        matrix[i] = INVERSE_SBOX[matrix[i] as usize];
    }
    matrix
}

// Rotate each column of the matrix down. The first column doesn't rotate, the second column
// rotates by 1, the third by 2, and the fourth by 3.
fn shift_columns(matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut shifted = [0; BLOCK_SIZE];
    for i in 0..matrix.len() {
        shifted[i] = matrix[(i * 5) % BLOCK_SIZE];
    }
    shifted
}

// Invert the rotation performed by shift_columns.
fn inv_shift_columns(matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut shifted = [0; BLOCK_SIZE];
    for i in 0..matrix.len() {
        shifted[(i * 5) % BLOCK_SIZE] = matrix[i];
    }
    shifted
}

// Perform matrix multiplication in GF(2^8) for a single row.
fn mix_row(row: [u8; 4]) -> [u8; 4] {
    let [b0, b1, b2, b3] = row;
    [
        gmul_x(b0) ^ gmul_x_plus_1(b1) ^ b2 ^ b3,
        b0 ^ gmul_x(b1) ^ gmul_x_plus_1(b2) ^ b3,
        b0 ^ b1 ^ gmul_x(b2) ^ gmul_x_plus_1(b3),
        gmul_x_plus_1(b0) ^ b1 ^ b2 ^ gmul_x(b3),
    ]
}

// Invert the matrix multiplication performed in mix_row.
fn inv_mix_row(row: [u8; 4]) -> [u8; 4] {
    let [b0, b1, b2, b3] = row;
    [
        gmul(14, b0) ^ gmul(11, b1) ^ gmul(13, b2) ^ gmul(9, b3),
        gmul(9, b0) ^ gmul(14, b1) ^ gmul(11, b2) ^ gmul(13, b3),
        gmul(13, b0) ^ gmul(9, b1) ^ gmul(14, b2) ^ gmul(11, b3),
        gmul(11, b0) ^ gmul(13, b1) ^ gmul(9, b2) ^ gmul(14, b3),
    ]
}

// Perform matrix multiplication on each row of the block.
fn mix_rows(mut matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    for row in 0..4 {
        for (ofs, result) in mix_row(matrix[row * 4..(row + 1) * 4].try_into().unwrap())
            .into_iter()
            .enumerate()
        {
            matrix[row * 4 + ofs] = result;
        }
    }
    matrix
}

// Invert the matrix multiplication performed in mix_rows.
fn inv_mix_rows(mut matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    for row in 0..4 {
        for (ofs, result) in inv_mix_row(matrix[row * 4..(row + 1) * 4].try_into().unwrap())
            .into_iter()
            .enumerate()
        {
            matrix[row * 4 + ofs] = result;
        }
    }
    matrix
}

// Add the round key to the block in GF(2^8), which happens to correspond to a byte-wise XOR.
fn add_round_key(matrix: [u8; BLOCK_SIZE], round_key: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    xor::fixed(matrix, round_key)
}

// Invert the addition done in add_round_key.
fn inv_add_round_key(matrix: [u8; BLOCK_SIZE], round_key: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Because we know addition is an XOR, reversing it is equivalent to XORing again.
    xor::fixed(matrix, round_key)
}

// Helper function to perform decryption given a single block and the generated round keys.
fn decrypt_block(mut block: [u8; BLOCK_SIZE], round_keys: [RoundKey; 11]) -> [u8; BLOCK_SIZE] {
    block = inv_add_round_key(block, round_keys[10]);
    block = inv_shift_columns(block);
    block = inv_sub_bytes(block);

    for round in (1..=9).rev() {
        block = inv_add_round_key(block, round_keys[round]);
        block = inv_mix_rows(block);
        block = inv_shift_columns(block);
        block = inv_sub_bytes(block);
    }
    block = inv_add_round_key(block, round_keys[0]);
    block
}

// Helper function to perform encryption given a single block and the generated round keys.
fn encrypt_block(mut block: [u8; BLOCK_SIZE], round_keys: [RoundKey; 11]) -> [u8; BLOCK_SIZE] {
    block = add_round_key(block, round_keys[0]);

    for round in 1..=9 {
        block = sub_bytes(block);
        block = shift_columns(block);
        block = mix_rows(block);
        block = add_round_key(block, round_keys[round]);
    }
    block = sub_bytes(block);
    block = shift_columns(block);
    block = add_round_key(block, round_keys[10]);
    block
}

// Iterator struct for decrypting a byte stream from AES-128.
pub struct Aes128Decryptor<I: Iterator> {
    upstream: Peekable<I>,
    round_keys: [RoundKey; 11],
    buffer_index: usize,
    buffer_length: usize,
    decrypted_buffer: [u8; BLOCK_SIZE],
    chain: Option<[u8; BLOCK_SIZE]>,
}

impl<I: Iterator> Aes128Decryptor<I>
where
    <I as Iterator>::Item: Borrow<u8>,
{
    fn refill_buffer(&mut self) -> Option<()> {
        let mut cipher = [0; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            // Return early if we can't fill the buffer.
            // We can only decrypt full BLOCK_SIZE blocks.
            cipher[i] = *self.upstream.next()?.borrow();
        }
        self.decrypted_buffer = decrypt_block(cipher, self.round_keys);
        if let Some(chain) = self.chain {
            self.decrypted_buffer = xor::fixed(self.decrypted_buffer, chain);
            self.chain = Some(cipher);
        }
        // We could have some padding.
        self.buffer_length = BLOCK_SIZE - self.padding_count().unwrap_or(0);
        Some(())
    }

    // Get the PKCS#7 padding count of a block. Returns None when there are still more blocks to decrypt.
    fn padding_count(&mut self) -> Option<usize> {
        if self.upstream.peek().is_some() {
            // There are still blocks to decrypt.
            return None;
        }
        // Check current decrypted_buffer for padding.
        let padding = self.decrypted_buffer[self.decrypted_buffer.len() - 1] as usize;
        if !(0x1..=0x10).contains(&padding) {
            return None;
        }
        self.decrypted_buffer
            .iter()
            .rev()
            .take(padding)
            .all(|&e| e as usize == padding)
            .then_some(padding)
    }
}

// Implement Iterator trait for Aes128Decryptor.
impl<I: Iterator> Iterator for Aes128Decryptor<I>
where
    <I as Iterator>::Item: Borrow<u8>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer_index == 0 {
            self.refill_buffer()?;
        }
        if self.buffer_index >= self.buffer_length {
            return None;
        }
        let next = self.decrypted_buffer[self.buffer_index];
        self.buffer_index = (self.buffer_index + 1) % BLOCK_SIZE;
        Some(next)
    }
}

// Trait extension to add aes_ecb_decrypt method to any iterator.
pub trait Aes128EcbDecryptorExt: Iterator {
    fn aes_ecb_decrypt(self, key: impl Into<Key128>) -> Aes128Decryptor<Self>
    where
        Self: Sized,
    {
        Aes128Decryptor {
            upstream: self.peekable(),
            round_keys: key.into().round_keys(),
            buffer_index: 0,
            buffer_length: BLOCK_SIZE,
            decrypted_buffer: [0; BLOCK_SIZE],
            chain: None,
        }
    }
}

impl<I: Iterator> Aes128EcbDecryptorExt for I {}

// Trait extension to add aes_cbc_decrypt method to any iterator.
pub trait Aes128CbcDecryptorExt: Iterator {
    fn aes_cbc_decrypt(self, key: impl Into<Key128>, iv: [u8; BLOCK_SIZE]) -> Aes128Decryptor<Self>
    where
        Self: Sized,
    {
        Aes128Decryptor {
            upstream: self.peekable(),
            round_keys: key.into().round_keys(),
            buffer_index: 0,
            buffer_length: BLOCK_SIZE,
            decrypted_buffer: [0; BLOCK_SIZE],
            chain: Some(iv),
        }
    }
}

impl<I: Iterator> Aes128CbcDecryptorExt for I {}

// Iterator struct for encrypting a byte stream in AES-128.
pub struct Aes128Encryptor<I: Iterator> {
    upstream: I,
    round_keys: [RoundKey; 11],
    buffer_index: usize,
    encrypted_buffer: [u8; BLOCK_SIZE],
    padded: bool,
    chain: Option<[u8; BLOCK_SIZE]>,
}

impl<I: Iterator> Aes128Encryptor<I>
where
    <I as Iterator>::Item: Borrow<u8>,
{
    fn refill_buffer(&mut self) -> Option<()> {
        // Get a block of plaintext from the upstream iterator.
        let mut plain = [0; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            if let Some(b) = self.upstream.next() {
                // We still have plaintext to encrypt.
                plain[i] = *b.borrow();
            } else if i > 0 {
                // We ran out of plaintext, so pad the rest.
                let size = BLOCK_SIZE - i;
                plain[i..].clone_from_slice(&[size as u8; 16][..size]);
                self.padded = true;
                break;
            } else if !self.padded {
                // We should always output padding, so if the plaintext is exactly a multiple of
                // BLOCK_SIZE, add a full block of padding.
                plain = [BLOCK_SIZE as u8; BLOCK_SIZE];
                self.padded = true;
                break;
            } else {
                // We don't have any more plaintext to encrypt.
                return None;
            }
        }
        if let Some(chain) = self.chain {
            self.encrypted_buffer = encrypt_block(xor::fixed(plain, chain), self.round_keys);
            // Save the chain for the next encryption block.
            self.chain = Some(self.encrypted_buffer);
        } else {
            self.encrypted_buffer = encrypt_block(plain, self.round_keys);
        }
        Some(())
    }
}

// Implement Iterator trait for Aes128Encryptor.
impl<I: Iterator> Iterator for Aes128Encryptor<I>
where
    <I as Iterator>::Item: Borrow<u8>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer_index == 0 {
            self.refill_buffer()?;
        }
        let next = self.encrypted_buffer[self.buffer_index];
        self.buffer_index = (self.buffer_index + 1) % BLOCK_SIZE;
        Some(next)
    }
}

// Trait extension to add aes_ecb_encrypt method to any iterator.
pub trait Aes128EcbEncryptorExt: Iterator {
    fn aes_ecb_encrypt(self, key: impl Into<Key128>) -> Aes128Encryptor<Self>
    where
        Self: Sized,
    {
        Aes128Encryptor {
            upstream: self,
            round_keys: key.into().round_keys(),
            buffer_index: 0,
            encrypted_buffer: [0; BLOCK_SIZE],
            padded: false,
            chain: None,
        }
    }
}

impl<I: Iterator> Aes128EcbEncryptorExt for I {}

// Trait extension to add aes_cbc_encrypt method to any iterator.
pub trait Aes128CbcEncryptorExt: Iterator {
    fn aes_cbc_encrypt(self, key: impl Into<Key128>, iv: [u8; BLOCK_SIZE]) -> Aes128Encryptor<Self>
    where
        Self: Sized,
    {
        Aes128Encryptor {
            upstream: self,
            round_keys: key.into().round_keys(),
            buffer_index: 0,
            encrypted_buffer: [0; BLOCK_SIZE],
            padded: false,
            chain: Some(iv),
        }
    }
}

impl<I: Iterator> Aes128CbcEncryptorExt for I {}

// Trait extension to add aes_nth_block method to any iterator.
pub trait AesNthBlockExt: Iterator {
    fn aes_nth_block(self, n: usize) -> Option<[u8; BLOCK_SIZE]>
    where
        Self: Sized,
        Self::Item: Borrow<u8>,
    {
        let mut output: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let mut iter = self.skip(n * BLOCK_SIZE).take(BLOCK_SIZE);
        for i in 0..BLOCK_SIZE {
            output[i] = *iter.next()?.borrow();
        }
        Some(output)
    }
}

impl<I: Iterator> AesNthBlockExt for I {}

// Given a vector of plaintext, truncate the PKCS#7 padding if there's any there.
pub fn strip_padding(block: &mut Vec<u8>) -> Option<usize> {
    let padding = block[block.len() - 1] as usize;
    if !(0x1..=0x10).contains(&padding) {
        return None;
    }
    let valid_padding = block
        .iter()
        .rev()
        .take(padding)
        .all(|&e| e as usize == padding);
    if valid_padding {
        block.truncate(block.len() - padding);
    }
    valid_padding.then_some(padding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gmul() {
        assert_eq!(gmul(193, 56), 165);
        assert_eq!(gmul_x(15), gmul(15, 2));
        assert_eq!(gmul_x_plus_1(34), gmul(34, 3));
    }

    #[test]
    fn test_sbox() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7c);
        assert_eq!(SBOX[0x11], 0x82);
        assert_eq!(SBOX[0x30], 0x04);
        assert_eq!(SBOX[0x7b], 0x21);
    }

    #[test]
    fn test_inverse_sbox() {
        assert_eq!(INVERSE_SBOX[0x00], 0x52);
        assert_eq!(INVERSE_SBOX[0x42], 0xf6);
        assert_eq!(INVERSE_SBOX[0xfd], 0x21);
    }

    #[test]
    fn test_sub_bytes() {
        #[rustfmt::skip]
        assert_eq!(
            sub_bytes(*b"The quick brown "),
            [
                0x20, 0x45, 0x4d, 0xb7,
                0xa3, 0x9d, 0xf9, 0xfb,
                0x7f, 0xb7, 0xaa, 0x40,
                0xa8, 0xf5, 0x9f, 0xb7,
            ]
        );
    }

    #[test]
    fn test_inv_sub_bytes() {
        assert_eq!(
            inv_sub_bytes(sub_bytes(*b"The quick brown ")),
            *b"The quick brown ",
        );
    }

    #[test]
    fn test_shift_columns() {
        #[rustfmt::skip]
        assert_eq!(
            shift_columns([
                0x20, 0x45, 0x4d, 0xb7,
                0xa3, 0x9d, 0xf9, 0xfb,
                0x7f, 0xb7, 0xaa, 0x40,
                0xa8, 0xf5, 0x9f, 0xb7,
            ]),
            [
                0x20, 0x9d, 0xaa, 0xb7,
                0xa3, 0xb7, 0x9f, 0xb7,
                0x7f, 0xf5, 0x4d, 0xfb,
                0xa8, 0x45, 0xf9, 0x40,
            ],
        );
    }

    #[test]
    fn test_inv_shift_columns() {
        assert_eq!(
            inv_shift_columns(shift_columns(*b"yellow submarine")),
            *b"yellow submarine",
        );
    }

    #[test]
    fn test_mix_rows() {
        #[rustfmt::skip]
        assert_eq!(
            mix_rows([
                0x20, 0x9d, 0xaa, 0xb7,
                0xa3, 0xb7, 0x9f, 0xb7,
                0x7f, 0xf5, 0x4d, 0xfb,
                0xa8, 0x45, 0xf9, 0x40,
            ]),
            [
                0xe1, 0x53, 0x30, 0x22,
                0xb7, 0xdb, 0xf3, 0xa3,
                0x4c, 0xa2, 0x06, 0xd4,
                0x3d, 0x72, 0xc4, 0xdf,
            ],
        );
    }

    fn test_inv_mix_rows() {
        assert_eq!(
            inv_mix_rows(mix_rows(*b"yellow submarine")),
            *b"yellow submarine"
        );
    }

    #[test]
    fn test_add_round_key() {
        #[rustfmt::skip]
        assert_eq!(
            add_round_key([
                0xe1, 0x53, 0x30, 0x22,
                0xb7, 0xdb, 0xf3, 0xa3,
                0x4c, 0xa2, 0x06, 0xd4,
                0x3d, 0x72, 0xc4, 0xdf,
            ], *b"abcdefghijklmnop"),
            [
                0x80, 0x31, 0x53, 0x46,
                0xd2, 0xbd, 0x94, 0xcb,
                0x25, 0xc8, 0x6d, 0xb8,
                0x50, 0x1c, 0xab, 0xaf,
            ],
        );
    }

    #[test]
    fn test_inv_add_round_key() {
        let key: [u8; 16] = *b"abcdefghijklmnop";
        assert_eq!(
            inv_add_round_key(add_round_key(*b"yellow submarine", key), key),
            *b"yellow submarine"
        );
    }

    #[test]
    fn test_encrypt_decrypt_ecb() {
        let key = *b"yellow submarine";
        let plain = "abcdefghijklmnopq";
        assert_eq!(
            plain
                .bytes()
                .aes_ecb_encrypt(key)
                .aes_ecb_decrypt(key)
                .map(char::from)
                .collect::<String>(),
            plain,
        );
    }

    #[test]
    fn test_encrypt_decrypt_ecb_block_size() {
        let key = *b"YELLOW SUBMARINE";
        let plain = "A".repeat(16);
        assert_eq!(
            plain
                .bytes()
                .aes_ecb_encrypt(key)
                .aes_ecb_decrypt(key)
                .map(char::from)
                .collect::<String>(),
            plain,
        );
    }

    #[test]
    fn test_encrypt_decrypt_cbc() {
        let key = *b"yellow submarine";
        let iv = *b"foo bar baz buzz";
        let plain = "abcdefghijklmnopq";
        assert_eq!(
            plain
                .bytes()
                .aes_cbc_encrypt(key, iv)
                .aes_cbc_decrypt(key, iv)
                .map(char::from)
                .collect::<String>(),
            plain,
        );
    }

    #[test]
    fn test_encrypt_ecb() {
        let plain = b"ABCDEFGHIJKLMNOP";
        let key = *b"YELLOW SUBMARINE";
        #[rustfmt::skip]
        assert_eq!(
            plain.iter().aes_ecb_encrypt(key).collect::<Vec<_>>(),
            [
                0xf5, 0x45, 0xc0, 0x06,
                0x06, 0x91, 0x26, 0xd9,
                0xc0, 0xf9, 0x3f, 0xa7,
                0xdd, 0x89, 0xab, 0x98,
                // Padding
                0x60, 0xfa, 0x36, 0x70,
                0x7e, 0x45, 0xf4, 0x99,
                0xdb, 0xa0, 0xf2, 0x5b,
                0x92, 0x23, 0x01, 0xa5,
            ],
        );
    }

    #[test]
    fn test_encrypt_cbc() {
        let plain = "ABCDEFGHIJKLMNOP";
        let key = *b"YELLOW SUBMARINE";
        let iv = [0; 16];
        #[rustfmt::skip]
        assert_eq!(
            plain.bytes().aes_cbc_encrypt(key, iv).collect::<Vec<_>>(),
            [
                0xf5, 0x45, 0xc0, 0x06,
                0x06, 0x91, 0x26, 0xd9,
                0xc0, 0xf9, 0x3f, 0xa7,
                0xdd, 0x89, 0xab, 0x98,
                // Padding
                0x8d, 0xe3, 0x10, 0x76,
                0x7d, 0xe1, 0xc5, 0x3d,
                0x4c, 0x0b, 0x12, 0xb6,
                0x03, 0x3c, 0x5c, 0xb8,
            ],
        );
    }
}
