const BLOCK_SIZE: usize = 16;

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

fn gmul2(a: u8) -> u8 {
    let high_bit = (a & 0x80) != 0;
    let mut b = a << 1;
    if high_bit {
        b ^= 0x1b;
    }
    b
}

fn gmul3(a: u8) -> u8 {
    a ^ gmul2(a)
}

// TODO: turn this into a LUT
fn rcon(mut value: u32) -> u32 {
    let mut c = 1;
    if value == 0 {
        return 0;
    }
    while value != 1 {
        c = gmul2(c);
        value -= 1;
    }
    (c as u32) << 24
}

const KEY_LENGTH: usize = 4;
const ROUND_KEY_LENGTH: usize = 40;

fn sub_word(input: u32) -> u32 {
    let indices = input.to_be_bytes();
    u32::from_be_bytes([
        SBOX[indices[0] as usize],
        SBOX[indices[1] as usize],
        SBOX[indices[2] as usize],
        SBOX[indices[3] as usize],
    ])
}

fn gen_round_keys(key: [u32; 4]) -> [u32; 44] {
    let mut gen_keys: [u32; 44] = [0; 44];
    for i in 0..44 {
        gen_keys[i] = if i < key.len() {
            key[i]
        } else if i % 4 == 0 {
            gen_keys[i - 4] ^ sub_word(gen_keys[i - 1].rotate_left(8)) ^ rcon((i / 4) as u32)
        } else {
            gen_keys[i - 4] ^ gen_keys[i - 1]
        };
    }
    gen_keys
}

fn sub_bytes(mut matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    for i in 0..matrix.len() {
        matrix[i] = SBOX[matrix[i] as usize];
    }
    matrix
}

fn inv_sub_bytes(mut matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    for i in 0..matrix.len() {
        matrix[i] = INVERSE_SBOX[matrix[i] as usize];
    }
    matrix
}

fn shift_columns(matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut shifted = [0; BLOCK_SIZE];
    for i in 0..matrix.len() {
        shifted[i] = matrix[(i * 5) % BLOCK_SIZE];
    }
    shifted
}

fn inv_shift_columns(matrix: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut shifted = [0; BLOCK_SIZE];
    for i in 0..matrix.len() {
        shifted[(i * 5) % BLOCK_SIZE] = matrix[i];
    }
    shifted
}

fn mix_row(row: [u8; 4]) -> [u8; 4] {
    let [b0, b1, b2, b3] = row;
    [
        gmul2(b0) ^ gmul3(b1) ^ b2 ^ b3,
        b0 ^ gmul2(b1) ^ gmul3(b2) ^ b3,
        b0 ^ b1 ^ gmul2(b2) ^ gmul3(b3),
        gmul3(b0) ^ b1 ^ b2 ^ gmul2(b3),
    ]
}

fn inv_mix_row(row: [u8; 4]) -> [u8; 4] {
    let [b0, b1, b2, b3] = row;
    [
        gmul(14, b0) ^ gmul(11, b1) ^ gmul(13, b2) ^ gmul(9, b3),
        gmul(9, b0) ^ gmul(14, b1) ^ gmul(11, b2) ^ gmul(13, b3),
        gmul(13, b0) ^ gmul(9, b1) ^ gmul(14, b2) ^ gmul(11, b3),
        gmul(11, b0) ^ gmul(13, b1) ^ gmul(9, b2) ^ gmul(14, b3),
    ]
}

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

fn add_round_key(mut matrix: [u8; BLOCK_SIZE], round_key: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    for i in 0..matrix.len() {
        matrix[i] ^= round_key[i];
    }
    matrix
}

fn inv_add_round_key(matrix: [u8; BLOCK_SIZE], round_key: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    add_round_key(matrix, round_key)
}

fn round_key_to_bytes(key: &[u32]) -> [u8; BLOCK_SIZE] {
    assert_eq!(key.len(), 4);
    key.iter()
        .copied()
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn strip_padding(block: &mut Vec<u8>) {
    let padding = block[block.len() - 1] as usize;
    if !(0x1..=0xf).contains(&padding) {
        return;
    }
    if block
        .iter()
        .rev()
        .take(padding)
        .all(|&e| e as usize == padding)
    {
        block.truncate(block.len() - padding);
    }
}

pub fn encrypt(plain: &[u8], key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let key = [
        u32::from_be_bytes(key[0..4].try_into().unwrap()),
        u32::from_be_bytes(key[4..8].try_into().unwrap()),
        u32::from_be_bytes(key[8..12].try_into().unwrap()),
        u32::from_be_bytes(key[12..16].try_into().unwrap()),
    ];
    let round_keys = gen_round_keys(key);
    let mut cipher = Vec::with_capacity(plain.len());
    for block in plain.chunks(BLOCK_SIZE) {
        let mut block: [u8; BLOCK_SIZE] = if block.len() == BLOCK_SIZE {
            block.try_into().unwrap()
        } else {
            let mut padded_block = [(BLOCK_SIZE - block.len()) as u8; BLOCK_SIZE];
            padded_block[..block.len()].clone_from_slice(block);
            padded_block
        };
        block = add_round_key(block, round_key_to_bytes(&round_keys[0..4]));

        for round in 1..=9 {
            block = sub_bytes(block);
            block = shift_columns(block);
            block = mix_rows(block);
            block = add_round_key(
                block,
                round_key_to_bytes(&round_keys[round * 4..(round + 1) * 4]),
            );
        }
        block = sub_bytes(block);
        block = shift_columns(block);
        block = add_round_key(block, round_key_to_bytes(&round_keys[40..44]));
        cipher.extend(block);
    }
    cipher
}

pub fn decrypt(cipher: &[u8], key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let key = [
        u32::from_be_bytes(key[0..4].try_into().unwrap()),
        u32::from_be_bytes(key[4..8].try_into().unwrap()),
        u32::from_be_bytes(key[8..12].try_into().unwrap()),
        u32::from_be_bytes(key[12..16].try_into().unwrap()),
    ];
    let round_keys = gen_round_keys(key);
    let mut plain = Vec::with_capacity(cipher.len());
    for block in cipher.chunks(BLOCK_SIZE) {
        let mut block: [u8; BLOCK_SIZE] = block.try_into().unwrap();
        block = inv_add_round_key(block, round_key_to_bytes(&round_keys[40..44]));
        block = inv_shift_columns(block);
        block = inv_sub_bytes(block);

        for round in (1..=9).rev() {
            block = inv_add_round_key(
                block,
                round_key_to_bytes(&round_keys[round * 4..(round + 1) * 4]),
            );
            block = inv_mix_rows(block);
            block = inv_shift_columns(block);
            block = inv_sub_bytes(block);
        }
        block = inv_add_round_key(block, round_key_to_bytes(&round_keys[0..4]));
        plain.extend(block);
    }
    strip_padding(&mut plain);
    plain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gmul() {
        assert_eq!(gmul(193, 56), 165);
        assert_eq!(gmul2(15), gmul(15, 2));
        assert_eq!(gmul3(34), gmul(34, 3));
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
    fn test_encrypt_decrypt() {
        let key = *b"yellow submarine";
        assert_eq!(
            decrypt(&encrypt(b"abcdefghijklmnopq", key), key),
            b"abcdefghijklmnopq",
        );
    }

    #[test]
    fn test_encrypt() {
        let plain = b"ABCDEFGHIJKLMNOP";
        let key = *b"YELLOW SUBMARINE";
        assert_eq!(
            encrypt(plain, key),
            [
                0xf5, 0x45, 0xc0, 0x06, 0x06, 0x91, 0x26, 0xd9, 0xc0, 0xf9, 0x3f, 0xa7, 0xdd, 0x89,
                0xab, 0x98
            ],
        );
    }
}
