mod aes;
mod b64;
mod freq;
mod hex;
mod rng;
mod vuln;
mod xor;

#[cfg(test)]
mod tests {
    use super::aes::*;
    use super::b64::*;
    use super::freq::*;
    use super::hex::*;
    use super::xor::*;
    use super::*;
    use std::iter;

    #[test]
    fn hex_to_base64() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let result: String = input.hex_decode().b64_collect();
        assert_eq!(
            result,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn hex_xor() {
        let a = "1c0111001f010100061a024b53535009181c";
        let b = "686974207468652062756c6c277320657965";

        let result: String = xor::bytewise(a.hex_decode(), b.hex_decode())
            .hex_encode()
            .collect();
        assert_eq!(result, "746865206b696420646f6e277420706c6179");
    }

    #[test]
    fn single_xor_cipher() {
        let cipher: Vec<u8> =
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
                .hex_decode()
                .collect();

        // For each key, try decoding the cipher and rank the output.
        // Find the highest score, the key that provided the highest score, and the resulting
        // decoded message.
        let possible_messages = (0x00..=0xff).map(|key| cipher.iter().xor_cycle(iter::once(key)));
        let (_, message) = freq::search(possible_messages).unwrap();

        assert_eq!(
            message.iter().b64_collect::<String>(),
            "Q29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
        );
    }

    #[test]
    fn single_xor_search() {
        let (_score, message) = include_str!("data/set4.txt")
            .lines()
            .map(|cipher| cipher.hex_decode().collect::<Vec<_>>())
            .filter_map(|cipher| {
                freq::search((0x00..=0xff).map(|key| cipher.iter().xor_repeat(key)))
            })
            .max_by(|(a, _), (b, _)| a.total_cmp(b))
            .unwrap();

        assert_eq!(
            message.iter().b64_collect::<String>(),
            "Tm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmcK"
        );
    }

    #[test]
    fn repeating_xor_cipher() {
        let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        assert_eq!(
            message.bytes().xor_cycle(b"ICE").hex_collect::<String>(),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn break_repeating_xor() {
        let cipher: Vec<u8> = include_str!("data/set6.txt").b64_decode().collect();

        // Find and rank key sizes.
        let mut key_sizes: Vec<_> = (2..=40)
            .map(|key_size| {
                // Take 20 distances and average them.
                let mut chunks = cipher.chunks(key_size);
                let hammings: Vec<_> = iter::from_fn(|| Some((chunks.next()?, chunks.next()?)))
                    .take(20)
                    .map(|(first, second)| freq::hamming(first, second))
                    .collect();
                // Average our findings (fixed point).
                let avg_hamming = hammings.iter().sum::<u32>() * 100 / hammings.len() as u32;
                // Normalize by the key size (fixed point).
                let edit_dist = avg_hamming * 1000 / key_size as u32;
                (edit_dist, key_size)
            })
            .collect();

        // Sort key sizes by the edit distance.
        key_sizes.sort_by(|(a, _), (b, _)| a.cmp(b));

        // Try each key size until the plaintext is all ASCII.
        let (key, _) = key_sizes
            .into_iter()
            .find_map(|(_, key_size)| {
                // Each index of the key is the best frequency analysis of that column of bytes.
                //
                // An iterator is constructed by first skipping an offset, then stepping every
                // key_size bytes, which creates a sequence of bytes for the target column.
                //
                // xor::search returns the best single-byte-xor key that decodes the sequence, and
                // then we can collect all of them to construct the key.
                let key: String = (0..key_size)
                    .filter_map(|ofs| xor::search(cipher.iter().skip(ofs).step_by(key_size)))
                    .map(|(_, key)| key as char)
                    .collect();

                // Decode the cipher with our guessed key.
                let message: String = cipher
                    .iter()
                    .xor_cycle(key.bytes())
                    .map(char::from)
                    .collect();

                // If the message is all ASCII, it's safe to assume we found the correct key.
                message.is_ascii().then_some((key, message))
            })
            .unwrap();

        assert_eq!(
            key.bytes().b64_collect::<String>(),
            "VGVybWluYXRvciBYOiBCcmluZyB0aGUgbm9pc2U=",
        );
    }

    #[test]
    fn aes_ecb_decrypt() {
        let plain: String = include_str!("data/set7.txt")
            .b64_decode()
            .aes_ecb_decrypt(*b"YELLOW SUBMARINE")
            .map(char::from)
            .collect();
        assert_eq!(plain, include_str!("data/set7-plain.txt"));
    }

    #[test]
    fn detect_aes_ecb() {
        let line = include_str!("data/set8.txt")
            .lines()
            .max_by_key(|line| {
                let data: Vec<u8> = line.chars().hex_decode().collect();
                let chunks = data.chunks(aes::BLOCK_SIZE);
                // Count the number of repeated chunks.
                (0..)
                    .map_while(|ofs| {
                        let mut iter = chunks.clone().skip(ofs);
                        let target = iter.next()?;
                        Some(
                            iter.filter(|&chunk| freq::hamming(chunk, target) == 0)
                                .count(),
                        )
                    })
                    .sum::<usize>()
            })
            .unwrap();

        assert_eq!(
            line.chars().hex_decode().take(32).b64_collect::<String>(),
            "2IBhl0CooZt4QKijHIEKPQhkmvcNwG9P1dLWnHRM0oM=",
        );
    }

    #[test]
    fn aes_cbc_decrypt() {
        let plain: String = include_str!("data/set10.txt")
            .b64_decode()
            .aes_cbc_decrypt(*b"YELLOW SUBMARINE", Default::default())
            .map(char::from)
            .collect();
        assert_eq!(plain, include_str!("data/set10-plain.txt"));
    }

    #[test]
    fn aes_mode_oracle() {
        fn oracle(cipher: &[u8]) -> &'static str {
            let mut chunks = cipher.chunks(aes::BLOCK_SIZE).skip(1);
            // Check that the second and third chunks are the same. This oracle only works if the
            // input to gen_cipher is a plaintext we control. ECB encrypts the same plaintext chunk
            // into the same ciphertext chunk.
            if chunks.next() == chunks.next() {
                "ECB"
            } else {
                "CBC"
            }
        }

        for _ in 0..100 {
            // Choose an input that we can easily detect repeats.
            let input = iter::repeat(b'A').take(aes::BLOCK_SIZE * 3);
            let vuln = vuln::aes_mode::new(input);
            let guess = oracle(&vuln.cipher);
            assert!(vuln.is(guess));
        }
    }

    #[test]
    fn simple_ecb_decrypt() {
        // A vulnerable system that always appends the same (unknown) suffix to before encryption.
        let vuln = vuln::ecb_suffix::new();

        // Find the block size assuming ECB mode.
        // This will be None if vuln is using CBC.
        let block_size = (1..=256)
            .find(|&size| {
                let cipher: Vec<u8> = vuln.gen_cipher(iter::repeat(b'A').take(size * 2)).collect();
                let mut chunks = cipher.chunks(size);
                chunks.next() == chunks.next()
            })
            .unwrap();
        assert_eq!(block_size, aes::BLOCK_SIZE);

        // Helper function to return the nth block as a u128.
        fn nth_block(cipher: impl Iterator<Item = u8>, n: usize) -> u128 {
            u128::from_be_bytes(
                cipher
                    .skip(n * aes::BLOCK_SIZE)
                    .take(aes::BLOCK_SIZE)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            )
        }

        // Dictionary of characters to try.
        const DICTIONARY: &[u8] =
            b" \r\netaoinshrdlucwmfygpbvkxjqzETAOINSHRDLUCWMFYGPBVKXJQZ0123456789.,?'\"-;:~!@#$^&*%()[]{}_/\\";

        let mut plain = Vec::new();
        // Iterate over each block.
        'outer: for block in 0.. {
            // Shift the input a known amount.
            for n in 1..=aes::BLOCK_SIZE {
                let input = iter::repeat(b'A').take(aes::BLOCK_SIZE - n);
                // This target block contains all known bytes except one, which we will search for
                // by trying all bytes in our DICTIONARY.
                let target = nth_block(vuln.gen_cipher(input.clone()), block);
                let next = DICTIONARY.iter().copied().find(|&b| {
                    let input = input
                        .clone()
                        .chain(plain.iter().copied())
                        .chain(iter::once(b));
                    let found = nth_block(vuln.gen_cipher(input), block);
                    found == target
                });
                // Save the found byte to our plaintext and continue until there's nothing left.
                if let Some(next) = next {
                    plain.push(next);
                    continue;
                }
                break 'outer;
            }
        }

        assert_eq!(
            plain.iter().b64_collect::<String>(),
            vuln::ecb_suffix::SUFFIX,
        );
    }

    #[test]
    fn ecb_cut_paste() {
        // Cookies are generated with the format: email={email}&uid={uid}&role={role}.
        let vuln = vuln::ecb_cookie::new();

        // 1. Isolate an "admin" block with padding. Since "admin" will be at the start of a block,
        //    the padding should be 11 bytes (0xb). We offset by 10 to remove the 'email=' prefix.
        let payload = "A".repeat(10) + "admin" + &"\x0b".repeat(0xb);
        let admin_block = vuln
            .cookie_for(payload)
            .unwrap()
            .b64_decode()
            .aes_nth_block(1)
            .unwrap();

        // 2. Create a profile with an email of exactly 13 characters to push "user" into its own
        //    AES block. Alternatively, a length of 13 + 16N for any integer N would work.
        let mallory = "bad@miccah.io";
        let cookie = vuln.cookie_for(mallory).unwrap();
        assert_eq!(vuln.is_admin(&cookie), false);

        // 3. Replace the last block with our admin block.
        let cookie: String = cookie
            .b64_decode()
            .take(2 * aes::BLOCK_SIZE)
            .chain(admin_block.into_iter())
            .b64_collect();

        assert_eq!(vuln.is_admin(cookie), true);
    }

    #[test]
    fn harder_ecb_decrypt() {
        // Generates ciphertexts with a random (fixed) prefix and suffix. The goal is to decrypt
        // the suffix.
        let vuln = vuln::ecb_prefix::new();

        // 1. Find the AES block boundary by looking for the when the first block stops changing.
        let prefix_size = (1..=aes::BLOCK_SIZE)
            .map(|size| {
                let input = iter::repeat(b'A').take(size);
                (size, vuln.gen_cipher(input).aes_nth_block(0).unwrap())
            })
            .reduce(|last, cur| if last.1 == cur.1 { last } else { cur })
            .map(|(size, _)| size)
            .unwrap();

        // 2. Generate 16 ciphertexts so every byte will be on a chunk border.
        let ciphers: Vec<Vec<u8>> = (0..aes::BLOCK_SIZE)
            .map(|ofs| {
                let input = iter::repeat(b'A').take(prefix_size + ofs);
                // Ignore the first chunk because it's garbage.
                vuln.gen_cipher(input).skip(aes::BLOCK_SIZE).collect()
            })
            .collect();

        // 3. Setup an oracle that, given 15 bytes of known plaintext, will search for an entry in
        //    DICTIONARY that will encrypt to the target cipher text.
        let oracle = |known_plain: [u8; 15], target_cipher: [u8; 16]| {
            const DICTIONARY: &[u8] =
                b" \r\netaoinshrdlucwmfygpbvkxjqzETAOINSHRDLUCWMFYGPBVKXJQZ0123456789.,?'\"-;:~!@#$^&*%()[]{}_/\\";
            let input = iter::repeat(b'A')
                .take(prefix_size)
                .chain(known_plain.into_iter());
            DICTIONARY.iter().copied().find(|&b| {
                let found: [u8; aes::BLOCK_SIZE] = vuln
                    .gen_cipher(input.clone().chain(iter::once(b)))
                    .aes_nth_block(1)
                    .unwrap();
                found == target_cipher
            })
        };

        // 4. Build out the plaintext byte-by-byte.
        let mut plain: Vec<u8> = Vec::new();
        for i in 0.. {
            // Calculate the current offset (how much padding we have) and block that we're
            // operating on.
            let ofs = 15 - (i % aes::BLOCK_SIZE);
            let block = i / aes::BLOCK_SIZE;
            // Build the known by taking the last 15 bytes of the known plaintext (padded with As).
            let known = {
                let mut known = [b'A'; 15];
                for (i, &b) in plain.iter().rev().take(15).enumerate() {
                    known[14 - i] = b;
                }
                known
            };
            let target = ciphers[ofs].iter().aes_nth_block(block).unwrap();
            if let Some(found) = oracle(known, target) {
                plain.push(found);
            } else {
                break;
            }
        }

        assert_eq!(
            plain.iter().b64_collect::<String>(),
            vuln::ecb_prefix::SUFFIX,
        );
    }

    #[test]
    fn cbc_bit_flip() {
        // Our user input gets prepended with 32 bytes and appended with 42 bytes before encryption.
        let vuln = vuln::cbc_bits::new();

        // Choose a plaintext that we can easily flip bits with. The only prevented characters are
        // ';' and '=', so we use ':' and '<' as they are both one bit off. We need to prefix the
        // string with a semicolon because the previous block will be entirely scrambled.
        let cookie = vuln.cookie_for(":admin<true").unwrap();
        assert_eq!(vuln.is_admin(&cookie).unwrap(), false);

        let mut cipher: Vec<u8> = cookie.b64_decode().collect();
        cipher[16] ^= 0x1; // Transform : into ;
        cipher[22] ^= 0x1; // Transform < into =

        let cookie: String = cipher.iter().b64_collect();
        assert_eq!(vuln.is_admin(cookie).unwrap(), true);
    }

    #[test]
    fn cbc_padding_oracle() {
        let vuln = vuln::cbc_padding::new();
        let (cipher, iv) = vuln.cipher();

        // Chunk up the cipher text into AES block sizes.
        let chunks: Vec<[u8; aes::BLOCK_SIZE]> = {
            let mut chunks = vec![iv];
            chunks.extend(
                cipher
                    .chunks(aes::BLOCK_SIZE)
                    .map(|chunk| chunk.try_into().unwrap())
                    .collect::<Vec<[u8; aes::BLOCK_SIZE]>>(),
            );
            chunks
        };

        // Isolate two blocks to work with. We'll go left to right.
        let mut decrypted = Vec::new();
        let mut iter = chunks.windows(2);
        while let Some(&[c1, c2]) = iter.next() {
            // Get the plaintext block a byte at a time.
            let mut plain = [0_u8; aes::BLOCK_SIZE];
            // Go through each possible padding.
            for padding in 1..=aes::BLOCK_SIZE {
                // Build the first ciphertext block by taking the original block and setting the
                // trailing bytes to the expected padding value. We need the plaintext to calculate
                // it correctly, so we must decode each block right to left.
                let c1 = {
                    let mut block = c1;
                    for index in (0..aes::BLOCK_SIZE).rev().take(padding - 1) {
                        block[index] = block[index] ^ plain[index] ^ (padding as u8);
                    }
                    block
                };
                let target_index = aes::BLOCK_SIZE - padding;
                // Try all 256 bytes and check for valid padding. We go in reverse because the last
                // block already has valid padding, so XOR with 0x00 (no-op) should be the last
                // thing we try.
                for b in (0x00..=0xff).rev() {
                    // Construct the block by XORing the target index byte. This should make the
                    // decrypted byte equal to b.
                    let c1 = {
                        let mut block = c1;
                        block[target_index] ^= b;
                        block
                    };
                    // Ask our vulnerable system if we have valid padding.
                    if vuln.valid_padding(c1.iter().chain(c2.iter())) {
                        plain[target_index] = b ^ (padding as u8);
                        break;
                    }
                }
            }
            decrypted.extend_from_slice(&plain);
        }
        aes::strip_padding(&mut decrypted);

        assert!(vuln.solve(&decrypted));
    }
}
