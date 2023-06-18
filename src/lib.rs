mod aes;
mod b64;
mod freq;
mod hash;
mod hex;
mod mac;
mod num;
mod rng;
mod vuln;
mod xor;

#[cfg(test)]
mod tests {
    use super::aes::*;
    use super::b64::*;
    use super::freq::*;
    use super::hash::{self, *};
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
                let cipher: Vec<u8> = vuln.gen_cipher(iter::repeat(b'A').take(size * 3)).collect();
                let mut chunks = cipher.chunks(size);
                let (a, b, c) = (chunks.next(), chunks.next(), chunks.next());
                a == b && b == c
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
    #[ignore]
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

    #[test]
    fn aes_ctr() {
        let input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let result: String = input
            .b64_decode()
            .aes_ctr(*b"YELLOW SUBMARINE", 0)
            .b64_collect();
        assert_eq!(
            result,
            "WW8sIFZJUCBMZXQncyBraWNrIGl0IEljZSwgSWNlLCBiYWJ5IEljZSwgSWNlLCBiYWJ5IA=="
        );
    }

    #[test]
    fn fixed_nonce() {
        let vuln = vuln::fixed_ctr_nonce::new();
        let ciphers = vuln.ciphers();

        // Use our previous search function to find the best single byte XOR key of a
        // cross-section of the cipher-texts. The most likely key will have the highest
        // frequency analysis score as it will decode all ciphertexts to ASCII characters.
        let key: Vec<u8> = (0..)
            .map_while(|ofs| {
                let cross: Vec<_> = ciphers
                    .iter()
                    .filter_map(|cipher| cipher.get(ofs))
                    .collect();
                // Only try to decode cross-sections that we have enough data for.
                if cross.len() < 3 * ciphers.len() / 4 {
                    return None;
                }
                xor::search(ciphers.iter().filter_map(|cipher| cipher.get(ofs)))
            })
            .map(|(_, guess)| guess)
            .collect();

        for (i, cipher) in ciphers.iter().enumerate() {
            let plain = xor::bytewise(&key, cipher).collect::<Vec<_>>();
            let plain = String::from_utf8_lossy(&plain);
            assert!(vuln.check_prefix(i, &plain));
        }
    }

    #[test]
    fn mersenne_twister() {
        assert_eq!(
            rng::MersenneTwister::new(0).take(7).collect::<Vec<u32>>(),
            [2357136044, 2546248239, 3071714933, 3626093760, 2588848963, 3684848379, 2340255427]
        );
    }

    #[test]
    #[ignore]
    fn crack_mersenne() {
        use std::thread;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        fn timestamp() -> u32 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32
        }

        let program_start = timestamp();
        thread::sleep(Duration::from_secs(rng::range(40..=1000)));
        let observed_number = rng::MersenneTwister::new(timestamp()).next();
        thread::sleep(Duration::from_secs(rng::range(40..=1000)));

        let seed = (program_start..)
            .find(|&seed| {
                let mut mt = rng::MersenneTwister::new(seed);
                mt.next() == observed_number
            })
            .unwrap();

        assert_eq!(rng::MersenneTwister::new(seed).next(), observed_number);
    }

    #[test]
    fn untemper_mersenne() {
        let mut mt = rng::MersenneTwister::new(rng::gen());

        // Magic untemper function.
        fn untemper(mut n: u32) -> u32 {
            // Reverse 'y >> 18'
            //  The upper 18 bits of y are unchanged, so we can directly get the lower 14 bits to
            //  XOR with.
            n ^= n >> 18;
            // Reverse 'y << 15 & C'
            //  We do this in two steps because we lost some information by shifting less than 16
            //  bits. The lower 15 bits are unchanged, so we get the next 15 bits, then the last
            //  2.
            let cmask = 0x7fff;
            n ^= (n << 15) & 0xefc60000 & (cmask << 15);
            n ^= (n << 15) & 0xefc60000 & (cmask << 30);
            // Reverse 'y << 7 & B'
            //  We do the same recovery as before, but it takes more steps because we only go 7
            //  bits at a time.
            let smask = 0x7f;
            n ^= (n << 7) & 0x9d2c5680 & (smask << 7);
            n ^= (n << 7) & 0x9d2c5680 & (smask << 14);
            n ^= (n << 7) & 0x9d2c5680 & (smask << 21);
            n ^= (n << 7) & 0x9d2c5680 & (smask << 28);
            // Reverse 'y >> 11'
            //  We go left to right this time since the shift direction is reversed.
            let umask = 0x7ff;
            n ^= (n >> 11) & (umask << 22);
            n ^= (n >> 11) & (umask << 11);
            n ^= (n >> 11) & umask;
            n
        }

        let mut state = [0; 624];
        let mut index = 0;
        while index < 624 {
            state[index] = untemper(mt.next());
            index += 1;
        }
        let mut spliced = unsafe { rng::MersenneTwister::from_state(state) };

        for (a, b) in mt.zip(spliced).take(1000) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn mersenne_stream_cipher() {
        use std::thread;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let vuln = vuln::mt19937_stream::new();

        // Generate a ciphertext of a random prefix followed by a known plaintext.
        let cipher = vuln
            .gen_blob(iter::repeat(b'A').take(14))
            .collect::<Vec<_>>();

        let prefix_len = cipher.len() - 14;
        // Extract the Mersenne Twister stream using the known plaintext.
        let mt_stream = cipher
            .iter()
            .skip(prefix_len)
            .xor_repeat(b'A')
            .collect::<Vec<_>>();

        // Brute force it now that we know the output bytes and that the seed is only 16 bits.
        let seed = (0..)
            .find(|&seed| {
                rng::MersenneTwister::new(seed as u32)
                    .into_iter::<u8>()
                    .skip(prefix_len)
                    .zip(mt_stream.iter().copied())
                    .all(|(a, b)| a == b)
            })
            .unwrap();
        assert!(vuln.check_seed(seed));

        // Generate two unique password reset tokens.
        let token_a: Vec<u8> = vuln.password_reset_token().collect();
        let ofs: u32 = 1;
        thread::sleep(Duration::from_secs(ofs as u64));
        let token_b: Vec<u8> = vuln.password_reset_token().collect();

        // XORing these two tokens, we'll get the two PRNG streams XORed together.
        let target: Vec<u8> = xor::bytewise(&token_a, &token_b).collect();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        // Brute force a known area for two PRNGs to XOR to the same target.
        let seed = (current_time - 100..=current_time)
            .find(|&seed| {
                let stream_a = rng::MersenneTwister::new(seed).into_iter::<u8>();
                let stream_b = rng::MersenneTwister::new(seed + ofs).into_iter::<u8>();
                freq::hamming(stream_a.xor_bytewise(stream_b), &target) == 0
            })
            .unwrap();

        // Recover the key by XORing the PRNG with the original token.
        let key: Vec<u8> = rng::MersenneTwister::new(seed)
            .into_iter::<u8>()
            .xor_bytewise(&token_a)
            .collect();

        // Confirm that we can create our own expiration tokens.
        let cracked_token = rng::MersenneTwister::new(current_time - 60)
            .into_iter::<u8>()
            .xor_bytewise(&key);
        assert!(vuln.valid_reset_token(cracked_token));
    }

    #[test]
    fn aes_ctr_ram() {
        let mut vuln = vuln::aes_ctr_seek::new();
        // Read the original cipher text.
        let cipher = vuln.read().clone();
        // Replace it all with our chosen plaintext.
        vuln.edit(0, iter::repeat(b'A').take(cipher.len()));
        // Recover the original plaintext by XORing the two ciphertexts and our known plaintext.
        // This works because the same keystream is reused:
        //  cipher     = plain     ^ keystream
        //  new_cipher = new_plain ^ keystream
        //  cipher ^ new_cipher               = plain ^ new_plain
        //  (cipher ^ new_cipher) ^ new_plain = plain
        let plain = iter::repeat(b'A')
            .xor_bytewise(vuln.read())
            .xor_bytewise(cipher)
            .map(char::from)
            .collect::<String>();
        assert_eq!(plain, include_str!("data/set7-plain.txt"));
    }

    #[test]
    fn ctr_bit_flip() {
        // Our user input gets prepended with 32 bytes and appended with 42 bytes before encryption.
        let vuln = vuln::ctr_bits::new();

        // Choose a plaintext that we can easily flip bits with. The only prevented characters are
        // ';' and '=', so we use ':' and '<' as they are both one bit off.
        let cookie = vuln.cookie_for(":admin<true").unwrap();
        assert_eq!(vuln.is_admin(&cookie).unwrap(), false);

        let mut cipher: Vec<u8> = cookie.b64_decode().collect();
        cipher[32] ^= 0x1; // Transform : into ;
        cipher[38] ^= 0x1; // Transform < into =

        let cookie: String = cipher.iter().b64_collect();
        assert_eq!(vuln.is_admin(cookie).unwrap(), true);
    }

    #[test]
    fn cbc_key_iv() {
        let vuln = vuln::cbc_iv::new();

        let cookie = vuln.cookie_for("AAAAAAAAAAAAAAAA").unwrap();
        assert!(cookie.b64_decode().count() >= 3 * aes::BLOCK_SIZE);

        let chunk = cookie.b64_decode().aes_nth_block(0).unwrap();
        // Construct a cookie using [C₀, 0, C₀]. We chain the original cookie to avoid padding
        // errors during decryption.
        let bad_cookie: String = [chunk, [0; aes::BLOCK_SIZE], chunk]
            .into_iter()
            .flatten()
            .chain(cookie.b64_decode())
            .b64_collect();
        // Give the bad cookie for decryption and capture the returned error plaintext.
        let err = vuln.is_admin(bad_cookie).unwrap_err();
        let plaintext: Vec<u8> = match err.split_once(": ").unwrap() {
            // We can just take the valid UTF-8 but not ASCII bytes.
            ("unexpected bytes found during decryption", s) => s.bytes().collect(),
            // We need to convert the message from a string representation of [b₀, b₁, ..].
            ("not utf8", s) => s
                .chars()
                .filter(|&b| b.is_ascii_digit() || b == ',')
                .collect::<String>()
                .split(',')
                .map(|item| item.parse().unwrap())
                .collect(),
            _ => unreachable!(),
        };

        // Recover the key as the first and third plaintext blocks XORed together.
        let key: [u8; aes::BLOCK_SIZE] = xor::bytewise(
            plaintext.iter().aes_nth_block(0).unwrap(),
            plaintext.iter().aes_nth_block(2).unwrap(),
        )
        .aes_nth_block(0)
        .unwrap();

        // Make our own cookie.
        let cookie: String = "pwnd;admin=true"
            .bytes()
            .aes_cbc_encrypt(key, key)
            .b64_collect();
        assert_eq!(vuln.is_admin(cookie).unwrap(), true);
    }

    #[test]
    fn sha1_mac() {
        use hash::Sha1;

        let vuln_a = vuln::hash_prefix::new::<Sha1>();
        let vuln_b = vuln::hash_prefix::new::<Sha1>();
        let message = "hello world";
        let (_, mac_a) = vuln_a.cookie_for(message).unwrap();
        let (_, mac_b) = vuln_b.cookie_for(message).unwrap();
        assert_ne!(mac_a, mac_b);
    }

    #[test]
    fn sha1_mac_prefix() {
        use hash::Sha1;
        use mac::Mac;
        let vuln = vuln::hash_prefix::new::<Sha1>();

        // Generate a MAC to a known plaintext.
        let (cookie, mac) = vuln.cookie_for("hello").unwrap();
        assert_eq!(vuln.is_admin(&cookie, &mac).unwrap(), false);

        // Get the raw message and construct the MAC.
        let message = cookie.b64_decode().collect::<Vec<_>>();
        let message_length = message.len();
        let mac: Mac<Sha1> = Mac::from((
            message,
            mac.hex_decode().collect::<Vec<_>>().try_into().unwrap(),
        ));

        // Guess the length of the secret prefix up to 64 bytes.
        let (new_message, new_mac) = (1..64)
            .map(|length_guess| {
                let (new_message, new_mac) = mac
                    .extend_with(";admin=true", message_length + length_guess)
                    .into();
                (
                    new_message.into_iter().b64_collect::<String>(),
                    new_mac.into_iter().hex_collect::<String>(),
                )
            })
            .find(|(new_message, new_mac)| vuln.is_admin(&new_message, &new_mac).is_ok())
            .unwrap();
        assert_eq!(vuln.is_admin(&new_message, &new_mac).unwrap(), true);
    }

    #[test]
    fn md4_mac_prefix() {
        use hash::Md4;
        use mac::Mac;
        let vuln = vuln::hash_prefix::new::<Md4>();

        // Generate a MAC to a known plaintext.
        let (cookie, mac) = vuln.cookie_for("hello").unwrap();
        assert_eq!(vuln.is_admin(&cookie, &mac).unwrap(), false);

        // Get the raw message and construct the MAC.
        let message = cookie.b64_decode().collect::<Vec<_>>();
        let message_length = message.len();
        let mac: Mac<Md4> = Mac::from((
            message,
            mac.hex_decode().collect::<Vec<_>>().try_into().unwrap(),
        ));

        // Guess the length of the secret prefix up to 64 bytes.
        let (new_message, new_mac) = (1..64)
            .map(|length_guess| {
                let (new_message, new_mac) = mac
                    .extend_with(";admin=true", message_length + length_guess)
                    .into();
                (
                    new_message.into_iter().b64_collect::<String>(),
                    new_mac.into_iter().hex_collect::<String>(),
                )
            })
            .find(|(new_message, new_mac)| vuln.is_admin(&new_message, &new_mac).is_ok())
            .unwrap();
        assert_eq!(vuln.is_admin(&new_message, &new_mac).unwrap(), true);
    }

    #[test]
    #[ignore]
    fn hmac_time() {
        use std::time::{Duration, SystemTime};

        let vuln = vuln::hmac_server::new();
        let file = "pwnd lol";

        fn time_fn<F: Fn() -> T, T>(f: F) -> (T, Duration) {
            let start = SystemTime::now();
            let result = f();
            let end = SystemTime::now();
            let duration = end.duration_since(start).unwrap();
            (result, duration)
        }

        // This takes 670s or ~11m.
        let mut hmac = String::new();
        while hmac.len() < Sha1::OUTPUT_SIZE * 2 {
            let b = b"0123456789abcdef"
                .iter()
                .max_by_key(|&b| {
                    hmac.push(*b as char);
                    let duration = time_fn(|| vuln.verify(&file, &hmac)).1;
                    hmac.pop();
                    duration
                })
                .unwrap();
            hmac.push(*b as char);
        }
        assert_eq!(vuln.verify(&file, &hmac), true);
    }

    #[test]
    #[ignore]
    fn hmac_time_parallel() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::{Duration, SystemTime};

        let vuln = vuln::hmac_server::new();
        let file = "pwnd lol";

        fn time_fn<F: Fn() -> T, T>(f: F) -> (T, Duration) {
            let start = SystemTime::now();
            let result = f();
            let end = SystemTime::now();
            let duration = end.duration_since(start).unwrap();
            (result, duration)
        }

        // This takes 46s. It could be twice as fast if the vulnerable system compared the bytes
        // instead the hex-encoded characters.
        let mut hmac = String::new();
        while hmac.len() < Sha1::OUTPUT_SIZE * 2 {
            let (tx, rx) = mpsc::channel();
            for b in b"0123456789abcdef" {
                let tx = tx.clone();
                let mut hmac = hmac.clone();
                thread::spawn(move || {
                    hmac.push(*b as char);
                    let duration: Duration = (0..5)
                        .map(|_| time_fn(|| vuln.verify(&file, &hmac)).1)
                        .sum();
                    tx.send((*b, duration)).unwrap();
                });
            }
            drop(tx);

            let b = rx.iter().max_by_key(|&(_, d)| d).map(|(b, _)| b).unwrap();
            hmac.push(b as char);
        }
        assert_eq!(vuln.verify(&file, &hmac), true);
    }
}
