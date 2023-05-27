mod aes;
mod b64;
mod freq;
mod hex;
mod rng;
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
        let (score, message) = include_str!("data/set4.txt")
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
        let cipher: Vec<u8> = include_str!("data/set6.txt").chars().b64_decode().collect();

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
            .chars()
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
            .chars()
            .b64_decode()
            .aes_cbc_decrypt(*b"YELLOW SUBMARINE", Default::default())
            .map(char::from)
            .collect();
        assert_eq!(plain, include_str!("data/set10-plain.txt"));
    }

    #[test]
    fn aes_mode_oracle() {
        // Randomly generate a ciphertext given the input.
        fn gen_cipher(input: impl Iterator<Item = u8>) -> (Vec<u8>, &'static str) {
            let prefix = rng::stream().take(rng::range(5..=10));
            let suffix = rng::stream().take(rng::range(5..=10));
            let plain = prefix.chain(input).chain(suffix);
            let key: aes::Key128 = rng::gen();
            if rng::gen() {
                (plain.aes_ecb_encrypt(key).collect(), "ECB")
            } else {
                (plain.aes_cbc_encrypt(key, rng::gen()).collect(), "CBC")
            }
        }

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
            let (cipher, kind) = gen_cipher(input);
            assert_eq!(oracle(&cipher), kind);
        }
    }

    #[test]
    fn simple_ecb_decrypt() {
        // An unknown plaintext that gets appended to our plaintext during encryption.
        const SUFFIX: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                              aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                              dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                              YnkK";
        // Dictionary of characters to try.
        const DICTIONARY: &[u8] =
            b" \r\netaoinshrdlucwmfygpbvkxjqzETAOINSHRDLUCWMFYGPBVKXJQZ0123456789.,?'\"-;:~!@#$^&*%()[]{}_/\\";
        // Generate a ciphertext with an unknown suffix and fixed key.
        fn gen_cipher(input: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
            let suffix = SUFFIX
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .b64_decode();
            input.chain(suffix).aes_ecb_encrypt(*b"YELLOW SUBMARINE")
        }

        // Find the block size assuming ECB mode.
        // This will be None if gen_cipher is using CBC.
        let block_size = (1..=256)
            .find(|&size| {
                let cipher: Vec<u8> = gen_cipher(iter::repeat(b'A').take(size * 2)).collect();
                let mut chunks = cipher.chunks(size);
                chunks.next() == chunks.next()
            })
            .unwrap();
        assert_eq!(block_size, aes::BLOCK_SIZE);

        // Generate the ciphertext from the input and return the nth block as a u128.
        fn nth_block(input: impl Iterator<Item = u8>, n: usize) -> u128 {
            u128::from_be_bytes(
                gen_cipher(input)
                    .skip(n * aes::BLOCK_SIZE)
                    .take(aes::BLOCK_SIZE)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            )
        }

        let mut plain = Vec::new();
        // Iterate over each block.
        'outer: for block in 0.. {
            // Shift the input a known amount.
            for n in 1..=aes::BLOCK_SIZE {
                let input = iter::repeat(b'A').take(aes::BLOCK_SIZE - n);
                // This target block contains all known bytes except one, which we will search for
                // by trying all bytes in our DICTIONARY.
                let target = nth_block(input.clone(), block);
                let next = DICTIONARY.iter().copied().find(|&b| {
                    let found = nth_block(
                        input
                            .clone()
                            .chain(plain.iter().copied())
                            .chain(iter::once(b)),
                        block,
                    );
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
            SUFFIX
                .chars()
                .filter(|&b| !b.is_ascii_whitespace())
                .b64_decode()
                .collect::<Vec<_>>(),
            plain,
        );
    }
}
