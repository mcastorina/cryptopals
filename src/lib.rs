mod aes;
mod b64;
mod freq;
mod hex;
mod xor;

#[cfg(test)]
mod tests {
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
        let possible_messages = (0x00..=0xff).map(|key| cipher.iter().xor_repeat(key));
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
    fn aes_decrypt() {
        let cipher: Vec<u8> = include_str!("data/set7.txt").chars().b64_decode().collect();
        let plain: String = aes::decrypt(&cipher, *b"YELLOW SUBMARINE")
            .into_iter()
            .map(char::from)
            .collect();
        assert_eq!(plain.lines().count(), 79);
    }
}
