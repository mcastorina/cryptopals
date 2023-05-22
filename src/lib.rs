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
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let cipher: Vec<u8> = include_str!("data/set6.txt").chars().b64_decode().collect();
        let mut heap: BinaryHeap<_> = (2..=40)
            .map(|key_size| {
                // Take 20 distances and average them.
                let hammings: Vec<_> = (0..20)
                    .map(|skip| {
                        let (first, second) = {
                            let mut it = cipher.chunks(key_size).skip(skip);
                            (it.next().unwrap(), it.next().unwrap())
                        };
                        freq::hamming(first, second)
                    })
                    .collect();
                // Average our findings.
                let avg_hamming = hammings.iter().sum::<u32>() / hammings.len() as u32;
                // Fixed point representation because f64 isn't Ord.
                let edit_dist = avg_hamming * 100_000 / key_size as u32;
                (Reverse(edit_dist), key_size)
            })
            .collect();

        // Try each key size until the plaintext is all ASCII.
        let mut key: Option<String> = None;
        let mut message: Option<String> = None;
        while let Some((_, key_size)) = heap.pop() {
            let k: String = (0..key_size)
                .filter_map(|ofs| xor::search(cipher.iter().skip(ofs).step_by(key_size)))
                .map(|(_, key)| key as char)
                .collect();

            let m: String = cipher.iter().xor_cycle(k.bytes()).map(char::from).collect();

            if m.is_ascii() {
                key = Some(k);
                message = Some(m);
                break;
            }
        }

        assert_eq!(
            key.unwrap().bytes().b64_collect::<String>(),
            "VGVybWluYXRvciBYOiBCcmluZyB0aGUgbm9pc2U=",
        );
    }
}
