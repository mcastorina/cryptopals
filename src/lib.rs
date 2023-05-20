mod b64;
mod freq;
mod hex;
mod xor;

#[cfg(test)]
mod tests {
    use super::b64::*;
    use super::freq::*;
    use super::hex::*;
    use super::*;
    use std::iter;

    #[test]
    fn hex_to_base64() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let result: String = input.hex_decode().b64_encode().collect();
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
        let (_, _, message) = (0x00..=0xff)
            .map(|key| {
                let plain: String = xor::bytewise(&cipher, iter::repeat(key))
                    .map(char::from)
                    .collect();
                (plain.bytes().ascii_freq_score(), key, plain)
            })
            .max_by(|(a, _, _), (b, _, _)| a.total_cmp(b))
            .unwrap();

        assert_eq!(
            message.bytes().b64_encode().collect::<String>(),
            "Q29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
        );
    }

    #[test]
    #[ignore]
    fn single_xor_search() {
        let (_, _, message) = include_str!("data/set4.txt")
            .lines()
            .flat_map(|cipher| {
                (0x00..=0xff).map(move |key| {
                    let plain: String = xor::bytewise(cipher.hex_decode(), iter::repeat(key))
                        .map(char::from)
                        .collect();
                    (plain.bytes().ascii_freq_score(), key, plain)
                })
            })
            .max_by(|(a, _, _), (b, _, _)| a.total_cmp(b))
            .unwrap();

        assert_eq!(
            message.bytes().b64_encode().collect::<String>(),
            "Tm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmcK"
        );
    }

    #[test]
    fn repeating_xor_cipher() {
        let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        assert_eq!(
            xor::bytewise(message.bytes(), "ICE".bytes().cycle()).hex_encode().collect::<String>(),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
