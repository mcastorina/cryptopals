mod b64;
mod hex;

#[cfg(test)]
mod tests {
    use super::b64::*;
    use super::hex::*;

    #[test]
    fn hex_to_base64() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let result: String = input.bytes().hex_decode().b64_encode().collect();
        assert_eq!(
            result,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn hex_xor() {
        let a = "1c0111001f010100061a024b53535009181c";
        let b = "686974207468652062756c6c277320657965";

        let result: String = a
            .bytes()
            .hex_decode()
            .zip(b.bytes().hex_decode())
            .map(|(a, b)| a ^ b)
            .hex_encode()
            .collect();
        assert_eq!(result, "746865206b696420646f6e277420706c6179");
    }
}
