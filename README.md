# cryptopals

Solutions to [cryptopals](https://cryptopals.com) in Rust. I'm taking the
opportunity to explore iterators and ergonomic (but poor) API design. The goal
is to write everything only using Rust's `std` library (no external crates).

Spoilers ahead!

## Table of Contents

* [Learnings](#learnings)
* [Set 1: Basics](#set-1-basics)
    * [Challenge 1-1: Convert hex to base64](#challenge-1-1-convert-hex-to-base64)
    * [Challenge 1-2: Fixed XOR](#challenge-1-2-fixed-xor)
    * [Challenge 1-3: Single-byte XOR cipher](#challenge-1-3-single-byte-xor-cipher)
    * [Challenge 1-4: Detect single-character XOR](#challenge-1-4-detect-single-character-xor)
    * [Challenge 1-5: Implement repeating-key XOR](#challenge-1-5-implement-repeating-key-xor)
    * [Challenge 1-6: Break repeating-key XOR](#challenge-1-6-break-repeating-key-xor)
    * [Challenge 1-7: AES in ECB mode](#challenge-1-7-aes-in-ecb-mode)


## Learnings

* [Borrow](https://doc.rust-lang.org/std/borrow/trait.Borrow.html) has a
  blanket implementation that allows generalization over referenced and owned
  values.
  ```rust
  fn foo(input: impl Borrow<u8>) -> u8 {
      *input.borrow()
  }
  foo(0_u8);
  foo(&0_u8);
  ```
  This is different than
  [Into](https://doc.rust-lang.org/std/convert/trait.Into.html) or
  [AsRef](https://doc.rust-lang.org/std/convert/trait.AsRef.html), which are
  more specific and idiomatic. It's not good practice to generalize over both
  because it makes the code much slower and less clear. I'm abusing it a lot
  with these solutions so I can have nicer looking APIs though.


## Set 1: Basics

### Challenge 1-1: Convert hex to base64

[Challenge link](https://cryptopals.com/sets/1/challenges/1)

Leaning into iterators and extension traits, I created two composable methods
`hex_decode()` and `b64_encode()` that takes an iterator and outputs an
iterator.

```rust
#[test]
fn hex_to_base64() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let result: String = input.hex_decode().b64_collect();
    assert_eq!(
        result,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}
```


## Challenge 1-2: Fixed XOR

[Challenge link](https://cryptopals.com/sets/1/challenges/2)

Here I created a `xor::bytewise` function to take two iterators and returns an
iterator that XORs the two inputs. Since it outputs an iterator, I can reuse
`hex_encode()` to encode the output.

```rust
#[test]
fn hex_xor() {
    let a = "1c0111001f010100061a024b53535009181c";
    let b = "686974207468652062756c6c277320657965";

    let result: String = xor::bytewise(a.hex_decode(), b.hex_decode())
        .hex_encode()
        .collect();
    assert_eq!(result, "746865206b696420646f6e277420706c6179");
}
```


## Challenge 1-3: Single-byte XOR cipher

[Challenge link](https://cryptopals.com/sets/1/challenges/3)

This challenge pushed me out of my comfort zone to write a frequency analysis
function. I don't think I did a very good job, but it seems to work okay (for
now)! Anyway, there's more iterators (surprise), hopefully it's readable. The
`freq::search` function takes in an iterator of iterators and returns the one
that had the best frequency analysis score.

```rust
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
```


## Challenge 1-4: Detect single-character XOR

[Challenge link](https://cryptopals.com/sets/1/challenges/4)

My original solution to this was really slow, so I updated my frequency
analysis function to immediately fail if a character isn't ASCII. Maybe that'll
bite me later but it's working okay now. I quite like how easy of an extension
this was to the previous challenge.

```rust
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
```


## Challenge 1-5: Implement repeating-key XOR

[Challenge link](https://cryptopals.com/sets/1/challenges/5)

Wow, another iterator extension?? Didn't see that coming! I added both
`xor_cycle()` which takes and repeats any iterator (or `IntoIterator`), and
`xor_repeat()` which takes a single byte to repeat. I wish `xor_cycle()`
could've been used both ways, but I couldn't quite figure out the trait
boundaries for that.

```rust
#[test]
fn repeating_xor_cipher() {
    let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    assert_eq!(
        message.bytes().xor_cycle(b"ICE").hex_collect::<String>(),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
}
```


## Challenge 1-6: Break repeating-key XOR

[Challenge link](https://cryptopals.com/sets/1/challenges/6)

This challenge was slightly annoying in that following the instructions the
actual key length wasn't in the top 5, but alas, taking a higher sample size
worked.

I'm actually really happy with how this reads and composes. Particularly, the
[freq::hamming](https://github.com/mcastorina/cryptopals/blob/00770e9e002c6386f93023eefc80aed2ec3ddc75/src/freq.rs#L67)
implementation, as it very easily came together due to my investment in iterators.

It is a bit verbose, so I may refactor some pieces based on future challenges,
but as a whole, it's fairly straightforward (I hope).

```rust
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
```

## Challenge 1-7: AES in ECB mode

[Challenge link](https://cryptopals.com/sets/1/challenges/7)

The OpenSSL CLI tool is.. what it is. To decode the file, we give it this command:

```bash
openssl enc -d -a -aes-128-ecb -in src/data/set7.txt -K '59454c4c4f57205355424d4152494e45'
# -d            decrypt the input
# -a            base64 decode the input
# -aes-128-ecb  cipher to use (AES-128 in ECB mode)
# -in           input file
# -K            hex-encoded key
```

I read [this article](https://medium.com/codex/aes-how-the-most-advanced-encryption-actually-works-b6341c44edb9)
in an attempt to understand and implement AES myself, got a lot of help with
the math and algorithm, and ultimately ended up with this beauty. It was very
rewarding testing the algorithm piece by piece and seeing it all come together.
[The implementation](https://github.com/mcastorina/cryptopals/blob/2ec12a293154158790446617c80b594f77b4a277/src/aes.rs#L266)
could be better and certainly needs a lot more comments, but I'm happy with it.

Thanks to Oliver and Thomas for all their help!

```rust
#[test]
fn aes_ecb_decrypt() {
    let plain: String = include_str!("data/set7.txt")
        .chars()
        .b64_decode()
        .aes_decrypt(*b"YELLOW SUBMARINE")
        .map(char::from)
        .collect();
    assert_eq!(plain, include_str!("data/set7-plain.txt"));
}
```
