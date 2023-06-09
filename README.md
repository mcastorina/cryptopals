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
    * [Challenge 1-8: Detect AES in ECB mode](#challenge-1-8-detect-aes-in-ecb-mode)
* [Set 2: Block crypto](#set-2-block-crypto)
    * [Challenge 2-9: Implement PKCS#7 padding](#challenge-2-9-implement-pkcs7-padding)
    * [Challenge 2-10: Implement CBC mode](#challenge-2-10-implement-cbc-mode)
    * [Challenge 2-11: An ECB/CBC detection oracle](#challenge-2-11-an-ecbcbc-detection-oracle)
    * [Challenge 2-12: Byte-at-a-time ECB decryption (Simple)](#challenge-2-12-byte-at-a-time-ecb-decryption-simple)
    * [Challenge 2-13: ECB cut-and-paste](#challenge-2-13-ecb-cut-and-paste)
    * [Challenge 2-14: Byte-at-a-time ECB decryption (Harder)](#challenge-2-14-byte-at-a-time-ecb-decryption-harder)
    * [Challenge 2-15: PKCS#7 padding validation](#challenge-2-15-pkcs7-padding-validation)
    * [Challenge 2-16: CBC bitflipping attacks](#challenge-2-16-cbc-bitflipping-attacks)
* [Set 3: Block & stream crypto](#set-3-block--stream-crypto)
    * [Challenge 3-17: The CBC padding oracle](#challenge-3-17-the-cbc-padding-oracle)
    * [Challenge 3-18: Implement CTR, the stream cipher mode](#challenge-3-18-implement-ctr-the-stream-cipher-mode)
    * [Challenge 3-19: Break fixed-nonce CTR mode using substitutions](#challenge-3-19-break-fixed-nonce-ctr-mode-using-substitutions)
    * [Challenge 3-20: Break fixed-nonce CTR statistically](#challenge-3-20-break-fixed-nonce-ctr-statistically)
    * [Challenge 3-21: Implement the MT19937 Mersenne Twister RNG](#challenge-3-21-implement-the-mt19937-mersenne-twister-rng)
    * [Challenge 3-22: Crack an MT19937 seed](#challenge-3-22-crack-an-mt19937-seed)
    * [Challenge 3-23: Clone an MT19937 RNG from its output](#challenge-3-23-clone-an-mt19937-rng-from-its-output)
    * [Challenge 3-24: Create the MT19937 stream cipher and break it](#challenge-3-24-create-the-mt19937-stream-cipher-and-break-it)
* [Set 4: Stream crypto and randomness](#set-4-stream-crypto-and-randomness)
    * [Challenge 4-25: Break "random access read/write" AES CTR](#challenge-4-25-break-random-access-readwrite-aes-ctr)
    * [Challenge 4-27: Recover the key from CBC with IV=Key](#challenge-4-27-recover-the-key-from-cbc-with-ivkey)


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
* [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) uses Galois
  Fields of 2⁸ specifically because it has some nice properties (like addition
  is XOR). It is rooted in polynomial modular arithmetic, which is a hard thing
  to grasp, but you don't really need to know the theory to implement each
  step. The high level steps of AES encryption are:
    * Take the **key** and expand it into a collection of **round keys**
    * Break the **plaintext** into 4x4 **blocks** of 16 bytes each
    * Perform a series of transformations on each **block** using the **round keys**
        * Each of these transformations are reversible
    * Join the blocks together and return the **ciphertext**
* [MaybeUninit](https://doc.rust-lang.org/std/mem/union.MaybeUninit.html) can
  be used to unsafely initialize a type.


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


### Challenge 1-2: Fixed XOR

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


### Challenge 1-3: Single-byte XOR cipher

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


### Challenge 1-4: Detect single-character XOR

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


### Challenge 1-5: Implement repeating-key XOR

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


### Challenge 1-6: Break repeating-key XOR

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
```

### Challenge 1-7: AES in ECB mode

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
        .b64_decode()
        .aes_ecb_decrypt(*b"YELLOW SUBMARINE")
        .map(char::from)
        .collect();
    assert_eq!(plain, include_str!("data/set7-plain.txt"));
}
```


### Challenge 1-8: Detect AES in ECB mode

[Challenge link](https://cryptopals.com/sets/1/challenges/8)

AES encrypted in ECB mode means the same 16 bytes of plaintext will be
encrypted to the same 16 bytes of ciphertext. In order to find the one that was
encrypted in the file, we can look for the line with the highest count of
repeated ciphertext chunks.

```rust
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
```

## Set 2: Block crypto

### Challenge 2-9: Implement PKCS#7 padding

[Challenge link](https://cryptopals.com/sets/2/challenges/9)

I had actually already implemented this as part of [AES in ECB mode](#challenge-1-7-aes-in-ecb-mode).
Here's the relevant implementation:

```rust
// Given a vector of plaintext, truncate the PKCS#7 padding if there's any there.
pub fn strip_padding(block: &mut Vec<u8>) -> Option<usize> {
    let padding = block[block.len() - 1] as usize;
    if !(0x1..=0xf).contains(&padding) {
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
```

### Challenge 2-10: Implement CBC mode

[Challenge link](https://cryptopals.com/sets/2/challenges/10)

This was a fun addition to my current implementation that didn't take too much
work. I decided to make another trait extension for an `aes_cbc_decrypt(key,
iv)` iterator method. I used the `openssl` CLI tool to confirm my code decrypts
correctly. You'll notice it's pretty similar to the ECB mode incantation, but
we have to give it an initialization vector.

```bash
openssl enc -d -a -aes-128-cbc -in src/data/set10.txt -K '59454c4c4f57205355424d4152494e45' -iv 0
```

```rust
#[test]
fn aes_cbc_decrypt() {
    let plain: String = include_str!("data/set10.txt")
        .b64_decode()
        .aes_cbc_decrypt(*b"YELLOW SUBMARINE", Default::default())
        .map(char::from)
        .collect();
    assert_eq!(plain, include_str!("data/set10-plain.txt"));
}
```


### Challenge 2-11: An ECB/CBC detection oracle

[Challenge link](https://cryptopals.com/sets/2/challenges/11)

I was sort of confused by the instructions on this one. It wasn't clear that we
can choose any plaintext as input to the ciphertext generator or that it was a
critical part to the oracle. Maybe I did it wrong, but if we can choose the
plaintext, it is simple.

Even if I did it wrong, I had a lot of fun implementing pseudorandom number
generator (PRNG) features without the external and idiomatic
[rand](https://docs.rs/rand/latest/rand/) crate. I'm simply relying on
`/dev/urandom` for the heavy lifting and built up an iterator (shocking) /
helper functions.

```rust
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
        let vuln = vuln::aes_mode::new(input);
        let guess = oracle(&vuln.cipher);
        assert!(vuln.is(guess));
    }
}
```


### Challenge 2-12: Byte-at-a-time ECB decryption (Simple)

[Challenge link](https://cryptopals.com/sets/2/challenges/12)

These challenges are starting to get more involved, and I'm not quite sure
which parts to break out into the library and which not to. We'll keep going
like this until I need to re-use something more regularly (or maybe make a
module for vulnerable systems).

In any case, this was a fun one because *we broke real crypto*! There's a lot
of code here, but the theory is simple: If we know 15/16 bytes of the
plaintext, and we're encrypting in ECB mode (same plaintext in = same
ciphertext out), then we can try all 256 bytes and compare the output
ciphertext with the one we see.

Actually, we don't even have to try all 256 bytes if we know it's going to be
ASCII. Changing my solution from trying all bytes to the `DICTIONARY` below
sped it up considerably. It went from encrypting 12k plaintexts to 150.

```rust
#[test]
fn simple_ecb_decrypt() {
    // A vulnerable system that always appends the same (unknown) suffix before encryption.
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
```

### Challenge 2-13: ECB cut-and-paste

[Challenge link](https://cryptopals.com/sets/2/challenges/13)

I decided to create the vulnerable system in its own module to clearly show the
attack surface area and what we have access to as the attacker. I'm not sure if
the attacker knows the format of the cookie or not. It's possible either way,
but the "blind" solution would require a lot more code. We would need to
detect which block our input is in, how many bytes until we cross an AES block
boundary, and we would have to assume the last block had the role attribute.

```rust
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
```


### Challenge 2-14: Byte-at-a-time ECB decryption (Harder)

[Challenge link](https://cryptopals.com/sets/2/challenges/14)

I am quite happy with this solution because I felt like I improved on my
solution from [the simpler version](#challenge-2-12-byte-at-a-time-ecb-decryption-simple).
I'm no longer using `u128` because `[u8; 16]` can be directly compared, my
`oracle` function feels a lot more intuitive, and the loop to build the
plaintext is also simpler.

I also added another iterator (what??) to get the `aes_nth_block` of a
byte-stream. I think that helped simplify a lot of the code so there isn't a
ton of `cipher.skip(n * aes::BLOCK_SIZE).take(aes::BLOCK_SIZE).collect::<Vec<_>>().try_into().unwrap()`s
everywhere.

I *do* wish there were some sort of iterator adaptor to easily find when a
stream value changes, but that's highly specific and `windows(2)` would
probably work well if I were using external crates.

```rust
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
```


### Challenge 2-15: PKCS#7 padding validation

[Challenge link](https://cryptopals.com/sets/2/challenges/15)

I thought this is covered by my [earlier implementation](#challenge-2-9-implement-pkcs7-padding),
but comparing with `openssl`, it looks like AES always pads (including an
entire block of padding if needed). So I updated my encryption and decryption
to always pad, though decryption won't panic if there isn't padding. Maybe this
calls for a `try_aes_decrypt` style iterator extension that consumes the
iterator and returns a `Result`.

Either way, I just had to change `strip_padding` to include `0x10` instead of
stopping at `0xf` (included below for completeness).

```rust
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
```


### Challenge 2-16: CBC bitflipping attacks

[Challenge link](https://cryptopals.com/sets/2/challenges/16)

This one was a lot easier than I anticipated, but the critical information is
given at the end of the challenge. You can flip bits in a block, which cause
the entire block to get scrambled and the following block to have a bit
flipped. Since we know the format of the plaintext, we know where the block
boundaries are and can easily choose the correct byte to target.

```rust
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
```

## Set 3: Block & stream crypto

### Challenge 3-17: The CBC padding oracle

[Challenge link](https://cryptopals.com/sets/3/challenges/17)

This is very cool and pretty cryptic. I wish I could make the code more
readable (maybe I'll come back to this and refactor), but it took a fair bit of
debugging. It boils down to taking two blocks, `c1` and `c2`, and modifying
`c1` so that `c2` decrypts to have valid padding. When it does, we know that
the byte we found XORs to the decrypted padding number and can recover the
plaintext.

```rust
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
```


### Challenge 3-18: Implement CTR, the stream cipher mode

[Challenge link](https://cryptopals.com/sets/3/challenges/18)

What's this? A *stream* cipher?? I bet I could make it an iterator. And so it
was done, and I'm quite happy with [the implementation](https://github.com/mcastorina/cryptopals/blob/d97e2d054061da52174ba157b44c4ea9f00e9ca6/src/aes.rs#L578-L588).
It is a function that returns an infinite iterator of bytes that can be XORed
with the input.

```rust
#[test]
fn aes_ctr() {
    let input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let result: String = input
        .b64_decode()
        .xor_bytewise(aes::ctr(*b"YELLOW SUBMARINE", 0))
        .b64_collect();
    assert_eq!(
        result,
        "WW8sIFZJUCBMZXQncyBraWNrIGl0IEljZSwgSWNlLCBiYWJ5IEljZSwgSWNlLCBiYWJ5IA=="
    );
}
```


### Challenge 3-19: Break fixed-nonce CTR mode using substitutions

[Challenge link](https://cryptopals.com/sets/3/challenges/19)

I think I overthunk it. I used the frequency analysis XOR search from earlier
to automatically find the best key and strung it together to decrypt each
ciphertext a column at a time.

```rust
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
```


### Challenge 3-20: Break fixed-nonce CTR statistically

[Challenge link](https://cryptopals.com/sets/3/challenges/20)

I basically did this in the [previous challenge](#challenge-3-19-break-fixed-nonce-ctr-mode-using-substitutions).
Oops. It certainly solidifies the danger of using a fixed nonce though, which
is very cool.


### Challenge 3-21: Implement the MT19937 Mersenne Twister RNG

[Challenge link](https://cryptopals.com/sets/3/challenges/21)

Hmm.. a PRNG you say? Sounds perfect as an infinite iterator! I also got a
little fancy here and implemented an `into_iter<T>` method which converts the
`MersenneTwister` into an iterator where each item is `T`. It does this by
allocating an uninitialzed `T` and filling it with bytes from the RNG.

Side note: mathematical algorithms have *way* too many single letter variables.
Here are the ones from Mersenne Twister (that I need to rename): `W`, `N`, `M`,
`R`, `A`, `U`, `D`, `S`, `B`, `T`, `C`, `L`, `F`.

```rust
#[test]
fn mersenne_twister() {
    assert_eq!(
        rng::MersenneTwister::new(0).take(7).collect::<Vec<u32>>(),
        [2357136044, 2546248239, 3071714933, 3626093760, 2588848963, 3684848379, 2340255427]
    );
}
```


### Challenge 3-22: Crack an MT19937 seed

[Challenge link](https://cryptopals.com/sets/3/challenges/22)

This is pretty simple if you have an idea when the program started. It's pretty
quick to start iterating from then until we find the seed that returns the
observed number.

```rust
#[test]
fn crack_mersenne() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use std::thread;

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

    let seed = (program_start..).find(|&seed| {
        let mut mt = rng::MersenneTwister::new(seed);
        mt.next() == observed_number
    }).unwrap();

    assert_eq!(
        rng::MersenneTwister::new(seed).next(),
        observed_number,
    );
}
```


### Challenge 3-23: Clone an MT19937 RNG from its output

[Challenge link](https://cryptopals.com/sets/3/challenges/23)

This one was a lot harder than I anticipated, and I'm still not sure I fully
understand how it works. I heavily relied on [this blog post](https://blog.ollien.com/posts/reverse-mersenne-twister/)
to get the code working and gain *some* intuition. The bit patterns in the
examples were great.

```rust
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
```


### Challenge 3-24: Create the MT19937 stream cipher and break it

[Challenge link](https://cryptopals.com/sets/3/challenges/24)

I wasn't too sure what this one was asking, but it was mostly brute-forcing by
taking educated guesses. The password reset token one was fun though, and it's
neat to crack something and then be able to generate your own token whenever
you want (if this were a real system). As mentioned previously, my
`into_iter<T>` method came in handy for converting the PRNG into a stream of
bytes, so that was cool.

```rust
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
```


## Set 4: Stream crypto and randomness

### Challenge 4-25: Break "random access read/write" AES CTR

[Challenge link](https://cryptopals.com/sets/4/challenges/25)

The hard part of this challenge was implementing the "edit mode" of the cipher.
I decided to implement it naively to not spend too much time on it. My solution
simply generates the AES CTR stream and skips the offset, which doesn't take
advantage of the fact that you can randomly access different blocks of the
data. I'm still performing AES encryption for every block. Maybe I can make an
`aes_ctr_splice` method which will actually do the random access calculations,
but for now I think it's fine.

```rust
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
```


### Challenge 4-26: CTR bitflipping

[Challenge link](https://cryptopals.com/sets/4/challenges/26)

Another easy one! This one was exactly the same as the [previous bit-flipping
challenge](#challenge-2-16-cbc-bitflipping-attacks) except instead of targeting
the previous block, we target the actual offsets we want to change. It's
actually even easier than CBC bit-flip attacks because we don't need to worry
about destroying other data.

```rust
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
```


### Challenge 4-27: Recover the key from CBC with IV=Key

[Challenge link](https://cryptopals.com/sets/4/challenges/27)

This one was very cool. I had alway heard that using the key for the IV is bad
practice but I neven knew *why*. Following the instructions got me through it,
but I had to stare at [some diagrams](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
before it clicked. We first get a ciphertext chunk **C₀** that is **E(P₀ ⊕
key)**. Then when we decrypt **[C₀, 0, C₀]**, we are given back **[P₀, ?, 0 ⊕
P₀ ⊕ key]**. To get the key is simply XORing **P₀** with **(P₀ ⊕ key)**!

```rust
#[test]
fn cbc_key_iv() {
    let vuln = vuln::cbc_iv::new();

    let cookie = vuln.cookie_for("AAAAAAAAAAAAAAAA").unwrap();
    assert!(cookie.b64_decode().count() >= 3 * aes::BLOCK_SIZE);

    let chunk = cookie.b64_decode().aes_nth_block(0).unwrap();
    // Construct a cookie using [C₀, 0, C₀].
    let bad_cookie: String = [chunk, [0; aes::BLOCK_SIZE], chunk]
        .iter()
        .flatten()
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
```
