use std::u8;

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let res = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16);
        match res {
            Ok(v) => bytes.push(v),
            Err(e) => println!("Problem with hex: {}", e),
        };
    }
    bytes
}

// cryptopals set1 challenge2
// https://cryptopals.com/sets/1/challenges/2
pub fn xor_two_buffers(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (a, b) in buf1.iter().zip(buf2.iter()) {
        bytes.push(a ^ b);
    }
    bytes
}

pub fn english_score(bytes: &[u8]) -> usize {
    let lower = bytes.to_ascii_lowercase();
    // the space at the end here is because spaces are a good sign we've
    // found a real sentence
    b"etaoinshrdlu "
        .iter()
        .map(|c| lower.iter().filter(|&&b| b == *c).count())
        .sum()
}

// cryptopals set1 challenge5
// https://cryptopals.com/sets/1/challenges/5
pub fn repeating_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (a, b) in plaintext.iter().zip(key.iter().cycle()) {
        bytes.push(a ^ b);
    }
    bytes
}

pub fn find_single_byte_key(buf: &[u8]) -> u8 {
    let mut best_key: u8 = 0;
    let mut best_score: usize = 0;
    for i in 0u8..=255 {
        let candidate = xor_two_buffers(buf, &vec![i; buf.len()]);
        let s = english_score(&candidate);
        if s > best_score {
            best_key = i;
            best_score = s;
        }
    }
    best_key
}

pub fn hamming_distance(buf1: &[u8], buf2: &[u8]) -> u32 {
    let xord_buffers = xor_two_buffers(buf1, buf2);
    xord_buffers.iter().map(|b| b.count_ones()).sum()
}

pub fn find_keysize(ciphertext: &[u8]) -> usize {
    let mut best_keysize = 2;
    let mut best_score = f64::MAX;

    for k in 2..=40 {
        let blocks: Vec<&[u8]> = (0..4).map(|i| &ciphertext[i * k..(i + 1) * k]).collect();

        // compute average normalized hamming distance across all pairs of blocks
        // pairs: (0,1), (0,2), (0,3), (1,2), (1,3), (2,3)
        let mut score = (hamming_distance(blocks[0], blocks[1])) as f64 / k as f64;
        score = score + (hamming_distance(blocks[0], blocks[2])) as f64 / k as f64;
        score = score + (hamming_distance(blocks[0], blocks[3])) as f64 / k as f64;
        score = score + (hamming_distance(blocks[1], blocks[2])) as f64 / k as f64;
        score = score + (hamming_distance(blocks[1], blocks[3])) as f64 / k as f64;
        score = score + (hamming_distance(blocks[2], blocks[3])) as f64 / k as f64;
        score = score / 6.0;

        if score < best_score {
            best_score = score;
            best_keysize = k;
        }
    }

    best_keysize
}
