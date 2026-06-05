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
pub fn xor_two_buffers(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (a, b) in buf1.iter().zip(buf2.iter()) {
        bytes.push(a ^ b);
    }
    bytes
}

pub fn score(bytes: Vec<u8>) -> usize {
    let lower = bytes.to_ascii_lowercase();
    b"etaoinshrdlu ".iter().map(|c| lower.iter().filter(|&&b| b == *c).count()).sum()
}
