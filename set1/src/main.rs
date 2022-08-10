use base64::encode;
use std::fs::File;
use std::io::{ BufRead, BufReader };
use std::str;
use std::u8;

fn main() {
    test_set1();
    test_set2();
    test_set3();
    test_set4();
}

pub fn test_set1() {
    let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let output = hex_to_base64(&input);
    let expected = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    assert_eq!(output, expected);
    println!("Set 1, Challenge 1: Passed!");
}

pub fn test_set2() {
    let input1 = hex_to_bytes("1c0111001f010100061a024b53535009181c");
    let input2 = hex_to_bytes("686974207468652062756c6c277320657965");
    let output = xor_two_buffers(&input1, &input2);
    let expected = hex_to_bytes("746865206b696420646f6e277420706c6179");
    assert_eq!(output, expected);
    println!("Set 1, Challenge 2: Passed!");
}

pub fn test_set3() {
    let input =
        hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let output = single_byte_xor_cypher(&input);
    let expected = "Cooking MC's like a pound of bacon";
    assert_eq!(str::from_utf8(&output[..]).unwrap(), expected);
    println!("Set 1, Challenge 3: Passed!");
}

pub fn test_set4() {
    let result = find_xor_encrypted_string();
    println!("{}", str::from_utf8(&result[..]).unwrap_or("RIP"));
}

// cryptopals set1 challenge1
// https://cryptopals.com/sets/1/challenges/1

// Convert hex to base64
// The string:
// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
// Should produce:
// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
// So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

// Cryptopals Rule
// Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
pub fn hex_to_base64(hex: &str) -> String {
    // Make vector of bytes from octets
    let bytes: Vec<u8> = hex_to_bytes(&hex);
    encode(&bytes) // now convert from Vec<u8> to b64-encoded String
}

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

// Fixed XOR
// Write a function that takes two equal-length buffers and produces their XOR combination.
// If your function works properly, then when you feed it the string:
// 1c0111001f010100061a024b53535009181c
// ... after hex decoding, and when XOR'd against:
// 686974207468652062756c6c277320657965
// ... should produce:
// 746865206b696420646f6e277420706c6179
pub fn xor_two_buffers(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (a, b) in buf1.iter().zip(buf2.iter()) {
        bytes.push(a ^ b);
    }
    bytes
}

// cryptopals set1 challenge3
// https://cryptopals.com/sets/1/challenges/3

// Single-byte XOR cipher
// The hex encoded string:
// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
// ... has been XOR'd against a single character. Find the key, decrypt the message.
// You can do this by hand. But don't: write code to do it for you.
// How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
pub fn single_byte_xor_cypher(encoded_bytes: &Vec<u8>) -> Vec<u8> {
    let mut best_match: u8 = 0;
    let mut best_score: usize = 0;
    for i in 0..128 as u8 {
        let bytes: Vec<u8> = xor_two_buffers(encoded_bytes, &vec![i; encoded_bytes.len()]);
        let score = score(&bytes);
        if score < best_score || best_score == 0 {
            best_match = i;
            best_score = score;
        }
    }
    //println!("We think the best match is: {}", best_match as char);
    xor_two_buffers(encoded_bytes, &vec![best_match; encoded_bytes.len()])
}

pub fn score(bytes: &Vec<u8>) -> usize {
    //bytes.iter().filter(|&&x| x as char == ' ').count()
    let mut meme = bytes.clone().to_ascii_lowercase();
    let mut score: usize = 0;
    meme.sort();
    let top_letters: [u8; 12] = [101, 116, 97, 111, 105, 110, 115, 104, 114, 100, 108, 117];
    for l in top_letters {
        score += meme.iter().position(|&x| x == l).unwrap_or(meme.len() * 2);
    }
    score
}

// cryptopals set1 challenge4
// https://cryptopals.com/sets/1/challenges/4

// Detect single-character XOR
// One of the 60-character strings in this file has been encrypted by single-character XOR.
// Find it.
// (Your code from #3 should help.)
pub fn find_xor_encrypted_string() -> Vec<u8> {
    let mut best_match: Vec<u8> = Vec::new();
    let mut best_score: usize = 0;
    let file = File::open("D:\\rust-projects\\cryptopals\\set1\\challenge_4.txt").expect("I am in literal hell");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let meme = single_byte_xor_cypher(&line.unwrap().into_bytes());
        let score = score(&meme);
        if score > best_score {
            best_match = meme;
            best_score = score;
        }
    }
    best_match
}
