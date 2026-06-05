use crate::primitives::{hex_to_bytes, repeating_xor, score, xor_two_buffers};
use base64::encode;
use std::fs::File;
use std::io::{BufRead, BufReader};

// cryptopals set1 challenge1
// https://cryptopals.com/sets/1/challenges/1
pub fn hex_to_base64(hex: &str) -> String {
    let bytes: Vec<u8> = hex_to_bytes(&hex);
    encode(&bytes)
}

// cryptopals set1 challenge3
// https://cryptopals.com/sets/1/challenges/3
pub fn single_byte_xor_cypher(encoded_bytes: &Vec<u8>) -> Vec<u8> {
    let mut best_match: u8 = 0;
    let mut best_score: usize = 0;
    for i in 0u8..=255u8 as u8 {
        let bytes: Vec<u8> = xor_two_buffers(encoded_bytes, &vec![i; encoded_bytes.len()]);
        let score = score(&bytes);
        if score > best_score {
            best_match = i;
            best_score = score;
        }
    }
    xor_two_buffers(encoded_bytes, &vec![best_match; encoded_bytes.len()])
}

// cryptopals set1 challenge4
// https://cryptopals.com/sets/1/challenges/4
pub fn find_xor_encrypted_string() -> Vec<u8> {
    let mut best_match: Vec<u8> = Vec::new();
    let mut best_score: usize = 0;
    let file = File::open("inputs/set1/challenge4.txt").expect("could not open challenge 4 input");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let decoded = hex_to_bytes(&line.unwrap());
        let candidate = single_byte_xor_cypher(&decoded);
        let score = score(&candidate);
        if score > best_score {
            best_match = candidate;
            best_score = score;
        }
    }
    best_match
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{hex_to_bytes, xor_two_buffers};
    use std::str;

    #[test]
    fn test_part1() {
        let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let output = hex_to_base64(&input);
        let expected =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(output, expected);
    }

    #[test]
    fn test_part2() {
        let input1 = hex_to_bytes("1c0111001f010100061a024b53535009181c");
        let input2 = hex_to_bytes("686974207468652062756c6c277320657965");
        let output = xor_two_buffers(&input1, &input2);
        let expected = hex_to_bytes("746865206b696420646f6e277420706c6179");
        assert_eq!(output, expected);
    }

    #[test]
    fn test_part3() {
        let input =
            hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let output = single_byte_xor_cypher(&input);
        let expected = "Cooking MC's like a pound of bacon";
        assert_eq!(str::from_utf8(&output[..]).unwrap(), expected);
    }

    #[test]
    fn test_part4() {
        let output = find_xor_encrypted_string();
        let expected = "Now that the party is jumping\n";
        assert_eq!(str::from_utf8(&output[..]).unwrap(), expected);
    }

    #[test]
    fn test_part5() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let expected = hex_to_bytes("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
        let key = "ICE";
        let output = repeating_xor(input.as_bytes(), key.as_bytes());
        assert_eq!(output, expected);
    }
}
