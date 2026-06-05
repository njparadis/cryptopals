use base64::encode;
use crate::primitives::{hex_to_bytes, xor_two_buffers, score};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{hex_to_bytes, xor_two_buffers};
    use std::str;

    #[test]
    fn test_set1() {
        let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let output = hex_to_base64(&input);
        let expected = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(output, expected);
    }

    #[test]
    fn test_set2() {
        let input1 = hex_to_bytes("1c0111001f010100061a024b53535009181c");
        let input2 = hex_to_bytes("686974207468652062756c6c277320657965");
        let output = xor_two_buffers(&input1, &input2);
        let expected = hex_to_bytes("746865206b696420646f6e277420706c6179");
        assert_eq!(output, expected);
    }

    #[test]
    fn test_set3() {
        let input =
            hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let output = single_byte_xor_cypher(&input);
        let expected = "Cooking MC's like a pound of bacon";
        assert_eq!(str::from_utf8(&output[..]).unwrap(), expected);
    }
}
