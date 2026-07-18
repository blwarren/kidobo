//! Hashing helpers for cache integrity.

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_lower(&digest)
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        output.push(lower_hex_nibble(byte >> 4));
        output.push(lower_hex_nibble(byte));
    }

    output
}

fn lower_hex_nibble(value: u8) -> char {
    match value & 0x0f {
        0..=9 => char::from(b'0' + (value & 0x0f)),
        _ => char::from(b'a' + ((value & 0x0f) - 10)),
    }
}

#[cfg(test)]
mod tests {
    use super::{hex_lower, sha256_hex};

    #[test]
    fn hex_lower_encodes_bytes() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn sha256_hex_is_stable() {
        assert_eq!(
            sha256_hex(b"https://example.com/feed.txt"),
            "8d1ab0f09e05f2372cd064749e63b5f87e8ee05d55affee6dd6826d89bd26931"
        );
    }
}
