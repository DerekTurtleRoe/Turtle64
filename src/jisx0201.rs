//! Strict ASCII / JIS X 0201 text decoding.
//!
//! Credit: per developer Jhynjhiruu, N64 / iQue / 64DD text fields only ever
//! need ASCII and JIS X 0201 — Shift-JIS and GBK are neither needed nor used,
//! so this module deliberately supports nothing beyond those two sets.
//!
//! Mapping (single byte only):
//! - `0x00..=0x7F` -> ASCII
//! - `0xA1..=0xDF` -> half-width katakana / punctuation (U+FF61..=U+FF9F)
//! - anything else -> U+FFFD (invalid)

/// Decodes a fixed-size, NUL/space-padded text field (ROM header game title,
/// MFS file/volume name, etc).
pub fn decode_field(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .map(|&b| match b {
            0x00..=0x7F => b as char,
            0xA1..=0xDF => char::from_u32(0xFF61 + (b as u32 - 0xA1)).unwrap_or('\u{FFFD}'),
            _ => '\u{FFFD}',
        })
        .collect();
    s.trim_end_matches(['\0', ' ']).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_plain_ascii_unchanged() {
        assert_eq!(decode_field(b"TURTLE64 TEST\0\0"), "TURTLE64 TEST");
    }

    #[test]
    fn decodes_half_width_katakana() {
        assert_eq!(decode_field(&[0xB3, 0xC0, 0x00, 0x00]), "ｳﾀ");
        assert_eq!(decode_field(&[0xA1, 0xDF]), "\u{FF61}\u{FF9F}");
    }

    #[test]
    fn rejects_anything_outside_ascii_and_jisx0201() {
        // 0xD6 0xD0 would be GBK "中" and 0x81 0x40 a Shift-JIS lead byte;
        // neither is supported, so the invalid bytes are marked, not decoded.
        assert_eq!(decode_field(&[0x81, b'A', 0xE0, 0xFF, 0xA0]), "\u{FFFD}A\u{FFFD}\u{FFFD}\u{FFFD}");
    }
}
