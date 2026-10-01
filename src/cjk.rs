//! Shared Japanese/Chinese text decoding helpers.
//!
//! N64 cartridge header titles are documented (N64brew wiki) as "usually
//! either ASCII or JIS X 0201 (a subset of Shift-JIS)"; 64DD MFS file names
//! follow the same real-world convention. iQue (China region) titles are
//! conventionally GBK-encoded instead. Rather than special-case the narrow
//! single-byte JIS X 0201 kana range, this decodes the whole field with
//! `encoding_rs`'s full Shift-JIS/GBK decoders, which are supersets of
//! JIS X 0201 / GB2312 respectively and also handle any multi-byte
//! kanji/hanzi a title happens to contain.

use encoding_rs::{GBK, SHIFT_JIS};

/// Decodes a fixed-size, NUL/space-padded text field (ROM header game
/// title, MFS file/volume name, etc).
///
/// `prefer_gbk` should be `true` for China/iQue region data, where Chinese
/// text is conventionally GBK-encoded rather than Shift-JIS; otherwise
/// Shift-JIS (which covers plain ASCII and Japanese half/full-width kana
/// and kanji) is tried first.
pub fn decode_cjk_field(bytes: &[u8], prefer_gbk: bool) -> String {
    // Fast path: plain ASCII can't be misread by either encoding, and
    // avoids any decoder overhead for the overwhelmingly common case.
    if bytes.iter().all(|&b| b < 0x80) {
        return clean(&String::from_utf8_lossy(bytes));
    }

    let (primary, secondary) = if prefer_gbk { (GBK, SHIFT_JIS) } else { (SHIFT_JIS, GBK) };

    let (decoded, _, had_errors) = primary.decode(bytes);
    if !had_errors {
        return clean(&decoded);
    }
    let (decoded, _, had_errors) = secondary.decode(bytes);
    if !had_errors {
        return clean(&decoded);
    }

    // Neither CJK encoding round-tripped cleanly (unusual/garbage bytes);
    // fall back to the historical lossy UTF-8 behavior so something
    // reasonable is still shown instead of an error.
    clean(&String::from_utf8_lossy(bytes))
}

fn clean(s: &str) -> String {
    s.trim_end_matches(['\0', ' ']).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_plain_ascii_unchanged() {
        assert_eq!(decode_cjk_field(b"TURTLE64 TEST\0\0", false), "TURTLE64 TEST");
    }

    #[test]
    fn decodes_shift_jis_half_width_katakana() {
        // Half-width katakana bytes 0xB3 0xC0 are valid JIS X 0201 / Shift-JIS
        // single-byte kana ("ｳ" and "ﾀ"), not plain ASCII/Latin-1 garbage.
        let bytes = [0xB3, 0xC0, 0x00, 0x00];
        let decoded = decode_cjk_field(&bytes, false);
        assert_eq!(decoded, "ｳﾀ");
    }

    #[test]
    fn decodes_gbk_chinese_text_when_preferred() {
        // GBK encoding of "中文" (Chinese).
        let bytes = [0xD6, 0xD0, 0xCE, 0xC4, 0x00];
        let decoded = decode_cjk_field(&bytes, true);
        assert_eq!(decoded, "中文");
    }
}
