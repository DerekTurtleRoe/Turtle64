//! ROM byte-order detection and conversion.
//!
//! N64 ROM dumps circulate in three different byte orderings depending on the
//! dumping hardware/method used back in the day:
//!   - Big-endian      (`.z64`, "native"): bytes appear in the same order the
//!     N64 CPU reads them. Header magic: `80 37 12 40`.
//!   - Byte-swapped     (`.v64`, "byteswapped"): every pair of bytes is swapped.
//!     Header magic: `37 80 40 12`.
//!   - Little-endian    (`.n64`, "little endian"): every group of 4 bytes is
//!     reversed. Header magic: `40 12 37 80`.
//!
//! Detection is always performed by inspecting the first 4 bytes of the file
//! itself (the IPL2 "magic" configuration bytes), never by file extension.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RomFormat {
    /// Big-endian, native format, ".z64"
    BigEndian,
    /// Byte-swapped (every 2 bytes swapped), ".v64"
    ByteSwapped,
    /// Little-endian (every 4 bytes reversed), ".n64"
    LittleEndian,
    /// Header magic did not match any known pattern.
    Unknown,
}

impl RomFormat {
    pub fn label(&self) -> &'static str {
        match self {
            RomFormat::BigEndian => "Big-endian (.z64)",
            RomFormat::ByteSwapped => "Byte-swapped (.v64)",
            RomFormat::LittleEndian => "Little-endian (.n64)",
            RomFormat::Unknown => "Unknown / unrecognized",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            RomFormat::BigEndian => "z64",
            RomFormat::ByteSwapped => "v64",
            RomFormat::LittleEndian => "n64",
            RomFormat::Unknown => "bin",
        }
    }

    pub fn all_targets() -> [RomFormat; 3] {
        [RomFormat::BigEndian, RomFormat::ByteSwapped, RomFormat::LittleEndian]
    }
}

impl std::fmt::Display for RomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Detects the byte ordering of raw ROM bytes by examining the first 4 bytes
/// (or at offset 0x20 if a 32-byte iQue header is prepended).
#[allow(dead_code)]
pub fn detect_format(data: &[u8]) -> RomFormat {
    let (fmt, _, _) = detect_format_and_offset(data);
    fmt
}

/// Detects the byte ordering and whether a 32-byte iQue container header
/// precedes the standard N64 header. Returns `(format, payload_offset, has_ique_header)`.
pub fn detect_format_and_offset(data: &[u8]) -> (RomFormat, usize, bool) {
    if data.len() < 4 {
        return (RomFormat::Unknown, 0, false);
    }
    // Check offset 0 first
    match &data[0..4] {
        [0x80, 0x37, 0x12, 0x40] | [0x80, 0x27, 0x07, 0x40] => {
            return (RomFormat::BigEndian, 0, false);
        }
        [0x37, 0x80, 0x40, 0x12] | [0x27, 0x80, 0x40, 0x07] => {
            return (RomFormat::ByteSwapped, 0, false);
        }
        [0x40, 0x12, 0x37, 0x80] | [0x40, 0x07, 0x27, 0x80] => {
            return (RomFormat::LittleEndian, 0, false);
        }
        _ => {}
    }

    // Check if a 32-byte (0x20) iQue header is prepended
    if data.len() >= 36 {
        match &data[32..36] {
            [0x80, 0x37, 0x12, 0x40] | [0x80, 0x27, 0x07, 0x40] => {
                return (RomFormat::BigEndian, 32, true);
            }
            [0x37, 0x80, 0x40, 0x12] | [0x27, 0x80, 0x40, 0x07] => {
                return (RomFormat::ByteSwapped, 32, true);
            }
            [0x40, 0x12, 0x37, 0x80] | [0x40, 0x07, 0x27, 0x80] => {
                return (RomFormat::LittleEndian, 32, true);
            }
            _ => {}
        }
    }

    let fmt = heuristic_detect(data);
    (fmt, 0, false)
}

/// Fallback heuristic for ROMs that don't ship the "standard" magic bytes
/// (e.g. replica carts / tuned PI timings). We look at all 4 possible
/// rotations of the byte pattern and additionally sanity check header fields
/// that are expected to look "reasonable" once normalized (e.g. boot address
/// living in the 0x8000_0000..0x8100_0000 RDRAM range).
fn heuristic_detect(data: &[u8]) -> RomFormat {
    if data.len() < 0x40 {
        return RomFormat::Unknown;
    }
    for fmt in [RomFormat::BigEndian, RomFormat::ByteSwapped, RomFormat::LittleEndian] {
        let normalized = to_big_endian(&data[0..0x40], fmt);
        let boot = u32::from_be_bytes(normalized[8..12].try_into().unwrap());
        if (0x8000_0000..0x8100_0000).contains(&boot) {
            return fmt;
        }
    }
    RomFormat::Unknown
}

/// Converts a buffer from the given source format into canonical big-endian.
pub fn to_big_endian(data: &[u8], from: RomFormat) -> Vec<u8> {
    match from {
        RomFormat::BigEndian | RomFormat::Unknown => data.to_vec(),
        RomFormat::ByteSwapped => swap_2(data),
        RomFormat::LittleEndian => swap_4(data),
    }
}

/// Converts a canonical big-endian buffer into the requested target format.
pub fn from_big_endian(data: &[u8], to: RomFormat) -> Vec<u8> {
    match to {
        RomFormat::BigEndian | RomFormat::Unknown => data.to_vec(),
        RomFormat::ByteSwapped => swap_2(data),
        RomFormat::LittleEndian => swap_4(data),
    }
}

/// Directly converts a buffer from one format to another via a big-endian
/// intermediate representation.
#[allow(dead_code)]
pub fn convert(data: &[u8], from: RomFormat, to: RomFormat) -> Vec<u8> {
    let be = to_big_endian(data, from);
    from_big_endian(&be, to)
}

fn swap_2(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let chunks = out.len() / 2;
    for i in 0..chunks {
        out.swap(i * 2, i * 2 + 1);
    }
    out
}

fn swap_4(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let chunks = out.len() / 4;
    for i in 0..chunks {
        let base = i * 4;
        out.swap(base, base + 3);
        out.swap(base + 1, base + 2);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_byteswap() {
        let be = vec![0x80, 0x37, 0x12, 0x40, 0x00, 0x00, 0x00, 0x0F];
        let v64 = to_big_endian(&be, RomFormat::BigEndian); // identity check
        assert_eq!(v64, be);

        let swapped = from_big_endian(&be, RomFormat::ByteSwapped);
        assert_eq!(swapped, vec![0x37, 0x80, 0x40, 0x12, 0x00, 0x00, 0x0F, 0x00]);
        let back = to_big_endian(&swapped, RomFormat::ByteSwapped);
        assert_eq!(back, be);

        let little = from_big_endian(&be, RomFormat::LittleEndian);
        assert_eq!(little, vec![0x40, 0x12, 0x37, 0x80, 0x0F, 0x00, 0x00, 0x00]);
        let back2 = to_big_endian(&little, RomFormat::LittleEndian);
        assert_eq!(back2, be);
    }

    #[test]
    fn detects_all_formats() {
        let be = [0x80u8, 0x37, 0x12, 0x40];
        let sw = [0x37u8, 0x80, 0x40, 0x12];
        let le = [0x40u8, 0x12, 0x37, 0x80];
        assert_eq!(detect_format(&be), RomFormat::BigEndian);
        assert_eq!(detect_format(&sw), RomFormat::ByteSwapped);
        assert_eq!(detect_format(&le), RomFormat::LittleEndian);
    }

    #[test]
    fn detects_ique_header_offset() {
        let mut ique_data = vec![0u8; 32];
        ique_data.extend_from_slice(&[0x80, 0x37, 0x12, 0x40]);
        let (fmt, offset, has_ique) = detect_format_and_offset(&ique_data);
        assert_eq!(fmt, RomFormat::BigEndian);
        assert_eq!(offset, 32);
        assert!(has_ique);
    }
}
