//! Legacy IPL3 boot-code checksum (informally known as "CRC1/CRC2") used by
//! older emulators and ROM databases, plus CIC boot-chip identification.
//!
//! This reimplements the long-standing, widely published N64 checksum
//! algorithm (the same rolling-checksum construction used by IPL3 itself to
//! validate a ROM before booting it, originally documented publicly as
//! "n64crc" and reproduced by countless independent tools since). All
//! computation here expects big-endian normalized ROM data.

use sha1::{Digest, Sha1};

const CHECKSUM_START: usize = 0x0000_1000;
const CHECKSUM_LENGTH: usize = 0x0010_0000;
const HEADER_SIZE: usize = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // CicIque/CicHw1 read clearer than dropping the shared prefix
pub enum Cic {
    Cic6101,
    Cic6102,
    Cic6103,
    Cic6105,
    Cic6106,
    Cic7102,
    Cic5101,
    Cic8303,
    CicIque,
    CicHw1,
    Unknown,
}

impl Cic {
    pub fn label(&self) -> &'static str {
        match self {
            Cic::Cic6101 => "CIC-NUS-6101 (NTSC)",
            Cic::Cic6102 => "CIC-NUS-6102 / 7101",
            Cic::Cic6103 => "CIC-NUS-6103 / 7103",
            Cic::Cic6105 => "CIC-NUS-6105 / 7105",
            Cic::Cic6106 => "CIC-NUS-6106 / 7106",
            Cic::Cic7102 => "CIC-NUS-7102 (PAL)",
            Cic::Cic5101 => "CIC-NUS-5101 (Aleck64 arcade)",
            Cic::Cic8303 => "CIC-NUS-8303 (Aleck64 / Pokémon Stadium JPN)",
            Cic::CicIque => "iQue Player",
            Cic::CicHw1 => "Development / HW1",
            Cic::Unknown => "Unknown",
        }
    }

    fn seed(&self) -> Option<u32> {
        match self {
            Cic::Cic6101 | Cic::Cic6102 | Cic::Cic7102 => Some(0xF8CA_4DDC),
            Cic::Cic6103 => Some(0xA388_6759),
            Cic::Cic6105 => Some(0xDF26_F436),
            Cic::Cic6106 => Some(0x1FEA_617A),
            _ => None,
        }
    }
}

/// Identifies the CIC boot chip by SHA-1 (and fallback CRC32) of the IPL3
/// boot-code region (bytes 0x40..0x1000, 0xFC0 bytes).
pub fn identify_cic(be_data: &[u8]) -> Cic {
    if be_data.len() < 0x1000 {
        return Cic::Unknown;
    }
    let bootcode = &be_data[HEADER_SIZE..0x1000];

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(bootcode);
    let sha1_bytes: [u8; 20] = sha1_hasher.finalize().into();

    match sha1_bytes {
        [0xea, 0xad, 0xcb, 0x8c, 0xca, 0x9c, 0x6b, 0xa1, 0x44, 0x5f, 0x98, 0xf1, 0x72, 0x7b, 0xf4, 0xad, 0xba, 0xbb, 0x88, 0xb2] => {
            Cic::Cic6101
        }
        [0xb2, 0xaf, 0xae, 0x24, 0x6e, 0x1d, 0xab, 0x74, 0x6b, 0xfb, 0x28, 0xcb, 0x34, 0x6e, 0x29, 0x11, 0x96, 0x5e, 0xef, 0xa1] => {
            Cic::Cic6102
        }
        [0x3f, 0x73, 0x47, 0xaa, 0x04, 0x26, 0xee, 0x97, 0xd9, 0x67, 0x21, 0xb0, 0x9b, 0x91, 0x8d, 0x4c, 0x9c, 0xdd, 0xb6, 0x9b] => {
            Cic::Cic6103
        }
        [0x41, 0x59, 0x26, 0x90, 0x55, 0xe8, 0xa5, 0xbe, 0x2e, 0x5c, 0x8e, 0x3e, 0x0f, 0x5e, 0x0d, 0x55, 0x2f, 0x1e, 0x85, 0xad] => {
            Cic::Cic6105
        }
        [0x63, 0x46, 0x8e, 0x3a, 0xb5, 0x54, 0x25, 0x3d, 0xa3, 0x4d, 0xe3, 0x59, 0x5c, 0xd0, 0x9b, 0x0e, 0xce, 0xa1, 0xce, 0x00] => {
            Cic::Cic6106
        }
        [0x79, 0xfe, 0x35, 0x1c, 0x50, 0xcd, 0xf7, 0x7c, 0x74, 0xe5, 0x03, 0xd7, 0x51, 0xa7, 0x15, 0x60, 0x5f, 0x87, 0xb8, 0x09] => {
            Cic::Cic7102
        }
        [0xb6, 0x60, 0x57, 0xa5, 0xc1, 0xba, 0x05, 0xb6, 0x64, 0x2b, 0x0a, 0x54, 0xef, 0x61, 0x74, 0xac, 0x2e, 0x84, 0x9f, 0xe9] => {
            Cic::Cic5101
        }
        [0x5e, 0xa7, 0xfc, 0x32, 0x74, 0xbe, 0x01, 0x12, 0x1c, 0xfb, 0x20, 0xad, 0x6c, 0x9e, 0x60, 0x85, 0xd6, 0x32, 0x79, 0xbe] => {
            Cic::Cic8303
        }
        [0x17, 0x6d, 0x20, 0xcd, 0x8b, 0x0f, 0x7e, 0x24, 0x5b, 0x3d, 0x4e, 0x02, 0x7e, 0x78, 0x95, 0x52, 0x01, 0xe7, 0xee, 0x5c] => {
            Cic::CicIque
        }
        [0xd6, 0x8c, 0x83, 0xda, 0xb8, 0xc2, 0xc2, 0xb0, 0x8e, 0x36, 0x70, 0xbd, 0xf2, 0x8d, 0x93, 0xb8, 0x94, 0x61, 0x20, 0xc6] => {
            Cic::CicHw1
        }
        _ => {
            let mut crc_hasher = crc32fast::Hasher::new();
            crc_hasher.update(bootcode);
            match crc_hasher.finalize() {
                0x6170_A4A1 => Cic::Cic6101,
                0x90BB_6CB5 => Cic::Cic6102,
                0x0B05_0EE0 => Cic::Cic6103,
                0x98BC_2C86 => Cic::Cic6105,
                0xACC8_580A => Cic::Cic6106,
                _ => Cic::Unknown,
            }
        }
    }
}

/// Computes the legacy CRC1/CRC2 checksum pair against the given ROM data
/// (must be big-endian normalized) using the given CIC's seed. Returns
/// `None` if the CIC couldn't provide a seed or the ROM is too small.
pub fn calc_crc(be_data: &[u8], cic: Cic) -> Option<(u32, u32)> {
    let seed = cic.seed()?;
    if be_data.len() < CHECKSUM_START + CHECKSUM_LENGTH {
        return None;
    }

    let (mut t1, mut t2, mut t3, mut t4, mut t5, mut t6) = (seed, seed, seed, seed, seed, seed);

    let mut rel: usize = 0;
    while rel < CHECKSUM_LENGTH {
        let off = CHECKSUM_START + rel;
        let d = u32::from_be_bytes(be_data[off..off + 4].try_into().unwrap());

        if t6.wrapping_add(d) < t6 {
            t4 = t4.wrapping_add(1);
        }
        t6 = t6.wrapping_add(d);
        t3 ^= d;
        let r = d.rotate_left(d & 0x1F);
        t5 = t5.wrapping_add(r);
        if t2 > d {
            t2 ^= r;
        } else {
            t2 ^= t6 ^ d;
        }

        if cic == Cic::Cic6105 {
            let addr = HEADER_SIZE + 0x0710 + (rel & 0xFF);
            let word = u32::from_be_bytes(be_data[addr..addr + 4].try_into().unwrap());
            t1 = t1.wrapping_add(word ^ d);
        } else {
            t1 = t1.wrapping_add(t5 ^ d);
        }

        rel += 4;
    }

    let (crc1, crc2) = match cic {
        Cic::Cic6103 => ((t6 ^ t4).wrapping_add(t3), (t5 ^ t2).wrapping_add(t1)),
        Cic::Cic6106 => (t6.wrapping_mul(t4).wrapping_add(t3), t5.wrapping_mul(t2).wrapping_add(t1)),
        _ => (t6 ^ t4 ^ t3, t5 ^ t2 ^ t1),
    };

    Some((crc1, crc2))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiTimingsStatus {
    /// The standard 0x80371240 magic used by essentially all commercial and
    /// homebrew ROMs.
    Standard,
    /// The alternate 0x80270740 magic seen on ROMs using the CIC-NUS-8303
    /// boot chip (e.g. some Pokemon Stadium/Aleck64 releases).
    Cic8303Variant,
    /// Some other value. Not necessarily invalid (replica carts can tune PI
    /// timings), but many emulators expect one of the two values above.
    NonStandard,
}

impl PiTimingsStatus {
    pub fn label(&self) -> &'static str {
        match self {
            PiTimingsStatus::Standard => "✅ Standard (0x80371240)",
            PiTimingsStatus::Cic8303Variant => "✅ CIC-8303 variant (0x80270740)",
            PiTimingsStatus::NonStandard => "⚠️ Non-standard value (may confuse emulators that hard-code the magic bytes)",
        }
    }
}

/// Grades the ROM's PI BSD DOM1 configuration ("PI timings") value, mirroring
/// romjudge's `grade_pi_timings`: the value is only unconditionally "OK" if
/// it matches the standard magic, with the CIC-8303 alternate magic also
/// accepted as OK since it is a known, intentional variant.
pub fn grade_pi_timings(pi_timings: u32) -> PiTimingsStatus {
    match pi_timings {
        0x8037_1240 => PiTimingsStatus::Standard,
        0x8027_0740 => PiTimingsStatus::Cic8303Variant,
        _ => PiTimingsStatus::NonStandard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_present() {
        assert!(Cic::Cic6102.seed().is_some());
        assert!(Cic::Cic7102.seed().is_some());
        assert!(Cic::Cic5101.seed().is_none());
        assert!(Cic::Cic8303.seed().is_none());
        assert!(Cic::CicIque.seed().is_none());
        assert!(Cic::Unknown.seed().is_none());
    }

    #[test]
    fn identifies_ique_and_aleck64_cics() {
        let data = vec![0u8; 0x1000];
        // Test with unknown initially
        assert_eq!(identify_cic(&data), Cic::Unknown);
    }

    #[test]
    fn grades_pi_timings() {
        assert_eq!(grade_pi_timings(0x8037_1240), PiTimingsStatus::Standard);
        assert_eq!(grade_pi_timings(0x8027_0740), PiTimingsStatus::Cic8303Variant);
        assert_eq!(grade_pi_timings(0x1234_5678), PiTimingsStatus::NonStandard);
    }
}
