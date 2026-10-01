//! N64 ROM header parsing, including the community "Advanced Homebrew ROM
//! Header" convention. All offsets/semantics are sourced from the public
//! N64brew wiki ROM Header page: https://n64brew.dev/wiki/ROM_Header
//!
//! All parsing here expects the ROM data to already be normalized to
//! big-endian.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RomHeader {
    /// Full 4-byte PI BSD DOM1 configuration value (offset 0x00-0x03),
    /// commonly called the "PI timings" or ROM "magic" value. Standard
    /// commercial/homebrew ROMs read 0x80371240 here.
    pub pi_timings: u32,
    pub pi_bsd_dom1_flags: [u8; 3],
    pub clock_rate_raw: u32,
    pub boot_address: u32,
    pub libultra_version_raw: u32,
    pub libultra_version: String,
    pub check_code: u64,
    pub crc1: u32,
    pub crc2: u32,
    pub game_title: String,
    pub category_code: char,
    pub unique_code: String,
    pub destination_code: char,
    pub destination_name: String,
    pub rom_version: u8,
    pub homebrew: Option<HomebrewHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomebrewHeader {
    pub controller1: String,
    pub controller2: String,
    pub controller3: String,
    pub controller4: String,
    pub has_metadata: bool,
    pub uses_rtc: bool,
    pub region_free: bool,
    pub savetype: String,
}

pub fn parse_header(be_data: &[u8]) -> Option<RomHeader> {
    if be_data.len() < 0x40 {
        return None;
    }
    let pi_timings = read_u32(be_data, 0x00);
    let pi_bsd_dom1_flags = [be_data[1], be_data[2], be_data[3]];
    let clock_rate_raw = read_u32(be_data, 0x04);
    let boot_address = read_u32(be_data, 0x08);
    let libultra_version_raw = read_u32(be_data, 0x0C);
    let libultra_version = decode_libultra_version(libultra_version_raw);
    let check_code = read_u64(be_data, 0x10);
    let crc1 = (check_code >> 32) as u32;
    let crc2 = (check_code & 0xFFFF_FFFF) as u32;

    // Read the destination/region code before decoding the title so we can
    // pick GBK (China/iQue) vs Shift-JIS (everywhere else) decoding.
    let destination_code = be_data[0x3E] as char;
    let destination_name = destination_name(destination_code).to_string();

    let title_bytes = &be_data[0x20..0x34];
    let game_title = decode_title(title_bytes, destination_code == 'C');

    let category_code = be_data[0x3B] as char;
    let unique_code = String::from_utf8_lossy(&be_data[0x3C..0x3E]).to_string();
    let rom_version = be_data[0x3F];

    let homebrew = parse_homebrew_header(be_data);

    Some(RomHeader {
        pi_timings,
        pi_bsd_dom1_flags,
        clock_rate_raw,
        boot_address,
        libultra_version_raw,
        libultra_version,
        check_code,
        crc1,
        crc2,
        game_title,
        category_code,
        unique_code,
        destination_code,
        destination_name,
        rom_version,
        homebrew,
    })
}

/// Attempts to decode the Advanced Homebrew ROM Header. This convention
/// reuses bytes normally reserved (0x34-0x3F) and is identified by the ASCII
/// marker "ED" at offset 0x3C.
fn parse_homebrew_header(be_data: &[u8]) -> Option<HomebrewHeader> {
    if be_data.len() < 0x40 {
        return None;
    }
    if &be_data[0x3C..0x3E] != b"ED" {
        return None;
    }
    let controller1 = decode_controller(be_data[0x34]);
    let controller2 = decode_controller(be_data[0x35]);
    let controller3 = decode_controller(be_data[0x36]);
    let controller4 = decode_controller(be_data[0x37]);
    let flags = be_data[0x38];
    let has_metadata = flags & 0x1 != 0;

    let savetype_byte = be_data[0x3F];
    let uses_rtc = savetype_byte & 0x1 != 0;
    let region_free = savetype_byte & 0x2 != 0;
    let savetype_bits = (savetype_byte >> 4) & 0xF;
    let savetype = match savetype_bits {
        0 => "None",
        1 => "4K EEPROM",
        2 => "16K EEPROM",
        3 => "256K SRAM",
        4 => "768K SRAM (banked)",
        5 => "Flash RAM",
        6 => "1M SRAM",
        _ => "Unknown",
    }
    .to_string();

    Some(HomebrewHeader { controller1, controller2, controller3, controller4, has_metadata, uses_rtc, region_free, savetype })
}

fn decode_controller(byte: u8) -> String {
    match byte {
        0x00 => "No information provided".to_string(),
        0xFF => "Nothing attached".to_string(),
        0x80 => "N64 mouse".to_string(),
        0x81 => "VRU".to_string(),
        0x82 => "GameCube controller".to_string(),
        0x83 => "Randnet keyboard".to_string(),
        0x84 => "GameCube keyboard".to_string(),
        0x01..=0x7F => {
            let mut parts = vec!["N64 controller".to_string()];
            if byte & 0x01 != 0 {
                parts.push("+ Rumble Pak".to_string());
            }
            if byte & 0x02 != 0 {
                parts.push("+ Controller Pak".to_string());
            }
            if byte & 0x04 != 0 {
                parts.push("+ Transfer Pak".to_string());
            }
            parts.join(" ")
        }
        _ => format!("Unknown (0x{:02X})", byte),
    }
}

fn decode_libultra_version(raw: u32) -> String {
    let major_minor = ((raw >> 8) & 0xFF) as u8;
    let revision = (raw & 0xFF) as u8;
    if major_minor == 0 {
        return "Unknown".to_string();
    }
    let major = major_minor / 10;
    let minor = major_minor % 10;
    let rev_char = if revision.is_ascii_alphabetic() { revision as char } else { '\0' };
    if rev_char != '\0' {
        format!("{}.{}{}", major, minor, rev_char)
    } else {
        format!("{}.{}", major, minor)
    }
}

fn decode_title(bytes: &[u8], prefer_gbk: bool) -> String {
    // Titles are documented as ASCII or JIS X 0201 (a Shift-JIS subset);
    // China/iQue titles are conventionally GBK instead. See `crate::cjk`.
    crate::cjk::decode_cjk_field(bytes, prefer_gbk)
}

fn destination_name(code: char) -> &'static str {
    match code {
        'A' => "All",
        'B' => "Brazil",
        'C' => "China / iQue",
        'D' => "Germany",
        'E' => "North America",
        'F' => "France",
        'G' => "Gateway 64 (NTSC)",
        'H' => "Netherlands",
        'I' => "Italy",
        'J' => "Japan",
        'K' => "Korea",
        'L' => "Gateway 64 (PAL)",
        'N' => "Canada",
        'P' => "Europe",
        'S' => "Spain",
        'U' => "Australia",
        'W' => "Scandinavia",
        'X' | 'Y' | 'Z' => "Europe",
        '\0' => "Region-free / unspecified",
        _ => "Unknown",
    }
}

pub fn category_name(code: char) -> &'static str {
    match code {
        'N' => "Game Pak (cartridge)",
        'D' => "64DD Disk",
        'C' => "Expandable Game: Game Pak Part",
        'E' => "Expandable Game: 64DD Disk Part",
        'Z' => "Aleck64 Game Pak (arcade)",
        _ => "Unknown",
    }
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Writes new CRC1/CRC2 values into the header's check-code field
/// (offset 0x10..0x18) of big-endian normalized ROM data, in place. Used
/// after patching the IPL3 boot code so the header matches the newly
/// computed checksum for whatever CIC the new boot code pairs with.
pub fn write_crc(be_data: &mut [u8], crc1: u32, crc2: u32) {
    if be_data.len() < 0x18 {
        return;
    }
    be_data[0x10..0x14].copy_from_slice(&crc1.to_be_bytes());
    be_data[0x14..0x18].copy_from_slice(&crc2.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_header(homebrew: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 0x1000];
        buf[0] = 0x80;
        buf[1] = 0x37;
        buf[2] = 0x12;
        buf[3] = 0x40;
        buf[4..8].copy_from_slice(&0x0000_000Fu32.to_be_bytes());
        buf[8..12].copy_from_slice(&0x8000_1000u32.to_be_bytes());
        buf[12..16].copy_from_slice(&[0x00, 0x00, 0x14, 0x4C]); // libultra 2.0L
        buf[0x10..0x18].copy_from_slice(&0xDEADBEEF_CAFEBABEu64.to_be_bytes());
        buf[0x20..0x2D].copy_from_slice(b"TURTLE64 TEST");
        buf[0x3B] = b'N';
        buf[0x3C] = b'T';
        buf[0x3D] = b'T';
        buf[0x3E] = b'E';
        buf[0x3F] = 0x00;

        if homebrew {
            buf[0x34] = 0x02; // controller pak
            buf[0x38] = 0x01; // has metadata
            buf[0x3C] = b'E';
            buf[0x3D] = b'D';
            buf[0x3E] = b'E'; // unused when homebrew marker occupies 0x3C-3D
            buf[0x3F] = 0b0010_0010; // region free + savetype 16K EEPROM (2<<4 | 0x2)
        }
        buf
    }

    #[test]
    fn parses_basic_header_fields() {
        let buf = synthetic_header(false);
        let header = parse_header(&buf).expect("header should parse");
        assert_eq!(header.game_title, "TURTLE64 TEST");
        assert_eq!(header.boot_address, 0x8000_1000);
        assert_eq!(header.libultra_version, "2.0L");
        assert_eq!(header.crc1, 0xDEADBEEF);
        assert_eq!(header.crc2, 0xCAFEBABE);
        assert_eq!(header.category_code, 'N');
        assert!(header.homebrew.is_none());
    }

    #[test]
    fn parses_homebrew_header() {
        let buf = synthetic_header(true);
        let header = parse_header(&buf).expect("header should parse");
        let hb = header.homebrew.expect("homebrew header expected");
        assert_eq!(hb.controller1, "N64 controller + Controller Pak");
        assert!(hb.has_metadata);
        assert!(hb.region_free);
        assert_eq!(hb.savetype, "16K EEPROM");
    }

    #[test]
    fn parses_aleck64_and_ique_destinations() {
        assert_eq!(category_name('Z'), "Aleck64 Game Pak (arcade)");
        assert_eq!(destination_name('C'), "China / iQue");
    }

    #[test]
    fn decodes_gbk_title_for_china_destination() {
        let mut buf = synthetic_header(false);
        // GBK encoding of "中文" (Chinese), padded with 0x20 like a real title.
        buf[0x20..0x24].copy_from_slice(&[0xD6, 0xD0, 0xCE, 0xC4]);
        buf[0x24..0x34].fill(0x20);
        buf[0x3E] = b'C'; // China / iQue destination code
        let header = parse_header(&buf).expect("header should parse");
        assert_eq!(header.game_title, "中文");
    }
}
