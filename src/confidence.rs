//! Heuristic "how likely is this a good dump?" estimate.
//!
//! This is purely informational and an *educated guess*: it only looks at
//! whether header fields look sane, whether the header CRCs match the ROM
//! contents, and whether the ROM is in a loaded No-Intro DAT. A ROM can look
//! perfect and still be a bad dump (or look odd and be a legitimate homebrew
//! or prototype), so only a No-Intro match should be treated as conclusive.

use crate::checksum::PiTimingsStatus;
use crate::dat::VerificationStatus;
use crate::header::RomHeader;
use crate::rom::RomInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Valid / as expected.
    Good,
    /// Unusual, non-standard, or could not be fully checked.
    Warn,
    /// Missing, invalid, or contradicting the rest of the ROM.
    Bad,
    /// Not applicable (e.g. no DAT loaded); excluded from scoring.
    Unknown,
}

impl Severity {
    fn points(self) -> Option<f32> {
        match self {
            Severity::Good => Some(1.0),
            Severity::Warn => Some(0.5),
            Severity::Bad => Some(0.0),
            Severity::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

impl ConfidenceLevel {
    pub fn label(self) -> &'static str {
        match self {
            ConfidenceLevel::VeryHigh => "Very high confidence",
            ConfidenceLevel::High => "High confidence",
            ConfidenceLevel::Medium => "Medium confidence",
            ConfidenceLevel::Low => "Low confidence",
            ConfidenceLevel::VeryLow => "Very low confidence",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldCheck {
    pub name: &'static str,
    pub severity: Severity,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct Assessment {
    pub checks: Vec<FieldCheck>,
    pub level: ConfidenceLevel,
    /// Weighted score in `0.0..=1.0`, a rough heuristic and not a true probability.
    pub score: f32,
}

pub const DISCLAIMER: &str = "This is only an educated guess based on header sanity checks, CRC1/CRC2, and No-Intro matching. \
     It is not proof: a ROM can pass every check and still be corrupted, and unusual ROMs (homebrew, prototypes, hacks) \
     may score low while being perfectly fine. Only a No-Intro match is a reliable verification.";

impl Assessment {
    pub fn severity_of(&self, name: &str) -> Severity {
        self.checks.iter().find(|c| c.name == name).map(|c| c.severity).unwrap_or(Severity::Unknown)
    }
}

pub fn assess(rom: &RomInfo) -> Assessment {
    assess_parts(rom.header.as_ref(), rom.pi_timings_status, rom.checksum_valid, &rom.verification)
}

fn check(name: &'static str, severity: Severity, note: impl Into<String>) -> FieldCheck {
    FieldCheck { name, severity, note: note.into() }
}

pub fn assess_parts(
    header: Option<&RomHeader>,
    pi_status: Option<PiTimingsStatus>,
    checksum_valid: Option<bool>,
    verification: &VerificationStatus,
) -> Assessment {
    let mut checks = Vec::new();

    match header {
        Some(h) => {
            checks.push(check_title(&h.game_title));
            checks.push(check_game_code(h));
            checks.push(check_region(h));
            checks.push(check_version(h.rom_version));
        }
        None => {
            for name in ["Game title", "Game code", "Region", "ROM version"] {
                checks.push(check(name, Severity::Bad, "Header missing (ROM too small)"));
            }
        }
    }

    checks.push(match pi_status {
        Some(PiTimingsStatus::Standard) | Some(PiTimingsStatus::Cic8303Variant) => check("PI timings", Severity::Good, "Standard value"),
        Some(PiTimingsStatus::NonStandard) => check("PI timings", Severity::Warn, "Non-standard value"),
        None => check("PI timings", Severity::Bad, "Header missing"),
    });

    checks.push(match checksum_valid {
        Some(true) => check("CRC1 / CRC2", Severity::Good, "Calculated values match the header"),
        Some(false) => check("CRC1 / CRC2", Severity::Bad, "Calculated values do NOT match the header"),
        None => check("CRC1 / CRC2", Severity::Warn, "Could not be calculated (unrecognized CIC or truncated ROM)"),
    });

    checks.push(match verification {
        VerificationStatus::GoodDump { .. } => check("No-Intro", Severity::Good, "Matches a verified dump"),
        VerificationStatus::BadDump { .. } => check("No-Intro", Severity::Bad, "Matches an entry but a stronger hash disagrees"),
        VerificationStatus::NotInDatabase => check("No-Intro", Severity::Warn, "Not found in the loaded DAT(s)"),
        VerificationStatus::NoDatLoaded => check("No-Intro", Severity::Unknown, "No DAT loaded; not counted"),
    });

    let (mut sum, mut total) = (0.0f32, 0.0f32);
    for c in &checks {
        if let Some(p) = c.severity.points() {
            let weight = match c.name {
                "No-Intro" => 3.0,
                "CRC1 / CRC2" => 2.0,
                _ => 1.0,
            };
            sum += p * weight;
            total += weight;
        }
    }
    let score = if total > 0.0 { sum / total } else { 0.0 };

    let mut level = match score {
        s if s >= 0.90 => ConfidenceLevel::VeryHigh,
        s if s >= 0.75 => ConfidenceLevel::High,
        s if s >= 0.55 => ConfidenceLevel::Medium,
        s if s >= 0.35 => ConfidenceLevel::Low,
        _ => ConfidenceLevel::VeryLow,
    };

    // A contradicting CRC or hash is strong evidence of corruption, so it caps the result.
    let cap = |level: &mut ConfidenceLevel, max: ConfidenceLevel| *level = (*level).min(max);
    if checksum_valid == Some(false) {
        cap(&mut level, ConfidenceLevel::Low);
    }
    if matches!(verification, VerificationStatus::BadDump { .. }) {
        cap(&mut level, ConfidenceLevel::VeryLow);
    }

    Assessment { checks, level, score }
}

fn check_title(title: &str) -> FieldCheck {
    let trimmed = title.trim_matches(|c: char| c == ' ' || c == '\0');
    if trimmed.is_empty() {
        check("Game title", Severity::Bad, "Empty")
    } else if trimmed.chars().any(|c| c.is_control() || c == '\u{FFFD}') {
        check("Game title", Severity::Bad, "Contains invalid or undecodable characters")
    } else {
        check("Game title", Severity::Good, "Present and readable")
    }
}

fn check_game_code(h: &RomHeader) -> FieldCheck {
    let unique_ok = h.unique_code.len() == 2 && h.unique_code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    match h.category_code {
        'N' | 'C' | 'Z' if h.unique_code == "ED" => check("Game code", Severity::Warn, "Homebrew \"ED\" marker, not a licensed game code"),
        'N' | 'C' | 'Z' if unique_ok => check("Game code", Severity::Good, "Valid category and ID"),
        'N' | 'C' | 'Z' => check("Game code", Severity::Bad, "Game ID is not two letters/digits"),
        'D' | 'E' if unique_ok => check("Game code", Severity::Warn, "64DD category on a cartridge ROM"),
        _ => check("Game code", Severity::Bad, "Unknown category or invalid game ID"),
    }
}

fn check_region(h: &RomHeader) -> FieldCheck {
    match h.destination_name.as_str() {
        "Unknown" => check("Region", Severity::Bad, "Unrecognized region code"),
        "Region-free / unspecified" => check("Region", Severity::Warn, "Unspecified (common for homebrew)"),
        _ => check("Region", Severity::Good, "Recognized region code"),
    }
}

fn check_version(version: u8) -> FieldCheck {
    match version {
        0..=9 => check("ROM version", Severity::Good, "Plausible version"),
        10..=0x7F => check("ROM version", Severity::Warn, "Unusually high version"),
        _ => check("ROM version", Severity::Bad, "Implausible version byte"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::parse_header;

    fn header_bytes(title: &[u8], cat: u8, uid: &[u8; 2], region: u8, version: u8) -> RomHeader {
        let mut d = vec![0u8; 0x40];
        d[..4].copy_from_slice(&0x8037_1240u32.to_be_bytes());
        d[0x20..0x20 + title.len()].copy_from_slice(title);
        d[0x3B] = cat;
        d[0x3C..0x3E].copy_from_slice(uid);
        d[0x3E] = region;
        d[0x3F] = version;
        parse_header(&d).unwrap()
    }

    fn good(name: &str) -> VerificationStatus {
        VerificationStatus::GoodDump { game_name: name.into() }
    }

    #[test]
    fn everything_valid_is_very_high() {
        let h = header_bytes(b"SUPER TEST", b'N', b"AB", b'E', 0);
        let a = assess_parts(Some(&h), Some(PiTimingsStatus::Standard), Some(true), &good("x"));
        assert_eq!(a.level, ConfidenceLevel::VeryHigh);
        assert!(a.checks.iter().all(|c| c.severity == Severity::Good));
    }

    #[test]
    fn a_few_bad_fields_is_medium() {
        let h = header_bytes(b"", b'N', b"AB", b'!', 0xFF);
        let a = assess_parts(Some(&h), Some(PiTimingsStatus::Standard), Some(true), &VerificationStatus::NoDatLoaded);
        assert_eq!(a.severity_of("Game title"), Severity::Bad);
        assert_eq!(a.severity_of("Region"), Severity::Bad);
        assert_eq!(a.severity_of("ROM version"), Severity::Bad);
        assert_eq!(a.level, ConfidenceLevel::Medium);
    }

    #[test]
    fn many_problems_is_very_low() {
        let a = assess_parts(None, None, None, &VerificationStatus::NotInDatabase);
        assert_eq!(a.level, ConfidenceLevel::VeryLow);
    }

    #[test]
    fn crc_mismatch_caps_confidence() {
        let h = header_bytes(b"SUPER TEST", b'N', b"AB", b'E', 0);
        let a = assess_parts(Some(&h), Some(PiTimingsStatus::Standard), Some(false), &good("x"));
        assert!(a.level <= ConfidenceLevel::Low);
    }

    #[test]
    fn nonstandard_and_homebrew_are_warnings() {
        let h = header_bytes(b"HOMEBREW", b'N', b"ED", b'\0', 0);
        let a = assess_parts(Some(&h), Some(PiTimingsStatus::NonStandard), Some(true), &VerificationStatus::NotInDatabase);
        assert_eq!(a.severity_of("Game code"), Severity::Warn);
        assert_eq!(a.severity_of("Region"), Severity::Warn);
        assert_eq!(a.severity_of("PI timings"), Severity::Warn);
        assert_eq!(a.severity_of("No-Intro"), Severity::Warn);
    }

    #[test]
    fn bad_dump_is_very_low() {
        let h = header_bytes(b"SUPER TEST", b'N', b"AB", b'E', 0);
        let v = VerificationStatus::BadDump { game_name: "x".into() };
        let a = assess_parts(Some(&h), Some(PiTimingsStatus::Standard), Some(true), &v);
        assert_eq!(a.level, ConfidenceLevel::VeryLow);
    }
}
