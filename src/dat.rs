//! No-Intro (Logiqx-style) DAT file parsing and ROM verification against a
//! loaded database, to classify a ROM as a verified good dump, a known-bad /
//! corrupted dump, or simply unknown / not present in the database.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
#[allow(dead_code)] // rom_name/size/crc32 kept for completeness / future display
pub struct DatEntry {
    pub game_name: String,
    pub rom_name: String,
    pub size: u64,
    pub crc32: Option<u32>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
}

#[derive(Debug, Default)]
pub struct DatDatabase {
    pub name: String,
    pub by_crc32: HashMap<u32, DatEntry>,
    pub entry_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    /// CRC32 (and MD5/SHA1 when available) all match a known-good entry.
    GoodDump { game_name: String },
    /// CRC32 matched an entry but a stronger hash disagreed - likely a
    /// corrupted/modified dump masquerading with a colliding CRC32.
    BadDump { game_name: String },
    /// No DAT entry has this ROM's CRC32 at all.
    NotInDatabase,
    /// No DAT loaded.
    NoDatLoaded,
}

impl DatDatabase {
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::load_from_str(&text)
    }

    pub fn load_from_str(text: &str) -> anyhow::Result<Self> {
        let doc = roxmltree::Document::parse(text)?;
        let root = doc.root_element();

        let name = root
            .descendants()
            .find(|n| n.has_tag_name("header"))
            .and_then(|h| h.children().find(|c| c.has_tag_name("name")))
            .and_then(|n| n.text())
            .unwrap_or("Unknown DAT")
            .to_string();

        let mut by_crc32 = HashMap::new();
        let mut entry_count = 0usize;

        for game in root.children().filter(|n| n.has_tag_name("game") || n.has_tag_name("machine")) {
            let game_name = game.attribute("name").unwrap_or("Unknown").to_string();
            for rom in game.children().filter(|n| n.has_tag_name("rom")) {
                let rom_name = rom.attribute("name").unwrap_or("").to_string();
                let size = rom.attribute("size").and_then(|s| s.parse().ok()).unwrap_or(0);
                let crc32 = rom.attribute("crc").and_then(|s| u32::from_str_radix(s.trim(), 16).ok());
                let md5 = rom.attribute("md5").map(|s| s.to_lowercase());
                let sha1 = rom.attribute("sha1").map(|s| s.to_lowercase());

                let entry = DatEntry { game_name: game_name.clone(), rom_name, size, crc32, md5, sha1 };
                entry_count += 1;
                if let Some(crc) = crc32 {
                    by_crc32.insert(crc, entry);
                }
            }
        }

        Ok(DatDatabase { name, by_crc32, entry_count })
    }

    pub fn verify(&self, crc32: u32, md5: &str, sha1: &str) -> VerificationStatus {
        match self.by_crc32.get(&crc32) {
            None => VerificationStatus::NotInDatabase,
            Some(entry) => {
                let md5_ok = entry.md5.as_deref().map(|e| e == md5).unwrap_or(true);
                let sha1_ok = entry.sha1.as_deref().map(|e| e == sha1).unwrap_or(true);
                if md5_ok && sha1_ok {
                    VerificationStatus::GoodDump { game_name: entry.game_name.clone() }
                } else {
                    VerificationStatus::BadDump { game_name: entry.game_name.clone() }
                }
            }
        }
    }
}

impl VerificationStatus {
    pub fn label(&self) -> String {
        match self {
            VerificationStatus::GoodDump { game_name } => format!("✅ Verified good dump: {game_name}"),
            VerificationStatus::BadDump { game_name } => {
                format!("⚠️ CRC matches \"{game_name}\" but MD5/SHA1 differ (corrupted/modified?)")
            }
            VerificationStatus::NotInDatabase => "❔ Not found in loaded DAT database".to_string(),
            VerificationStatus::NoDatLoaded => "— No DAT database loaded".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DAT: &str = r#"<?xml version="1.0"?>
<datafile>
  <header><name>Nintendo - Nintendo 64 (Test)</name></header>
  <game name="Example Game (USA)">
    <rom name="Example Game (USA).z64" size="8388608" crc="deadbeef" md5="00112233445566778899aabbccddeeff0011223" sha1="00112233445566778899aabbccddeeff0011223344556677889"/>
  </game>
</datafile>"#;

    #[test]
    fn parses_and_matches_good_dump() {
        let db = DatDatabase::load_from_str(SAMPLE_DAT).unwrap();
        assert_eq!(db.entry_count, 1);
        let status =
            db.verify(0xdeadbeef, "00112233445566778899aabbccddeeff0011223", "00112233445566778899aabbccddeeff0011223344556677889");
        assert!(matches!(status, VerificationStatus::GoodDump { .. }));
    }

    #[test]
    fn detects_bad_dump_on_hash_mismatch() {
        let db = DatDatabase::load_from_str(SAMPLE_DAT).unwrap();
        let status = db.verify(0xdeadbeef, "ffffffffffffffffffffffffffffffffffffff", "00112233445566778899aabbccddeeff0011223344556677889");
        assert!(matches!(status, VerificationStatus::BadDump { .. }));
    }

    #[test]
    fn reports_not_in_database() {
        let db = DatDatabase::load_from_str(SAMPLE_DAT).unwrap();
        let status = db.verify(0x1234_5678, "", "");
        assert_eq!(status, VerificationStatus::NotInDatabase);
    }
}
