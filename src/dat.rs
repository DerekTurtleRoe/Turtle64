//! No-Intro (Logiqx-style) DAT file parsing and ROM verification against a
//! loaded database, to classify a ROM as a verified good dump, a known-bad /
//! corrupted dump, or simply unknown / not present in the database.
//!
//! Turtle64 can hold several DAT files loaded at once, one per [`DatKind`] —
//! matching the separate DAT files No-Intro publishes for N64 cartridge ROMs
//! (BigEndian / ByteSwapped), 64DD disks, iQue, and Aleck64 arcade dumps.
//! There is deliberately **no** automatic or scripted download of these DAT
//! files: No-Intro's DAT-o-MATIC site explicitly bans automated/bot access
//! in its terms of service (and bans the requesting IP on detection), so the
//! "check for updates" feature here only ever re-reads already-downloaded
//! DAT files from disk — no network access is ever performed by Turtle64.

use crate::hashes::RomHashes;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    /// The DAT's own `<header><version>` text, e.g. `20240315-120000`.
    /// No-Intro bumps this every time a DAT is regenerated, so it's the
    /// simplest way to tell whether a re-downloaded file is newer.
    pub version: Option<String>,
    /// The DAT's own `<header><date>` text, when present (some DAT
    /// generators use `<date>` instead of/alongside `<version>`).
    pub date: Option<String>,
    pub by_crc32: HashMap<u32, DatEntry>,
    pub entry_count: usize,
}

/// Which No-Intro DAT file a loaded [`DatDatabase`] corresponds to. No-Intro
/// publishes these as separate DAT files rather than one combined N64 DAT,
/// since each covers dumps in a different byte order / format / platform
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DatKind {
    /// "Nintendo - Nintendo 64 (BigEndian)" — standard .z64 cartridge dumps.
    N64BigEndian,
    /// "Nintendo - Nintendo 64 (ByteSwapped)" — .v64 cartridge dumps.
    N64ByteSwapped,
    /// "Nintendo - Nintendo 64DD" — 64DD disk images.
    N64Dd,
    /// "Nintendo - Mario no Photopie (SmartMedia)" — Mario Artist Talent
    /// Studio SmartMedia card dumps.
    MarioNoPhotopieSmartMedia,
    /// "Nintendo - iQue Player (CDN)" — encrypted iQue CDN downloads.
    IQueCdn,
    /// "Nintendo - iQue Player (Decrypted)" — decrypted iQue N64 titles.
    IQueDecrypted,
    /// "Aleck64 (BigEndian)" — Seta/Aleck64 arcade ROM dumps.
    Aleck64BigEndian,
    /// "Aleck64 (ByteSwapped)" — Seta/Aleck64 arcade ROM dumps, byteswapped.
    Aleck64ByteSwapped,
}

impl DatKind {
    pub const ALL: [DatKind; 8] = [
        DatKind::N64BigEndian,
        DatKind::N64ByteSwapped,
        DatKind::N64Dd,
        DatKind::MarioNoPhotopieSmartMedia,
        DatKind::IQueCdn,
        DatKind::IQueDecrypted,
        DatKind::Aleck64BigEndian,
        DatKind::Aleck64ByteSwapped,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            DatKind::N64BigEndian => "Nintendo 64 (BigEndian)",
            DatKind::N64ByteSwapped => "Nintendo 64 (ByteSwapped)",
            DatKind::N64Dd => "Nintendo 64DD",
            DatKind::MarioNoPhotopieSmartMedia => "Mario no Photopie (SmartMedia)",
            DatKind::IQueCdn => "iQue Player (CDN)",
            DatKind::IQueDecrypted => "iQue Player (Decrypted)",
            DatKind::Aleck64BigEndian => "Aleck64 (BigEndian)",
            DatKind::Aleck64ByteSwapped => "Aleck64 (ByteSwapped)",
        }
    }

    /// `true` for the two DAT kinds whose entries are hashed against the
    /// ROM's original on-disk (byteswapped) byte order rather than the
    /// normalized big-endian order everything else uses.
    pub fn is_byteswapped(&self) -> bool {
        matches!(self, DatKind::N64ByteSwapped | DatKind::Aleck64ByteSwapped)
    }

    /// Best-effort guess of which [`DatKind`] a loaded DAT's own
    /// `<header><name>` text corresponds to, used when the user picks
    /// several/all DAT files at once (e.g. via "Load all No-Intro DATs…")
    /// so each file lands in the right slot without asking which-is-which.
    /// Matching is intentionally loose (lowercase substring checks) since
    /// No-Intro's exact header wording has drifted slightly over the years.
    pub fn guess_from_dat_name(name: &str) -> Option<DatKind> {
        let n = name.to_lowercase();
        let has = |s: &str| n.contains(s);
        if has("aleck64") || has("aleck 64") {
            return Some(if has("byteswap") { DatKind::Aleck64ByteSwapped } else { DatKind::Aleck64BigEndian });
        }
        if has("ique") {
            return Some(if has("cdn") { DatKind::IQueCdn } else { DatKind::IQueDecrypted });
        }
        if has("photopie") || has("smartmedia") || has("smart media") {
            return Some(DatKind::MarioNoPhotopieSmartMedia);
        }
        if has("64dd") || has("nintendo 64dd") || (has("nintendo 64") && has(" dd")) {
            return Some(DatKind::N64Dd);
        }
        if has("nintendo 64") || has("n64") {
            return Some(if has("byteswap") { DatKind::N64ByteSwapped } else { DatKind::N64BigEndian });
        }
        None
    }
}

/// One loaded DAT database plus the file path it was loaded from, so it can
/// later be re-read from disk (e.g. after the user downloads a newer DAT to
/// the same path) without needing to re-prompt a file picker.
#[derive(Debug, Clone)]
pub struct LoadedDat {
    pub db: Arc<DatDatabase>,
    pub path: PathBuf,
}

/// All DAT databases currently loaded, keyed by [`DatKind`]. Cheap to clone
/// (each entry is an `Arc`), so it can be handed to batch worker threads the
/// same way a single `DatDatabase` used to be.
#[derive(Debug, Default, Clone)]
pub struct DatCollection {
    entries: HashMap<DatKind, LoadedDat>,
}

impl DatCollection {
    /// Directly inserts a DAT into a known slot, bypassing name-guessing.
    /// Kept as a primitive building block for `load_files`/tests; most
    /// callers should use `load_files` instead.
    #[allow(dead_code)]
    pub fn set(&mut self, kind: DatKind, db: DatDatabase, path: PathBuf) {
        self.entries.insert(kind, LoadedDat { db: Arc::new(db), path });
    }

    /// Loads every DAT file in `paths`, guessing each one's [`DatKind`] from
    /// its own `<header><name>` text and inserting it into the matching
    /// slot. Used for "Load all No-Intro DATs…", where the user selects a
    /// folder (or multi-selects files) containing some/all of the 8 DAT
    /// files at once instead of loading them one at a time. Returns one
    /// result per input path: the detected kind on success, or an error
    /// string (parse failure, or a name that couldn't be matched to a known
    /// kind) on failure. Successfully guessed files are inserted even if
    /// other files in the same batch fail.
    pub fn load_files(&mut self, paths: &[PathBuf]) -> Vec<(PathBuf, Result<DatKind, String>)> {
        paths
            .iter()
            .map(|path| {
                let result =
                    DatDatabase::load_from_file(path).map_err(|e| e.to_string()).and_then(|db| {
                        match DatKind::guess_from_dat_name(&db.name) {
                            Some(kind) => {
                                self.entries.insert(kind, LoadedDat { db: Arc::new(db), path: path.clone() });
                                Ok(kind)
                            }
                            None => Err(format!("Could not match DAT name \"{}\" to a known No-Intro N64 DAT kind", db.name)),
                        }
                    });
                (path.clone(), result)
            })
            .collect()
    }

    pub fn get(&self, kind: DatKind) -> Option<&LoadedDat> {
        self.entries.get(&kind)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lists every currently loaded DAT's kind and path, sorted by
    /// `DatKind`'s declaration order, for display in the UI (version
    /// numbers, entry counts, etc. are read off `get(kind).db`).
    pub fn loaded_kinds(&self) -> Vec<DatKind> {
        let mut kinds: Vec<DatKind> = self.entries.keys().copied().collect();
        kinds.sort();
        kinds
    }

    fn has_byteswapped_kind(&self) -> bool {
        self.entries.keys().any(|k| k.is_byteswapped())
    }

    /// Re-reads every currently loaded DAT from its original file path.
    /// This performs **no network access whatsoever** — it exists purely so
    /// that if the user manually downloads an updated DAT file to the same
    /// path (e.g. by overwriting it from their browser), Turtle64 picks up
    /// the new version/date/entry count without needing to re-browse for
    /// the file. Returns one result per currently loaded kind.
    pub fn recheck_all(&mut self) -> Vec<(DatKind, Result<(), String>)> {
        let kinds: Vec<DatKind> = self.entries.keys().copied().collect();
        kinds.into_iter().map(|kind| (kind, self.recheck_one(kind))).collect()
    }

    /// Re-reads a single loaded DAT from its original file path. See
    /// [`DatCollection::recheck_all`] for why this never touches the network.
    pub fn recheck_one(&mut self, kind: DatKind) -> Result<(), String> {
        let Some(loaded) = self.entries.get(&kind) else {
            return Err("No DAT loaded for this slot".to_string());
        };
        let path = loaded.path.clone();
        match DatDatabase::load_from_file(&path) {
            Ok(db) => {
                self.entries.insert(kind, LoadedDat { db: Arc::new(db), path });
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Verifies a ROM/disk against every loaded DAT, trying the normalized
    /// big-endian hash against every slot and (when available) the native
    /// on-disk-order hash against the ByteSwapped slots. A `GoodDump` match
    /// anywhere wins immediately; otherwise a `BadDump` (CRC hit, stronger
    /// hash mismatch) from any slot is reported; otherwise `NotInDatabase`
    /// if at least one DAT is loaded, or `NoDatLoaded` if none are.
    pub fn verify(&self, be_hashes: &RomHashes, native_hashes: Option<&RomHashes>) -> VerificationStatus {
        if self.entries.is_empty() {
            return VerificationStatus::NoDatLoaded;
        }
        let mut bad: Option<VerificationStatus> = None;

        for loaded in self.entries.values() {
            match loaded.db.verify(be_hashes.crc32, &be_hashes.md5, &be_hashes.sha1) {
                VerificationStatus::GoodDump { game_name } => return VerificationStatus::GoodDump { game_name },
                status @ VerificationStatus::BadDump { .. } => bad = Some(status),
                _ => {}
            }
        }

        if let Some(native) = native_hashes {
            if self.has_byteswapped_kind() {
                for loaded in self.entries.values() {
                    match loaded.db.verify(native.crc32, &native.md5, &native.sha1) {
                        VerificationStatus::GoodDump { game_name } => return VerificationStatus::GoodDump { game_name },
                        status @ VerificationStatus::BadDump { .. } => bad = Some(status),
                        _ => {}
                    }
                }
            }
        }

        bad.unwrap_or(VerificationStatus::NotInDatabase)
    }
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

        let header = root.descendants().find(|n| n.has_tag_name("header"));
        let name =
            header.and_then(|h| h.children().find(|c| c.has_tag_name("name"))).and_then(|n| n.text()).unwrap_or("Unknown DAT").to_string();
        let version = header.and_then(|h| h.children().find(|c| c.has_tag_name("version"))).and_then(|n| n.text()).map(|s| s.to_string());
        let date = header.and_then(|h| h.children().find(|c| c.has_tag_name("date"))).and_then(|n| n.text()).map(|s| s.to_string());

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

        Ok(DatDatabase { name, version, date, by_crc32, entry_count })
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

    #[test]
    fn parses_version_and_date() {
        const DAT_WITH_VERSION: &str = r#"<?xml version="1.0"?>
<datafile>
  <header><name>Nintendo - Nintendo 64 (BigEndian)</name><version>20240315-120000</version><date>2024-03-15</date></header>
</datafile>"#;
        let db = DatDatabase::load_from_str(DAT_WITH_VERSION).unwrap();
        assert_eq!(db.version.as_deref(), Some("20240315-120000"));
        assert_eq!(db.date.as_deref(), Some("2024-03-15"));
    }

    #[test]
    fn guesses_kind_from_dat_name() {
        assert_eq!(DatKind::guess_from_dat_name("Nintendo - Nintendo 64 (BigEndian)"), Some(DatKind::N64BigEndian));
        assert_eq!(DatKind::guess_from_dat_name("Nintendo - Nintendo 64 (ByteSwapped)"), Some(DatKind::N64ByteSwapped));
        assert_eq!(DatKind::guess_from_dat_name("Nintendo - Nintendo 64DD"), Some(DatKind::N64Dd));
        assert_eq!(DatKind::guess_from_dat_name("Nintendo - Mario no Photopie (SmartMedia)"), Some(DatKind::MarioNoPhotopieSmartMedia));
        assert_eq!(DatKind::guess_from_dat_name("Nintendo - iQue Player (CDN)"), Some(DatKind::IQueCdn));
        assert_eq!(DatKind::guess_from_dat_name("Nintendo - iQue Player (Decrypted)"), Some(DatKind::IQueDecrypted));
        assert_eq!(DatKind::guess_from_dat_name("Aleck64 (BigEndian)"), Some(DatKind::Aleck64BigEndian));
        assert_eq!(DatKind::guess_from_dat_name("Aleck64 (ByteSwapped)"), Some(DatKind::Aleck64ByteSwapped));
        assert_eq!(DatKind::guess_from_dat_name("Totally unrelated software list"), None);
    }

    #[test]
    fn load_files_routes_each_dat_into_its_kind_and_reports_failures() {
        let dir = std::env::temp_dir().join(format!("turtle64_dat_test_{}_{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();

        let be_path = dir.join("n64_be.dat");
        std::fs::write(
            &be_path,
            "<?xml version=\"1.0\"?><datafile><header><name>Nintendo - Nintendo 64 (BigEndian)</name></header></datafile>",
        )
        .unwrap();
        let bs_path = dir.join("n64_bs.dat");
        std::fs::write(
            &bs_path,
            "<?xml version=\"1.0\"?><datafile><header><name>Nintendo - Nintendo 64 (ByteSwapped)</name></header></datafile>",
        )
        .unwrap();
        let bogus_path = dir.join("bogus.dat");
        std::fs::write(&bogus_path, "<?xml version=\"1.0\"?><datafile><header><name>Some Other System</name></header></datafile>").unwrap();

        let mut collection = DatCollection::default();
        let results = collection.load_files(&[be_path.clone(), bs_path.clone(), bogus_path.clone()]);

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].1.as_ref().ok(), Some(&DatKind::N64BigEndian));
        assert_eq!(results[1].1.as_ref().ok(), Some(&DatKind::N64ByteSwapped));
        assert!(results[2].1.is_err());

        assert!(!collection.is_empty());
        assert_eq!(collection.loaded_kinds(), vec![DatKind::N64BigEndian, DatKind::N64ByteSwapped]);
        assert!(collection.get(DatKind::N64BigEndian).is_some());
        assert!(collection.get(DatKind::N64Dd).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recheck_all_rereads_each_loaded_dat_without_network_access() {
        let dir = std::env::temp_dir().join(format!("turtle64_dat_recheck_test_{}_{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("n64_be.dat");
        std::fs::write(
            &path,
            "<?xml version=\"1.0\"?><datafile><header><name>Nintendo - Nintendo 64 (BigEndian)</name><version>1</version></header></datafile>",
        )
        .unwrap();

        let mut collection = DatCollection::default();
        collection.load_files(std::slice::from_ref(&path));
        assert_eq!(collection.get(DatKind::N64BigEndian).unwrap().db.version.as_deref(), Some("1"));

        // Simulate the user manually downloading a newer DAT to the same path.
        std::fs::write(
            &path,
            "<?xml version=\"1.0\"?><datafile><header><name>Nintendo - Nintendo 64 (BigEndian)</name><version>2</version></header></datafile>",
        )
        .unwrap();
        let results = collection.recheck_all();
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok());
        assert_eq!(collection.get(DatKind::N64BigEndian).unwrap().db.version.as_deref(), Some("2"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
