//! High level ROM loading: ties together format detection, header parsing,
//! legacy checksum calculation, and modern hashing into one struct.

use crate::checksum::{self, Cic, PiTimingsStatus};
use crate::dat::{DatDatabase, VerificationStatus};
use crate::hashes::{self, RomHashes};
use crate::header::{self, RomHeader};
use crate::rom_format::{self, RomFormat};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RomInfo {
    pub path: PathBuf,
    pub detected_format: RomFormat,
    pub has_ique_header: bool,
    pub file_size: u64,
    pub header: Option<RomHeader>,
    pub cic: Cic,
    pub calculated_crc1: Option<u32>,
    pub calculated_crc2: Option<u32>,
    pub checksum_valid: Option<bool>,
    pub pi_timings_status: Option<PiTimingsStatus>,
    pub hashes: RomHashes,
    pub verification: VerificationStatus,
    /// Big-endian normalized bytes, kept around for conversion without a
    /// second disk read. Not serialized/displayed.
    pub be_data: Vec<u8>,
}

impl RomInfo {
    pub fn load(path: &Path, dat: Option<&DatDatabase>) -> anyhow::Result<Self> {
        let raw = std::fs::read(path)?;
        let (detected_format, offset, has_ique_header) = rom_format::detect_format_and_offset(&raw);
        let payload = if offset > 0 && offset < raw.len() { &raw[offset..] } else { &raw[..] };
        let be_data = rom_format::to_big_endian(payload, detected_format);
        Ok(Self::from_be_data(path.to_path_buf(), detected_format, has_ique_header, be_data, dat))
    }

    /// Builds a fully-analyzed `RomInfo` from already-normalized big-endian
    /// ROM bytes, without touching disk. Used both by `load` and by IPL3
    /// patching (which needs to re-derive CIC/checksums/hashes for the
    /// patched bytes before the user saves them).
    fn from_be_data(path: PathBuf, detected_format: RomFormat, has_ique_header: bool, be_data: Vec<u8>, dat: Option<&DatDatabase>) -> Self {
        let file_size = be_data.len() as u64;
        let header = header::parse_header(&be_data);
        let cic = checksum::identify_cic(&be_data);
        let (calculated_crc1, calculated_crc2) = match checksum::calc_crc(&be_data, cic) {
            Some((a, b)) => (Some(a), Some(b)),
            None => (None, None),
        };
        let checksum_valid = match (&header, calculated_crc1, calculated_crc2) {
            (Some(h), Some(c1), Some(c2)) => Some(h.crc1 == c1 && h.crc2 == c2),
            _ => None,
        };
        let pi_timings_status = header.as_ref().map(|h| checksum::grade_pi_timings(h.pi_timings));

        let hashes = hashes::compute_hashes(&be_data);
        let verification = match dat {
            Some(db) => db.verify(hashes.crc32, &hashes.md5, &hashes.sha1),
            None => VerificationStatus::NoDatLoaded,
        };

        RomInfo {
            path,
            detected_format,
            has_ique_header,
            file_size,
            header,
            cic,
            calculated_crc1,
            calculated_crc2,
            checksum_valid,
            pi_timings_status,
            hashes,
            verification,
            be_data,
        }
    }

    /// Converts this ROM to the target format and writes it to `out_path`.
    pub fn convert_to_file(&self, target: RomFormat, out_path: &Path) -> anyhow::Result<()> {
        let out_data = rom_format::from_big_endian(&self.be_data, target);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(out_path, out_data)?;
        Ok(())
    }

    /// Extracts this ROM's IPL3 boot code (offset 0x40-0x1000, 0xFC0 bytes)
    /// for dumping to a file for separate inspection.
    pub fn ipl3_bytes(&self) -> Option<Vec<u8>> {
        crate::bootcode::dump_ipl3(&self.be_data)
    }

    /// Renders all header/checksum/hash/verification info for this ROM as a
    /// plain-text report, suitable for saving alongside the ROM or sharing
    /// for troubleshooting/database purposes.
    pub fn info_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "Turtle64 ROM Info Report");
        let _ = writeln!(out, "========================");
        let _ = writeln!(out, "File: {}", self.path.display());
        let _ = writeln!(out, "File size: {} bytes ({:.2} MiB)", self.file_size, self.file_size as f64 / (1024.0 * 1024.0));
        let _ = writeln!(out, "Detected format: {}", self.detected_format.label());
        let _ = writeln!(out, "CIC boot chip: {}", self.cic.label());
        if self.has_ique_header {
            let _ = writeln!(out, "iQue container header: 32-byte iQue header detected and parsed");
        }
        out.push('\n');

        if let Some(header) = &self.header {
            let _ = writeln!(out, "-- ROM Header --");
            let _ = writeln!(out, "Game title: {}", header.game_title);
            let _ = writeln!(
                out,
                "Game code: {}{} ({})",
                header.category_code,
                header.unique_code,
                header::category_name(header.category_code)
            );
            let _ = writeln!(out, "Region: {} - {}", header.destination_code, header.destination_name);
            let _ = writeln!(out, "ROM version: 1.{}", header.rom_version);
            let _ = writeln!(out, "Boot address (entry point): 0x{:08X}", header.boot_address);
            let _ = writeln!(out, "Clock rate (raw): 0x{:08X}", header.clock_rate_raw);
            let _ = writeln!(out, "Libultra version: {} (raw 0x{:08X})", header.libultra_version, header.libultra_version_raw);
            let _ = writeln!(
                out,
                "PI BSD DOM1 config / PI timings: 0x{:08X}  {}",
                header.pi_timings,
                self.pi_timings_status.map(|s| s.label()).unwrap_or("")
            );
            let _ = writeln!(out, "Header check code: 0x{:016X}", header.check_code);
            let _ = writeln!(out, "Header CRC1 / CRC2: 0x{:08X} / 0x{:08X}", header.crc1, header.crc2);
            out.push('\n');

            if let Some(hb) = &header.homebrew {
                let _ = writeln!(out, "-- Advanced Homebrew ROM Header --");
                let _ = writeln!(out, "Controller 1: {}", hb.controller1);
                let _ = writeln!(out, "Controller 2: {}", hb.controller2);
                let _ = writeln!(out, "Controller 3: {}", hb.controller3);
                let _ = writeln!(out, "Controller 4: {}", hb.controller4);
                let _ = writeln!(out, "Save type: {}", hb.savetype);
                let _ = writeln!(out, "Uses RTC: {}", if hb.uses_rtc { "Yes" } else { "No" });
                let _ = writeln!(out, "Region-free: {}", if hb.region_free { "Yes" } else { "No" });
                let _ = writeln!(out, "Embedded metadata ZIP: {}", if hb.has_metadata { "Yes" } else { "No" });
            } else {
                let _ = writeln!(out, "No Advanced Homebrew ROM Header detected (no \"ED\" marker at 0x3C).");
            }
            out.push('\n');
        } else {
            let _ = writeln!(out, "ROM too small to contain a valid header.\n");
        }

        let _ = writeln!(out, "-- Checksums & Hashes --");
        match (self.calculated_crc1, self.calculated_crc2) {
            (Some(c1), Some(c2)) => {
                let status = match self.checksum_valid {
                    Some(true) => "(matches header)",
                    Some(false) => "(MISMATCH)",
                    None => "",
                };
                let _ = writeln!(out, "Calculated CRC1 / CRC2: 0x{:08X} / 0x{:08X} {}", c1, c2, status);
            }
            _ => {
                let _ = writeln!(out, "Calculated CRC1 / CRC2: unable to calculate (unrecognized CIC or truncated ROM)");
            }
        }
        let _ = writeln!(out, "CRC32: {:08X}", self.hashes.crc32);
        let _ = writeln!(out, "MD5: {}", self.hashes.md5);
        let _ = writeln!(out, "SHA-1: {}", self.hashes.sha1);
        out.push('\n');

        let _ = writeln!(out, "No-Intro verification: {}", self.verification.label());

        out
    }

    /// Produces a new, fully re-analyzed `RomInfo` with the IPL3 region
    /// replaced by `new_ipl3`. If `fix_header_crc` is true, the header's
    /// stored CRC1/CRC2 are overwritten with freshly calculated values so
    /// the ROM boots correctly under the new IPL3/CIC pairing (mirroring
    /// romjudge's checksum-fix mode). The original `RomInfo` is untouched;
    /// the result is a separate in-memory preview that the caller can then
    /// save to disk.
    pub fn with_patched_ipl3(&self, new_ipl3: &[u8], fix_header_crc: bool, dat: Option<&DatDatabase>) -> anyhow::Result<RomInfo> {
        let mut patched = crate::bootcode::patch_ipl3(&self.be_data, new_ipl3)?;
        if fix_header_crc {
            let cic = checksum::identify_cic(&patched);
            if let Some((c1, c2)) = checksum::calc_crc(&patched, cic) {
                header::write_crc(&mut patched, c1, c2);
            }
        }
        Ok(Self::from_be_data(self.path.clone(), self.detected_format, self.has_ique_header, patched, dat))
    }
}

/// Recognized ROM file extensions used when scanning folders for batch jobs.
/// Detection of the actual byte order is still always done via the magic
/// bytes; this list is only used to decide which files to *consider*.
pub const ROM_EXTENSIONS: &[&str] = &["z64", "n64", "v64", "rom", "bin"];

pub fn is_probably_rom(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).map(|e| ROM_EXTENSIONS.contains(&e.to_lowercase().as_str())).unwrap_or(false)
}
