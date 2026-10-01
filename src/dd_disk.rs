//! Ties together 64DD disk format detection, System Data / Disk ID parsing,
//! CIC identification, hashing, and MFS inspection into a single `DdDiskInfo`
//! — the disk-image analogue of `rom::RomInfo`.

use crate::dd_cic::{identify_dd_cic, DdCic};
use crate::dd_convert;
use crate::dd_geometry as geo;
use crate::dd_mfs::MfsVolume;
use crate::hashes::{compute_hashes, RomHashes};
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskFormat {
    Ndd,
    /// SDK master disk format. **Lossy**: it never stores disk formatting
    /// metadata (defect/bad track table, exact physical LBA sizing info),
    /// so converting a disk *to* D64 discards that data, and converting
    /// *from* a D64 back to NDD/MAME can only reconstruct an idealized
    /// "freshly formatted, defect-free" disk rather than the original exact
    /// dump. See `dd_convert::logical_to_d64`/`d64_to_logical` doc comments.
    D64,
    Mame,
}

impl DiskFormat {
    pub fn label(&self) -> &'static str {
        match self {
            DiskFormat::Ndd => "NDD (64DD Disk Dumper, LBA-ordered)",
            DiskFormat::D64 => "D64 (SDK master disk format, LOSSY)",
            DiskFormat::Mame => "MAME (physical track-ordered)",
        }
    }

    /// `true` for the one format (D64) that cannot round-trip a disk image
    /// losslessly, because it doesn't retain disk formatting metadata.
    pub fn is_lossy(&self) -> bool {
        matches!(self, DiskFormat::D64)
    }

    pub fn extension(&self) -> &'static str {
        match self {
            DiskFormat::Ndd => "ndd",
            DiskFormat::D64 => "d64",
            // The MAME physical-order format also conventionally uses the
            // ".ndd" extension — it's distinguished from the regular NDD
            // dump purely by file size/content, not by extension.
            DiskFormat::Mame => "ndd",
        }
    }
}

/// Parsed System Data fields, shared by disk-info display and conversion.
#[derive(Debug, Clone, Copy)]
pub struct SysData {
    pub region: u32,
    pub disk_type: u32,
    pub retail: bool,
    pub ipl_load_size: u16,
    pub ipl_load_address: u32,
    pub rom_end_lba: u16,
    pub ram_start_lba: u16,
    pub ram_end_lba: u16,
}

impl SysData {
    pub fn parse(b: &[u8]) -> SysData {
        let region = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        SysData {
            region,
            disk_type: (b[5] & 0x0F) as u32,
            retail: b[5] & 0x10 != 0,
            ipl_load_size: u16::from_be_bytes([b[6], b[7]]),
            ipl_load_address: u32::from_be_bytes([b[0x1c], b[0x1d], b[0x1e], b[0x1f]]),
            rom_end_lba: u16::from_be_bytes([b[0xe0], b[0xe1]]),
            ram_start_lba: u16::from_be_bytes([b[0xe2], b[0xe3]]),
            ram_end_lba: u16::from_be_bytes([b[0xe4], b[0xe5]]),
        }
    }

    pub fn region_name(&self) -> &'static str {
        match self.region {
            geo::REGION_JAPAN => "Japan",
            geo::REGION_USA => "USA",
            geo::REGION_DEV => "Development / none",
            _ => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiskId {
    pub game_code: String,
    pub game_version: u8,
    pub disk_number: u8,
    pub ram_use: bool,
    pub company_code: String,
    pub production_datetime: String,
}

impl DiskId {
    pub fn parse(b: &[u8]) -> DiskId {
        let game_code = String::from_utf8_lossy(&b[0..4]).trim_matches('\0').to_string();
        let year = u16::from_be_bytes([b[0x11], b[0x12]]);
        let production_datetime = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, b[0x13], b[0x14], b[0x15], b[0x16], b[0x17]);
        DiskId {
            game_code,
            game_version: b[4],
            disk_number: b[5],
            ram_use: b[6] != 0,
            company_code: String::from_utf8_lossy(&b[0x18..0x1a]).trim_matches('\0').to_string(),
            production_datetime,
        }
    }
}

pub struct DdDiskInfo {
    pub path: PathBuf,
    pub format: DiskFormat,
    pub file_size: u64,
    pub sys: SysData,
    pub disk_id: DiskId,
    pub destination_code: u8,
    pub cic: DdCic,
    pub has_defect_tracks: bool,
    pub hashes: RomHashes,
    pub rom_area_sha1: Option<String>,
    pub mfs: Option<MfsVolume>,
    /// Fully expanded, logically (NDD-style) ordered bytes — used internally
    /// for MFS parsing and as the basis for further format conversion.
    logical: Vec<u8>,
}

fn expected_d64_size(sys: &SysData) -> usize {
    0x200 + geo::rom_area_size(sys.disk_type, sys.rom_end_lba) + geo::ram_area_size(sys.disk_type, sys.ram_start_lba, sys.ram_end_lba)
}

/// Detects the disk image format purely from its contents (size + System
/// Data sanity), never from the file extension.
pub fn detect_format(data: &[u8]) -> Result<DiskFormat> {
    if data.len() < 232 {
        bail!("File is too small to be a 64DD disk image");
    }
    let sys = SysData::parse(&data[0..232]);
    let looks_like_system_data =
        matches!(sys.region, geo::REGION_JAPAN | geo::REGION_USA | geo::REGION_DEV) && geo::is_valid_disk_type(sys.disk_type);

    if data.len() == geo::NDD_FILE_SIZE {
        return Ok(DiskFormat::Ndd);
    }
    if data.len() == geo::mame_file_size() {
        return Ok(DiskFormat::Mame);
    }
    if looks_like_system_data && data.len() == expected_d64_size(&sys) {
        return Ok(DiskFormat::D64);
    }
    // Fall back to a closest-match guess so odd-sized dumps still load with
    // a warning rather than failing outright, but only if the header at
    // least looks plausible.
    if looks_like_system_data {
        bail!(
            "Unrecognized 64DD disk image size ({} bytes). Expected NDD ({} bytes), MAME ({} bytes), or D64 ({} bytes for this disk).",
            data.len(),
            geo::NDD_FILE_SIZE,
            geo::mame_file_size(),
            expected_d64_size(&sys)
        );
    }
    bail!("File does not look like a 64DD disk image (no recognized System Data region)");
}

impl DdDiskInfo {
    pub fn load(path: &Path) -> Result<DdDiskInfo> {
        let data = std::fs::read(path)?;
        let format = detect_format(&data)?;
        let sys = SysData::parse(&data[0..232]);

        let logical = match format {
            DiskFormat::Ndd => data.clone(),
            DiskFormat::Mame => dd_convert::mame_to_logical(&data, sys.disk_type),
            DiskFormat::D64 => dd_convert::d64_to_logical(&data, &sys),
        };

        let diskid_off = geo::ndd_disk_id_offset();
        let disk_id = if diskid_off + 232 <= logical.len() {
            DiskId::parse(&logical[diskid_off..diskid_off + 232])
        } else {
            DiskId::parse(&[0u8; 232])
        };

        let destination_code = if format == DiskFormat::D64 && data.len() > 0x1E8 {
            data[0x1E8]
        } else {
            dd_convert::destination_code_from_game_code(disk_id.game_code.as_bytes())
        };

        let cic = identify_dd_cic(sys.region, sys.retail);
        let has_defect_tracks = dd_convert::has_defect_tracks(&data[0..232.min(data.len())]);

        let hashes = compute_hashes(&data);

        let rom_start = geo::ndd_rom_area_start(sys.disk_type);
        let rom_size = geo::rom_area_size(sys.disk_type, sys.rom_end_lba);
        let rom_area_sha1 = if rom_start + rom_size <= logical.len() {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&logical[rom_start..rom_start + rom_size]);
            Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
        } else {
            None
        };

        let mfs = if disk_id.ram_use { MfsVolume::parse(&logical, sys.disk_type, sys.ram_start_lba) } else { None };

        Ok(DdDiskInfo {
            path: path.to_path_buf(),
            format,
            file_size: data.len() as u64,
            sys,
            disk_id,
            destination_code,
            cic,
            has_defect_tracks,
            hashes,
            rom_area_sha1,
            mfs,
            logical,
        })
    }

    pub fn destination_name(&self) -> &'static str {
        dd_convert::destination_name(self.destination_code)
    }

    /// Converts this disk to `target` format and returns the raw bytes.
    pub fn convert_to(&self, target: DiskFormat) -> Vec<u8> {
        match target {
            DiskFormat::Ndd => self.logical.clone(),
            DiskFormat::Mame => dd_convert::logical_to_mame(&self.logical, self.sys.disk_type),
            DiskFormat::D64 => dd_convert::logical_to_d64(&self.logical, &self.sys),
        }
    }

    pub fn convert_to_file(&self, target: DiskFormat, out: &Path) -> Result<()> {
        let bytes = self.convert_to(target);
        std::fs::write(out, bytes)?;
        Ok(())
    }

    /// Extracts a single MFS file's raw bytes, if an MFS volume was found.
    pub fn extract_mfs_file(&self, entry: &crate::dd_mfs::MfsEntry) -> Option<Vec<u8>> {
        self.mfs.as_ref()?.extract_file(&self.logical, entry)
    }

    /// Renders all disk-info/checksum/hash/MFS-listing info for this disk
    /// image as a plain-text report, suitable for saving alongside the
    /// image or sharing for troubleshooting/database purposes.
    pub fn info_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "Turtle64 64DD Disk Info Report");
        let _ = writeln!(out, "===============================");
        let _ = writeln!(out, "File: {}", self.path.display());
        let _ = writeln!(out, "File size: {} bytes ({:.2} MiB)", self.file_size, self.file_size as f64 / (1024.0 * 1024.0));
        let _ = writeln!(out, "Detected format: {}", self.format.label());
        let _ = writeln!(out, "Region: {}", self.sys.region_name());
        let _ = writeln!(out, "Disk type: {} ({})", self.sys.disk_type, if self.sys.retail { "retail" } else { "development" });
        let _ = writeln!(out, "64DD IPL CIC: {}", self.cic.label());
        if self.has_defect_tracks {
            let _ = writeln!(
                out,
                "WARNING: This disk reports bad/defect tracks. MAME-format conversion does not model these and may not be bit-exact."
            );
        }
        if self.format.is_lossy() {
            let _ = writeln!(
                out,
                "NOTE: This disk was loaded from a D64 file (a lossy, trimmed format) — info below reflects that \
                 idealized, defect-free disk, not necessarily the original physical dump."
            );
        }
        out.push('\n');

        let _ = writeln!(out, "-- System Data / Disk ID --");
        let _ = writeln!(out, "Game code: {}", self.disk_id.game_code);
        let _ = writeln!(out, "Game version: {}", self.disk_id.game_version);
        let _ = writeln!(out, "Disk number: {}", self.disk_id.disk_number);
        let _ = writeln!(out, "Destination: {} (0x{:02X})", self.destination_name(), self.destination_code);
        let _ = writeln!(out, "Company code: {}", self.disk_id.company_code);
        let _ = writeln!(out, "Production date/time: {}", self.disk_id.production_datetime);
        let _ = writeln!(out, "IPL load address: 0x{:08X}", self.sys.ipl_load_address);
        let _ = writeln!(out, "IPL load size (blocks): {}", self.sys.ipl_load_size);
        let _ = writeln!(out, "ROM end LBA: {}", self.sys.rom_end_lba);
        let _ = writeln!(out, "RAM used (MFS): {}", if self.disk_id.ram_use { "yes" } else { "no" });
        out.push('\n');

        let _ = writeln!(out, "-- Checksums / Hashes --");
        let _ = writeln!(out, "CRC32 (whole file): {:08X}", self.hashes.crc32);
        let _ = writeln!(out, "MD5 (whole file): {}", self.hashes.md5);
        let _ = writeln!(out, "SHA-1 (whole file): {}", self.hashes.sha1);
        if let Some(rom_sha1) = &self.rom_area_sha1 {
            let _ = writeln!(out, "SHA-1 (ROM Area only): {}", rom_sha1);
        }
        out.push('\n');

        if let Some(mfs) = &self.mfs {
            let _ = writeln!(out, "-- MFS Filesystem --");
            let _ = writeln!(out, "Volume: {} — formatted {}", mfs.volname, mfs.format_datetime);
            let _ = writeln!(out, "Renewal counter: {}  •  checksum: 0x{:08X}", mfs.renewal_counter, mfs.checksum);
            for entry in &mfs.entries {
                if entry.is_dir {
                    continue;
                }
                let _ = writeln!(out, "  {}  ({} bytes, {})", mfs.full_path(entry), entry.size, entry.datetime);
            }
        } else if self.disk_id.ram_use {
            let _ = writeln!(out, "Disk ID indicates MFS should be present, but it could not be parsed.");
        } else {
            let _ = writeln!(out, "No MFS filesystem on this disk (RAM Area unused).");
        }

        out
    }

    /// Produces a combined "conversion + info" report for this disk: a
    /// short note about the conversion just performed, followed by the
    /// full `info_text()` report.
    pub fn conversion_info_text(&self, target: DiskFormat, out_path: &Path) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "Converted: {} ({})", self.path.display(), self.format.label());
        let _ = writeln!(out, "       -> : {} ({})", out_path.display(), target.label());
        out.push('\n');
        out.push_str(&self.info_text());
        out
    }
}

/// File extensions this app will offer when browsing for 64DD disk images.
/// Note: the MAME physical-order format is also conventionally saved with
/// a `.ndd` extension — it is told apart from a regular NDD dump purely by
/// file size/content, never by extension.
pub const DISK_EXTENSIONS: &[&str] = &["ndd", "d64"];

#[allow(dead_code)]
pub fn is_probably_disk_image(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).map(|e| DISK_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str())).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ndd() -> Vec<u8> {
        let mut buf = vec![0u8; geo::NDD_FILE_SIZE];
        buf[0..4].copy_from_slice(&geo::REGION_JAPAN.to_be_bytes());
        buf[5] = 0x10; // disk type 0, retail
        buf[0xE2..0xE4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        buf[0xE4..0xE6].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let diskid_off = geo::ndd_disk_id_offset();
        buf[diskid_off..diskid_off + 4].copy_from_slice(b"DMPJ");
        buf
    }

    #[test]
    fn detects_ndd_by_size() {
        let buf = sample_ndd();
        assert_eq!(detect_format(&buf).unwrap(), DiskFormat::Ndd);
    }

    #[test]
    fn rejects_garbage() {
        let buf = vec![0xAAu8; 1000];
        assert!(detect_format(&buf).is_err());
    }

    #[test]
    fn destination_derived_from_game_code() {
        let buf = sample_ndd();
        let diskid_off = geo::ndd_disk_id_offset();
        let disk_id = DiskId::parse(&buf[diskid_off..diskid_off + 232]);
        assert_eq!(disk_id.game_code, "DMPJ");
        assert_eq!(dd_convert::destination_code_from_game_code(disk_id.game_code.as_bytes()), 0x00);
    }

    #[test]
    fn identifies_japan_retail_cic() {
        let buf = sample_ndd();
        let sys = SysData::parse(&buf[0..232]);
        assert_eq!(identify_dd_cic(sys.region, sys.retail), DdCic::Cic8303);
    }
}
