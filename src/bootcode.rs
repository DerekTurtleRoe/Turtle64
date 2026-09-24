//! IPL3 boot-code extraction and patching.
//!
//! Per the N64brew wiki (https://n64brew.dev/wiki/Initial_Program_Load), the
//! 0xFC0-byte (4032 byte) IPL3 stage lives at ROM offset 0x40-0x1000 and is
//! matched against a checksum hardcoded into the cart's CIC chip. This
//! module lets users dump that region out to a file for inspection, and
//! patch a different, previously-dumped IPL3 back into a ROM - useful for
//! repairing ROMs with a corrupted/missing IPL3, testing how a ROM behaves
//! under a different CIC pairing, or restoring an original boot code onto a
//! ROM that shipped with a placeholder/zeroed one.
//!
//! Known-good dumps are expected to live in a `bootcodes` folder next to the
//! Turtle64 executable (created automatically on demand), one file per
//! CIC/IPL3 variant, each exactly 0xFC0 bytes of raw binary data.

use std::path::{Path, PathBuf};

pub const IPL3_OFFSET: usize = 0x40;
pub const IPL3_SIZE: usize = 0xFC0;

/// Resolves the `bootcodes` folder used to store known IPL3 dumps. This
/// lives next to the running executable so the app remains portable. Falls
/// back to the current working directory if the executable's location
/// can't be determined.
pub fn bootcodes_dir() -> PathBuf {
    let base = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())).unwrap_or_else(|| PathBuf::from("."));
    base.join("bootcodes")
}

/// Ensures the bootcodes folder exists, creating it if necessary.
pub fn ensure_bootcodes_dir() -> std::io::Result<PathBuf> {
    let dir = bootcodes_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Lists candidate IPL3 dump files in the bootcodes folder: any regular
/// file exactly `IPL3_SIZE` bytes long. The dump is a raw, headerless
/// binary blob, so files are sanity-checked by size rather than extension.
pub fn list_bootcodes() -> Vec<PathBuf> {
    let dir = bootcodes_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && std::fs::metadata(p).map(|m| m.len() == IPL3_SIZE as u64).unwrap_or(false))
        .collect();
    files.sort();
    files
}

/// Extracts the IPL3 boot code region from big-endian normalized ROM data.
pub fn dump_ipl3(be_data: &[u8]) -> Option<Vec<u8>> {
    if be_data.len() < IPL3_OFFSET + IPL3_SIZE {
        return None;
    }
    Some(be_data[IPL3_OFFSET..IPL3_OFFSET + IPL3_SIZE].to_vec())
}

/// Loads a raw IPL3 dump from disk, verifying it is exactly `IPL3_SIZE`
/// bytes.
pub fn load_bootcode_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    if data.len() != IPL3_SIZE {
        anyhow::bail!("'{}' is {} bytes, expected exactly {} bytes (0xFC0) for an IPL3 dump", path.display(), data.len(), IPL3_SIZE);
    }
    Ok(data)
}

/// Returns a copy of `be_data` with its IPL3 region replaced by
/// `new_ipl3`. `be_data` must already be big-endian normalized and at
/// least `IPL3_OFFSET + IPL3_SIZE` bytes long.
pub fn patch_ipl3(be_data: &[u8], new_ipl3: &[u8]) -> anyhow::Result<Vec<u8>> {
    if new_ipl3.len() != IPL3_SIZE {
        anyhow::bail!("replacement IPL3 must be exactly {} bytes", IPL3_SIZE);
    }
    if be_data.len() < IPL3_OFFSET + IPL3_SIZE {
        anyhow::bail!("ROM is too small to contain an IPL3 region");
    }
    let mut out = be_data.to_vec();
    out[IPL3_OFFSET..IPL3_OFFSET + IPL3_SIZE].copy_from_slice(new_ipl3);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_and_patch_round_trip() {
        let be_data = vec![0xAAu8; IPL3_OFFSET + IPL3_SIZE + 16];
        let new_ipl3 = vec![0x42u8; IPL3_SIZE];
        let patched = patch_ipl3(&be_data, &new_ipl3).unwrap();
        let dumped = dump_ipl3(&patched).unwrap();
        assert_eq!(dumped, new_ipl3);

        // Original untouched.
        assert!(dump_ipl3(&be_data).unwrap().iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn rejects_wrong_size() {
        let be_data = vec![0u8; IPL3_OFFSET + IPL3_SIZE];
        let bad = vec![0u8; 10];
        assert!(patch_ipl3(&be_data, &bad).is_err());
    }

    #[test]
    fn rejects_truncated_rom() {
        let be_data = vec![0u8; 0x10];
        let new_ipl3 = vec![0u8; IPL3_SIZE];
        assert!(patch_ipl3(&be_data, &new_ipl3).is_err());
    }
}
