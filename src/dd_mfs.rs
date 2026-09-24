//! MFS (Mario/N64 File System) parsing — the FAT-like filesystem 64DD games
//! use for their writable RAM Area. Directory/file entry layouts below were
//! independently reimplemented from the field offsets documented by
//! jkbenaim's leotools (`mfs.h`/`mfs.c`, disk-info tooling only — no code
//! copied) and cross-checked against LuigiBlood's leo64dd_python `DOC.md`.
//!
//! Listing (volume label, directory tree, file sizes/dates) follows the
//! documented on-disk layout closely and should be reliable. Raw file
//! *extraction* additionally assumes each FAT entry addresses one RAM-area
//! LBA-sized block and that a chain terminates once enough bytes have been
//! read to cover the file's recorded size; this is a best-effort
//! reconstruction (flagged as experimental in the UI) since the exact FAT
//! terminator convention is not documented publicly.

use crate::dd_geometry;

const MFS_MAGIC: &[u8; 10] = b"64dd-Multi";
const HEADER_SIZE: usize = 60;
const FAT_SIZE: usize = 5748;
const DIR_ENTRY_SIZE: usize = 48;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MfsEntry {
    pub is_dir: bool,
    pub name: String,
    pub parent_id: u16,
    pub id: u16,
    pub fat_entry: u16,
    pub size: u32,
    pub company_code: String,
    pub game_code: String,
    pub datetime: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MfsVolume {
    pub valid: bool,
    pub volname: String,
    pub format_datetime: String,
    pub renewal_counter: u16,
    pub checksum: u32,
    pub disk_type_in_header: u8,
    pub entries: Vec<MfsEntry>,
    ram_start_offset: usize,
    block_size: usize,
    fat: Vec<u16>,
}

fn mfs_date_to_string(b: &[u8]) -> String {
    if b.len() < 4 {
        return String::new();
    }
    let year = 1996 + ((b[0] & 0xfe) >> 1) as u32;
    let month = (((b[0] & 0x01) << 3) + ((b[1] & 0xe0) >> 5)) as u32;
    let day = (b[1] & 0x1f) as u32;
    let hour = ((b[2] & 0xf8) >> 3) as u32;
    let minute = (((b[2] & 0x07) << 3) + ((b[3] & 0xe0) >> 5)) as u32;
    let second = ((b[3] & 0x1f) << 1) as u32;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

/// Best-effort conversion of a Shift-JIS-esque MFS filename to a readable
/// string. Filenames on real disks are almost always plain ASCII, so this
/// treats bytes >= 0x80 as literal Latin-1 rather than pulling in a full
/// Shift-JIS decoding dependency.
/// TODO: Add Shift-JIS support
fn decode_mfs_name(raw: &[u8]) -> String {
    raw.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect::<String>().trim().to_string()
}

fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl MfsVolume {
    /// Attempts to parse the MFS volume embedded in the RAM Area of a
    /// (logically-ordered, i.e. NDD/D64-style) disk buffer.
    pub fn parse(disk: &[u8], disk_type: u32, ram_start_lba: u16) -> Option<MfsVolume> {
        if ram_start_lba == 0xFFFF {
            return None;
        }
        let ram_start_offset = dd_geometry::ndd_rom_area_start(disk_type) + dd_geometry::lba_to_offset(disk_type, ram_start_lba as i32);
        let block_size = dd_geometry::size_of_lba(disk_type, ram_start_lba as i32);
        let total = block_size.checked_mul(6)?;
        if ram_start_offset.checked_add(total)? > disk.len() {
            return None;
        }
        let header_blob = &disk[ram_start_offset..ram_start_offset + total];
        if &header_blob[0..10] != MFS_MAGIC {
            return None;
        }

        let renewal_counter = read_u16(header_blob, 0x28);
        let checksum = read_u32(header_blob, 0x2c);
        let volname = decode_mfs_name(&header_blob[0x10..0x10 + 20]);
        let format_datetime = mfs_date_to_string(&header_blob[0x24..0x28]);
        let disk_type_in_header = header_blob[0xf];

        let fat_bytes = &header_blob[HEADER_SIZE..HEADER_SIZE + FAT_SIZE];
        #[allow(clippy::chunks_exact_to_as_chunks)] // `slice::as_chunks` is nightly-only
        let fat: Vec<u16> = fat_bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();

        let dir_start = HEADER_SIZE + FAT_SIZE;
        let dir_bytes = &header_blob[dir_start..];
        let maxfiles = dir_bytes.len() / DIR_ENTRY_SIZE;

        let mut entries = Vec::new();
        for i in 0..maxfiles {
            let ent = &dir_bytes[i * DIR_ENTRY_SIZE..(i + 1) * DIR_ENTRY_SIZE];
            let attr = read_u16(ent, 0);
            if attr == 0x0000 || attr == 0xFFFF {
                continue; // free/unused slot
            }
            let is_dir = attr & 0x8000 != 0;
            let is_file = attr & 0x4000 != 0;
            if !is_dir && !is_file {
                continue;
            }
            let parent_id = read_u16(ent, 2);
            let company_code = String::from_utf8_lossy(&ent[4..6]).trim_matches('\0').to_string();
            let game_code = String::from_utf8_lossy(&ent[6..10]).trim_matches('\0').to_string();
            let datetime = mfs_date_to_string(&ent[0x2c..0x30]);

            if is_dir {
                let dir_id2 = read_u16(ent, 0x0a);
                let name = decode_mfs_name(&ent[0x10..0x10 + 20]);
                entries.push(MfsEntry {
                    is_dir: true,
                    name,
                    parent_id,
                    id: dir_id2,
                    fat_entry: 0,
                    size: 0,
                    company_code,
                    game_code,
                    datetime,
                });
            } else {
                let fat_entry_num = read_u16(ent, 0x0a);
                let filesize = read_u32(ent, 0x0c);
                let base_name = decode_mfs_name(&ent[0x10..0x10 + 20]);
                let ext = decode_mfs_name(&ent[0x24..0x24 + 5]);
                let name = if ext.is_empty() { base_name } else { format!("{base_name}.{ext}") };
                entries.push(MfsEntry {
                    is_dir: false,
                    name,
                    parent_id,
                    id: fat_entry_num,
                    fat_entry: fat_entry_num,
                    size: filesize,
                    company_code,
                    game_code,
                    datetime,
                });
            }
        }

        Some(MfsVolume {
            valid: true,
            volname,
            format_datetime,
            renewal_counter,
            checksum,
            disk_type_in_header,
            entries,
            ram_start_offset,
            block_size,
            fat,
        })
    }

    /// Builds a full "/parent/child" path for a given entry, best-effort.
    pub fn full_path(&self, entry: &MfsEntry) -> String {
        let mut segments = vec![entry.name.clone()];
        let mut current_parent = entry.parent_id;
        let mut guard = 0;
        while current_parent != 0 && current_parent != 0xFFFE && guard < 64 {
            if let Some(dir) = self.entries.iter().find(|e| e.is_dir && e.id == current_parent) {
                segments.push(dir.name.clone());
                current_parent = dir.parent_id;
            } else {
                break;
            }
            guard += 1;
        }
        segments.reverse();
        format!("/{}", segments.join("/"))
    }

    /// Best-effort extraction of a file's raw bytes by following its FAT
    /// chain of RAM-area blocks. See module docs for the caveats.
    pub fn extract_file(&self, disk: &[u8], entry: &MfsEntry) -> Option<Vec<u8>> {
        if entry.is_dir {
            return None;
        }
        let mut out = Vec::with_capacity(entry.size as usize);
        let mut cluster = entry.fat_entry;
        let mut guard = 0usize;
        while (cluster as usize) < self.fat.len() && out.len() < entry.size as usize && guard < self.fat.len() {
            let offset = self.ram_start_offset + cluster as usize * self.block_size;
            if offset + self.block_size > disk.len() {
                break;
            }
            out.extend_from_slice(&disk[offset..offset + self.block_size]);
            let next = self.fat[cluster as usize];
            if next == 0 || next == cluster || next as usize >= self.fat.len() {
                break;
            }
            cluster = next;
            guard += 1;
        }
        out.truncate(entry.size as usize);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_returns_none_without_magic() {
        let disk = vec![0u8; dd_geometry::NDD_FILE_SIZE];
        assert!(MfsVolume::parse(&disk, 0, 0x100).is_none());
    }

    #[test]
    fn parse_returns_none_when_ram_unused() {
        let disk = vec![0u8; 1024];
        assert!(MfsVolume::parse(&disk, 0, 0xFFFF).is_none());
    }

    #[test]
    fn date_decoding_is_stable() {
        // 1996 + 0 = 1996, all-zero month/day/etc. should not panic.
        let s = mfs_date_to_string(&[0, 0, 0, 0]);
        assert!(s.starts_with("1996-"));
    }
}
