//! 64DD disk geometry: zone/track/LBA tables shared by disk-info parsing and
//! format conversion. Independently reimplemented in Rust from the publicly
//! documented 64DD disk geometry (LuigiBlood's 64dd wiki "Disk Image Formats"
//! / "CIC" pages, and the field layouts described by jkbenaim's leotools and
//! LuigiBlood's leo64dd_python `DOC.md`) — these tables describe the physical
//! geometry of a real 64DD disk (fixed by the hardware), not any project's
//! original source code.

/// Number of logical LBAs in a full 64DD disk image (System Area included).
#[allow(dead_code)]
pub const NDD_LBA_COUNT: usize = 4316;
/// Sectors that make up one LBA block.
pub const SECTORS_PER_BLOCK: usize = 85;
/// Fixed file size of the `.ndd` (64DD Disk Dumper) image format.
pub const NDD_FILE_SIZE: usize = 0x3DEC800;
/// Byte size of the System Data / Disk ID areas.
#[allow(dead_code)]
pub const SYS_DATA_SIZE: usize = 232;

/// Region magic values found at offset 0x00 of the System Data.
pub const REGION_JAPAN: u32 = 0xE848D316;
pub const REGION_USA: u32 = 0x2263EE56;
pub const REGION_DEV: u32 = 0x0000_0000;

// ---------------------------------------------------------------------
// "Logical" (LBA-ordered) geometry — used by the NDD and D64 formats.
// A disk has 7 known "disk types" (0-6) that determine how LBAs map to
// physical zones, and therefore how many bytes each LBA block occupies.
// ---------------------------------------------------------------------

/// For each disk type, the highest LBA belonging to each of 16 successive
/// geometry "bands" (cumulative boundary, inclusive).
const BAND_LBA_BOUND: [[i32; 16]; 7] = [
    [267, 559, 833, 1125, 1417, 1691, 1965, 2239, 2513, 2717, 2921, 3195, 3469, 3743, 4017, 4291],
    [267, 559, 833, 1107, 1381, 1673, 1965, 2239, 2513, 2787, 2991, 3195, 3469, 3743, 4017, 4291],
    [267, 559, 833, 1107, 1381, 1655, 1929, 2221, 2513, 2787, 3061, 3265, 3469, 3743, 4017, 4291],
    [267, 559, 833, 1107, 1381, 1655, 1929, 2203, 2477, 2769, 3061, 3335, 3539, 3743, 4017, 4291],
    [267, 559, 833, 1107, 1381, 1655, 1929, 2203, 2477, 2751, 3025, 3317, 3609, 3813, 4017, 4291],
    [267, 559, 833, 1107, 1381, 1655, 1929, 2133, 2407, 2681, 2955, 3229, 3503, 3795, 4087, 4291],
    [267, 559, 833, 1107, 1381, 1655, 1929, 2133, 2337, 2611, 2885, 3159, 3433, 3707, 3999, 4291],
];

/// For each disk type, the "band id" (0-15) that corresponds to each boundary
/// entry above, in physical disk order.
const BAND_ORDER: [[usize; 16]; 7] = [
    [0, 1, 2, 14, 15, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    [0, 1, 2, 3, 13, 14, 15, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    [0, 1, 2, 3, 4, 12, 13, 14, 15, 5, 6, 7, 8, 9, 10, 11],
    [0, 1, 2, 3, 4, 5, 11, 12, 13, 14, 15, 6, 7, 8, 9, 10],
    [0, 1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 7, 8, 9],
    [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 8],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
];

/// Maps a band id (0-15) to one of 9 "size zones" that determine block size.
const BAND_TO_SIZE_ZONE: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];

/// Byte size of one LBA block for each of the 9 size zones.
const SIZE_ZONE_BLOCK_BYTES: [usize; 9] = [19720, 18360, 17680, 16320, 14960, 13600, 12240, 10880, 9520];

/// Returns `true` if `disk_type` (0-6) is a recognized 64DD disk type.
pub fn is_valid_disk_type(disk_type: u32) -> bool {
    (disk_type as usize) < BAND_LBA_BOUND.len()
}

/// Byte size of a single LBA block, given the disk type and LBA index.
pub fn size_of_lba(disk_type: u32, lba: i32) -> usize {
    let dt = (disk_type as usize).min(BAND_LBA_BOUND.len() - 1);
    let mut band = 0usize;
    for i in (0..16).rev() {
        if lba <= BAND_LBA_BOUND[dt][i] {
            band = BAND_ORDER[dt][i];
        } else {
            break;
        }
    }
    SIZE_ZONE_BLOCK_BYTES[BAND_TO_SIZE_ZONE[band]]
}

/// Cumulative byte offset of LBA `lba` relative to LBA 0, for the given disk
/// type (i.e. the sum of the sizes of all LBAs before it).
pub fn lba_to_offset(disk_type: u32, lba: i32) -> usize {
    let mut offset = 0usize;
    for l in 0..lba {
        offset += size_of_lba(disk_type, l);
    }
    offset
}

/// Byte offset (from the very start of a full NDD-style dump, i.e. including
/// the System Area) of Disk ID (LBA 14). This is always the same because the
/// first 14 LBAs are always within the largest/outermost geometry band.
pub fn ndd_disk_id_offset() -> usize {
    lba_to_offset(0, 14)
}

/// Byte offset (from the start of a full NDD-style dump) where the ROM Area
/// begins (base LBA 24, i.e. right after the System Area).
pub fn ndd_rom_area_start(disk_type: u32) -> usize {
    lba_to_offset(0, 24) + lba_to_offset(disk_type, 0)
}

/// Byte size of the ROM Area, given `rom_end_lba` from the System Data
/// (LBA numbering relative to base LBA 24).
pub fn rom_area_size(disk_type: u32, rom_end_lba: u16) -> usize {
    lba_to_offset(disk_type, rom_end_lba as i32 + 1)
}

/// Byte size of the RAM Area, given `ram_start_lba`/`ram_end_lba` from the
/// System Data (both relative to base LBA 24). Returns 0 if unused (0xFFFF).
pub fn ram_area_size(disk_type: u32, ram_start_lba: u16, ram_end_lba: u16) -> usize {
    if ram_start_lba == 0xFFFF || ram_end_lba == 0xFFFF {
        return 0;
    }
    lba_to_offset(disk_type, ram_end_lba as i32 + 1) - lba_to_offset(disk_type, ram_start_lba as i32)
}

// ---------------------------------------------------------------------
// Physical (track-ordered) geometry — used by the MAME disk image format.
// Ported/reimplemented from the publicly published `ddconvert` algorithm
// (Happy-yappH / LuigiBlood) which documents how MAME lays out disks in
// physical head/zone/track order.
// ---------------------------------------------------------------------

pub const PHYS_ZONE_SECTOR_SIZE: [usize; 16] = [232, 216, 208, 192, 176, 160, 144, 128, 216, 208, 192, 176, 160, 144, 128, 112];
pub const PHYS_ZONE_TRACKS: [usize; 16] = [158, 158, 149, 149, 149, 149, 149, 114, 158, 158, 149, 149, 149, 149, 149, 114];

pub const DISK_TYPE_ZONES: [[usize; 16]; 7] = [
    [0, 1, 2, 9, 8, 3, 4, 5, 6, 7, 15, 14, 13, 12, 11, 10],
    [0, 1, 2, 3, 10, 9, 8, 4, 5, 6, 7, 15, 14, 13, 12, 11],
    [0, 1, 2, 3, 4, 11, 10, 9, 8, 5, 6, 7, 15, 14, 13, 12],
    [0, 1, 2, 3, 4, 5, 12, 11, 10, 9, 8, 6, 7, 15, 14, 13],
    [0, 1, 2, 3, 4, 5, 6, 13, 12, 11, 10, 9, 8, 7, 15, 14],
    [0, 1, 2, 3, 4, 5, 6, 7, 14, 13, 12, 11, 10, 9, 8, 15],
    [0, 1, 2, 3, 4, 5, 6, 7, 15, 14, 13, 12, 11, 10, 9, 8],
];

pub const REV_DISK_TYPE_ZONES: [[usize; 16]; 7] = [
    [0, 1, 2, 5, 6, 7, 8, 9, 4, 3, 15, 14, 13, 12, 11, 10],
    [0, 1, 2, 3, 7, 8, 9, 10, 6, 5, 4, 15, 14, 13, 12, 11],
    [0, 1, 2, 3, 4, 9, 10, 11, 8, 7, 6, 5, 15, 14, 13, 12],
    [0, 1, 2, 3, 4, 5, 11, 12, 10, 9, 8, 7, 6, 15, 14, 13],
    [0, 1, 2, 3, 4, 5, 6, 13, 12, 11, 10, 9, 8, 7, 15, 14],
    [0, 1, 2, 3, 4, 5, 6, 7, 14, 13, 12, 11, 10, 9, 8, 15],
    [0, 1, 2, 3, 4, 5, 6, 7, 15, 14, 13, 12, 11, 10, 9, 8],
];

pub const START_BLOCK: [[usize; 16]; 7] = [
    [0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1],
    [0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0],
    [0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1],
    [0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0],
    [0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1],
    [0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0],
    [0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1],
];

pub fn phys_block_size(zone: usize) -> usize {
    PHYS_ZONE_SECTOR_SIZE[zone] * SECTORS_PER_BLOCK
}
pub fn phys_track_size(zone: usize) -> usize {
    phys_block_size(zone) * 2
}
pub fn phys_zone_size(zone: usize) -> usize {
    phys_track_size(zone) * PHYS_ZONE_TRACKS[zone]
}
pub fn phys_vzone_size(zone: usize) -> usize {
    phys_track_size(zone) * (PHYS_ZONE_TRACKS[zone] - 0xC)
}

/// Total byte size of a full physical (MAME) disk image for a given disk type.
pub fn mame_file_size() -> usize {
    (0..16).map(phys_zone_size).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndd_disk_id_offset_matches_known_value() {
        // leotools' leoimginfo.c reads Disk ID at a fixed offset of 276080
        // bytes regardless of disk type (14 * 19720).
        assert_eq!(ndd_disk_id_offset(), 276080);
    }

    #[test]
    fn rom_area_start_is_stable_for_all_disk_types() {
        for dt in 0..7 {
            assert_eq!(ndd_rom_area_start(dt), 19720 * 24);
        }
    }

    #[test]
    fn mame_size_is_plausible_and_deterministic() {
        let size = mame_file_size();
        assert!(size > 60_000_000 && size < 80_000_000);
        assert_eq!(size, mame_file_size());
    }
}
