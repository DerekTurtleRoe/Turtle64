//! Conversion between the three 64DD disk image formats: `.ndd` (raw
//! LBA-ordered dump), `.d64` (SDK master disk format), and MAME's
//! physical-track-ordered format.
//!
//! **D64 is a lossy, heavily trimmed format.** Per LuigiBlood's 64dd wiki:
//! "This master disk file being as small as possible also means all
//! unnecessary data are not present unlike a fully dumped disk." A D64 is
//! only System Data + Disk ID + the ROM/RAM Area payload (typically tens of
//! MB), whereas a full NDD/MAME dump is a fixed ~64.5 MB regardless of how
//! much of the disk the game actually uses. Converting NDD/MAME -> D64
//! throws away the defect-track table, exact physical LBA sizing, and all
//! disk padding; converting D64 -> NDD/MAME cannot recover any of that and
//! instead reconstructs an idealized, defect-free "freshly formatted" disk.
//! Do not use D64 as an archival/round-trip format if you need a bit-exact
//! copy of an original dump — prefer NDD or MAME for that.
//!
//! The NDD <-> D64 conversion is derived directly from the field layout
//! documented on LuigiBlood's 64dd wiki ("Disk Image Formats" page) — both
//! formats share LBA-ordered addressing, so converting between them is a
//! matter of locating/trimming/padding the System Data, Disk ID, ROM Area
//! and RAM Area using the shared geometry tables in `dd_geometry`.
//!
//! The MAME <-> logical (NDD-ordered) conversion is a fresh reimplementation
//! of the publicly documented physical zone/track layout used by the
//! `ddconvert` / `ddconvert_back` tools (Happy-yappH / LuigiBlood): both
//! directions are implemented as literal inverses of the same per-track
//! "de/interleave" operation, so a disk with no marked defect tracks will
//! round-trip byte-for-byte through NDD -> MAME -> NDD. Disks that report
//! defect tracks in their System Data are *not* specially handled (no alt
//! track injection) — this is flagged to the user rather than silently
//! producing a subtly-wrong image.

use crate::dd_disk::SysData;
use crate::dd_geometry as geo;

/// Best-effort Disk Destination Code, derived from the last character of a
/// disk's 4-character game code (mirroring cartridge ROM convention). Real
/// n64mdisk-produced D64s store this explicitly at offset 0x1E8; NDD/MAME
/// dumps don't carry it separately, so we reconstruct our best guess.
pub fn destination_code_from_game_code(code: &[u8]) -> u8 {
    match code.last().copied().unwrap_or(b'J') {
        b'J' => 0x00,
        b'E' => 0x01,
        b'P' => 0x02,
        b'F' => 0x06,
        b'H' => 0x07,
        b'S' => 0x08,
        b'D' => 0x09,
        b'I' => 0x0A,
        b'C' => 0x0B,
        b'K' => 0x0D,
        b'A' => 0x11,
        _ => 0x00,
    }
}

pub fn destination_name(code: u8) -> &'static str {
    match code {
        0x00 => "Japan",
        0x01 => "North America",
        0x02 => "Europe",
        0x03 => "Europe (North)",
        0x06 => "Europe (France)",
        0x07 => "Holland",
        0x08 => "Spain",
        0x09 => "Germany",
        0x0A => "Italy",
        0x0B => "China",
        0x0D => "Korea",
        0x0F => "Canada",
        0x10 => "Brazil",
        0x11 => "Australia",
        _ => "Unknown",
    }
}

/// Converts a logically-ordered (NDD-style) disk buffer to the compact D64
/// master disk format.
///
/// **This is a lossy, trimming conversion.** The output keeps only the
/// System Data, Disk ID, and the actual ROM/RAM Area payload — it discards
/// the defect-track table, physical LBA boundary/formatting fields, and all
/// of the disk padding that a full NDD/MAME dump carries. The resulting
/// file is typically tens of MB instead of the fixed ~64.5 MB of an NDD/MAME
/// image. None of the discarded data can be recovered later.
pub fn logical_to_d64(logical: &[u8], sys: &SysData) -> Vec<u8> {
    let rom_size = geo::rom_area_size(sys.disk_type, sys.rom_end_lba);
    let ram_size = geo::ram_area_size(sys.disk_type, sys.ram_start_lba, sys.ram_end_lba);
    let mut out = vec![0u8; 0x200 + rom_size + ram_size];

    let copy_len = 232.min(logical.len());
    out[..copy_len].copy_from_slice(&logical[..copy_len]);
    // Disk formatting-specific fields (defect track table + boundaries) are
    // not meaningful in the compact D64 format, and are permanently lost by
    // this conversion; zero them per spec.
    for b in out.iter_mut().take(0x20).skip(0x08) {
        *b = 0;
    }

    let diskid_off = geo::ndd_disk_id_offset();
    if diskid_off + 232 <= logical.len() {
        out[0x100..0x100 + 232].copy_from_slice(&logical[diskid_off..diskid_off + 232]);
    }
    out[0x1E8] = destination_code_from_game_code(&logical[diskid_off..diskid_off + 4.min(logical.len().saturating_sub(diskid_off))]);

    let rom_start = geo::ndd_rom_area_start(sys.disk_type);
    let rom_avail = logical.len().saturating_sub(rom_start).min(rom_size);
    out[0x200..0x200 + rom_avail].copy_from_slice(&logical[rom_start..rom_start + rom_avail]);

    if ram_size > 0 {
        let ram_start = rom_start + geo::lba_to_offset(sys.disk_type, sys.ram_start_lba as i32);
        let ram_avail = logical.len().saturating_sub(ram_start).min(ram_size);
        let dst = 0x200 + rom_size;
        out[dst..dst + ram_avail].copy_from_slice(&logical[ram_start..ram_start + ram_avail]);
    }
    out
}

/// Expands a compact D64 master disk image back into a full logically
/// ordered (NDD-style) buffer.
///
/// **This is a lossy expansion, not a true restoration.** Real disk
/// formatting metadata (defect tracks, physical LBA boundary info) and the
/// disk's original padding are not present in a D64 file — because
/// `logical_to_d64` already trimmed them away — so the result approximates
/// a "freshly formatted, defect-free" retail disk rather than reproducing
/// the exact original dump byte-for-byte.
pub fn d64_to_logical(d64: &[u8], sys: &SysData) -> Vec<u8> {
    let mut out = vec![0u8; geo::NDD_FILE_SIZE];
    let copy_len = 232.min(d64.len());
    out[..copy_len].copy_from_slice(&d64[..copy_len]);

    let diskid_off = geo::ndd_disk_id_offset();
    let diskid_avail = d64.len().saturating_sub(0x100).min(232);
    out[diskid_off..diskid_off + diskid_avail].copy_from_slice(&d64[0x100..0x100 + diskid_avail]);

    let rom_start = geo::ndd_rom_area_start(sys.disk_type);
    let rom_size = geo::rom_area_size(sys.disk_type, sys.rom_end_lba);
    let rom_avail = d64.len().saturating_sub(0x200).min(rom_size);
    out[rom_start..rom_start + rom_avail].copy_from_slice(&d64[0x200..0x200 + rom_avail]);
    for b in out.iter_mut().skip(rom_start + rom_avail).take(rom_size - rom_avail) {
        *b = 0xFF;
    }

    let ram_size = geo::ram_area_size(sys.disk_type, sys.ram_start_lba, sys.ram_end_lba);
    if ram_size > 0 {
        let ram_start = rom_start + geo::lba_to_offset(sys.disk_type, sys.ram_start_lba as i32);
        let ram_src_start = 0x200 + rom_size;
        let ram_avail = d64.len().saturating_sub(ram_src_start).min(ram_size);
        out[ram_start..ram_start + ram_avail].copy_from_slice(&d64[ram_src_start..ram_src_start + ram_avail]);
        for b in out.iter_mut().skip(ram_start + ram_avail).take(ram_size - ram_avail) {
            *b = 0xFF;
        }
    }
    out
}

/// `true` if the disk's System Data reports any defect (bad) tracks, in
/// which case MAME-format conversion will not exactly reproduce them.
pub fn has_defect_tracks(sys_bytes: &[u8]) -> bool {
    sys_bytes.len() >= 0x20 && sys_bytes[0x08..0x18].iter().any(|&b| b != 0)
}

fn zone_start_tables(disk_type: usize) -> ([usize; 16], [usize; 16]) {
    let mut in_start = [0usize; 16];
    let mut out_start = [0usize; 16];
    for zone in 1..16 {
        in_start[zone] = in_start[zone - 1] + geo::phys_vzone_size(geo::DISK_TYPE_ZONES[disk_type][zone - 1]);
        out_start[zone] = out_start[zone - 1] + geo::phys_zone_size(zone - 1);
    }
    (in_start, out_start)
}

/// De/interleaves one track's two blocks between `src` and `dst` according
/// to the block parity for that track. This operation is its own inverse:
/// calling it twice with the same parity, swapping src/dst, restores the
/// original data — which is what lets `logical_to_mame`/`mame_to_logical`
/// share this single routine.
fn transfer_track(src: &[u8], src_off: usize, dst: &mut [u8], dst_off: usize, block_size: usize, parity_odd: bool) {
    if src_off + block_size * 2 > src.len() || dst_off + block_size * 2 > dst.len() {
        return;
    }
    let (a_off, b_off) = if parity_odd { (src_off + block_size, src_off) } else { (src_off, src_off + block_size) };
    dst[dst_off..dst_off + block_size].copy_from_slice(&src[a_off..a_off + block_size]);
    dst[dst_off + block_size..dst_off + block_size * 2].copy_from_slice(&src[b_off..b_off + block_size]);
}

/// Converts a logically-ordered (NDD-style) disk buffer into MAME's
/// physical track-ordered format. Assumes no defect tracks (see module docs).
pub fn logical_to_mame(logical: &[u8], disk_type: u32) -> Vec<u8> {
    let dt = (disk_type as usize).min(6);
    let (in_start, out_start) = zone_start_tables(dt);
    let mut mame = vec![0u8; geo::mame_file_size()];

    for zone in 0..8 {
        let block_size = geo::phys_block_size(zone);
        let track_size = block_size * 2;
        let in_zone = in_start[geo::REV_DISK_TYPE_ZONES[dt][zone]];
        let out_zone = out_start[zone];
        let mut block = geo::START_BLOCK[dt][zone];
        for track in 0..geo::PHYS_ZONE_TRACKS[zone] {
            transfer_track(logical, in_zone + track * track_size, &mut mame, out_zone + track * track_size, block_size, block % 2 == 1);
            block = 1 - block;
        }
    }
    for zone in 8..16 {
        let block_size = geo::phys_block_size(zone);
        let track_size = block_size * 2;
        let in_zone = in_start[geo::REV_DISK_TYPE_ZONES[dt][zone]];
        let out_zone = out_start[zone];
        let mut block = geo::START_BLOCK[dt][zone];
        let tracks = geo::PHYS_ZONE_TRACKS[zone];
        for track in 0..tracks {
            let src_off = in_zone + track * track_size;
            let dst_off = out_zone + (tracks - 1 - track) * track_size;
            transfer_track(logical, src_off, &mut mame, dst_off, block_size, block % 2 == 1);
            block = 1 - block;
        }
    }
    mame
}

/// Converts a MAME physical track-ordered disk buffer back into logical
/// (NDD-style) LBA order. See module docs re: defect tracks.
pub fn mame_to_logical(mame: &[u8], disk_type: u32) -> Vec<u8> {
    let dt = (disk_type as usize).min(6);
    let (in_start, out_start) = zone_start_tables(dt);
    let mut logical = vec![0u8; geo::NDD_FILE_SIZE];

    for zone in 0..8 {
        let block_size = geo::phys_block_size(zone);
        let track_size = block_size * 2;
        let out_zone = in_start[geo::REV_DISK_TYPE_ZONES[dt][zone]];
        let in_zone = out_start[zone];
        let mut block = geo::START_BLOCK[dt][zone];
        for track in 0..geo::PHYS_ZONE_TRACKS[zone] {
            transfer_track(mame, in_zone + track * track_size, &mut logical, out_zone + track * track_size, block_size, block % 2 == 1);
            block = 1 - block;
        }
    }
    for zone in 8..16 {
        let block_size = geo::phys_block_size(zone);
        let track_size = block_size * 2;
        let out_zone = in_start[geo::REV_DISK_TYPE_ZONES[dt][zone]];
        let in_zone = out_start[zone];
        let mut block = geo::START_BLOCK[dt][zone];
        let tracks = geo::PHYS_ZONE_TRACKS[zone];
        for track in 0..tracks {
            let dst_off = out_zone + track * track_size;
            let src_off = in_zone + (tracks - 1 - track) * track_size;
            transfer_track(mame, src_off, &mut logical, dst_off, block_size, block % 2 == 1);
            block = 1 - block;
        }
    }
    logical
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern_ndd() -> Vec<u8> {
        let mut buf = vec![0u8; geo::NDD_FILE_SIZE];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        // Disk type 0, region Japan retail, keep valid-looking fields.
        buf[0..4].copy_from_slice(&geo::REGION_JAPAN.to_be_bytes());
        buf[5] = 0x10; // disk_type 0, retail
        for b in buf.iter_mut().take(0x20).skip(0x08) {
            *b = 0; // no defects
        }
        buf
    }

    #[test]
    fn mame_round_trip_matches_original_when_defect_free() {
        let ndd = pattern_ndd();
        let mame = logical_to_mame(&ndd, 0);
        let back = mame_to_logical(&mame, 0);
        // Only the System Area + first zone are guaranteed touched by every
        // disk type/track combination; compare the whole logical stream.
        assert_eq!(ndd, back);
    }

    #[test]
    fn d64_round_trip_preserves_rom_area() {
        let mut ndd = pattern_ndd();
        // Set rom_end_lba small so the test stays fast.
        ndd[0xE0..0xE2].copy_from_slice(&10u16.to_be_bytes());
        ndd[0xE2..0xE4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        ndd[0xE4..0xE6].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let sys = SysData::parse(&ndd[0..232]);
        let d64 = logical_to_d64(&ndd, &sys);
        let back = d64_to_logical(&d64, &sys);
        let rom_start = geo::ndd_rom_area_start(sys.disk_type);
        let rom_size = geo::rom_area_size(sys.disk_type, sys.rom_end_lba);
        assert_eq!(&ndd[rom_start..rom_start + rom_size], &back[rom_start..rom_start + rom_size]);
    }
}
