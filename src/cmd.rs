//! iQue Player content metadata (`.cmd`) parsing.
//!
//! Layout per the iQueBrew wiki "CMD" page (https://www.iquebrew.org/index.php?title=CMD)
//! and jbop1626/iquecrypt (https://github.com/jbop1626/iquecrypt), which was
//! used as a behavioural reference for what a `.cmd` file contains. This is a
//! read-only, independently written parser: no keys are derived and nothing
//! is decrypted.
//!
//! A CMD is an optional 0x2800-byte `contentDesc` followed by the 0x1AC-byte
//! `BbContentMetaDataHead`. All integers are big-endian. A CMD found next to
//! a ROM is *presumed* to describe it, but nothing here assumes that; use
//! [`CmdFile::compare_to_rom`] to see whether the two actually agree.

use std::path::{Path, PathBuf};

const DESC_LEN: usize = 0x2800;
const HEAD_LEN: usize = 0x1AC;
const FULL_LEN: usize = DESC_LEN + HEAD_LEN;
const MAX_THUMB_LEN: usize = 0x4000;
const MAX_TITLE_IMG_LEN: usize = 0x10000;

#[derive(Debug, Clone)]
pub struct ContentDesc {
    pub eeprom_addr: u32,
    pub eeprom_size: u32,
    pub flash_addr: u32,
    pub flash_size: u32,
    pub sram_addr: u32,
    pub sram_size: u32,
    pub cpak_addrs: [u32; 4],
    pub cpak_size: u32,
    pub os_rom_base: u32,
    pub os_tv_type: u32,
    pub os_mem_size: u32,
    pub tag: String,
    pub unknown_count: u8,
    pub thumb_len: u16,
    pub title_img_len: u16,
    /// Title name / ISBN text segments, decoded as ASCII / JIS X 0201 only
    /// (anything else shows as U+FFFD).
    pub title_text: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CmdHead {
    pub ca_crl_version: u32,
    pub cp_crl_version: u32,
    /// Size in bytes of the associated (plaintext) app.
    pub size: u32,
    pub desc_flags: u32,
    pub title_key_iv: [u8; 16],
    /// SHA-1 of the plaintext of the associated app.
    pub hash: [u8; 20],
    pub content_iv: [u8; 16],
    pub exec_flags: u32,
    pub hw_access_rights: u32,
    pub secure_kernel_rights: u32,
    pub bbid: u32,
    pub issuer: String,
    pub content_id: u32,
    /// Title key, still encrypted (once with the common key, and a second
    /// time for non-SA apps). Never decrypted by Turtle64.
    pub encrypted_title_key: [u8; 16],
    pub signature_present: bool,
}

#[derive(Debug, Clone)]
pub struct CmdFile {
    pub path: PathBuf,
    pub file_size: usize,
    pub desc: Option<ContentDesc>,
    pub head: CmdHead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdMatch {
    Match,
    Mismatch,
}

#[derive(Debug, Clone)]
pub struct CmdComparison {
    pub size: CmdMatch,
    pub hash: CmdMatch,
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn arr<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[o..o + N]);
    a
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn parse_desc(b: &[u8]) -> ContentDesc {
    let thumb_len = u16::from_be_bytes([b[0x44], b[0x45]]);
    let title_img_len = u16::from_be_bytes([b[0x46], b[0x47]]);
    let (t, i) = (thumb_len as usize, title_img_len as usize);
    let text_start = 0x48 + t + i;
    let title_text = if t <= MAX_THUMB_LEN && i <= MAX_TITLE_IMG_LEN && text_start < DESC_LEN {
        b[text_start..DESC_LEN].split(|&c| c == 0).map(crate::jisx0201::decode_field).filter(|s| !s.is_empty()).collect()
    } else {
        Vec::new()
    };
    ContentDesc {
        eeprom_addr: u32_at(b, 0x00),
        eeprom_size: u32_at(b, 0x04),
        flash_addr: u32_at(b, 0x08),
        flash_size: u32_at(b, 0x0C),
        sram_addr: u32_at(b, 0x10),
        sram_size: u32_at(b, 0x14),
        cpak_addrs: [u32_at(b, 0x18), u32_at(b, 0x1C), u32_at(b, 0x20), u32_at(b, 0x24)],
        cpak_size: u32_at(b, 0x28),
        os_rom_base: u32_at(b, 0x2C),
        os_tv_type: u32_at(b, 0x30),
        os_mem_size: u32_at(b, 0x34),
        tag: crate::jisx0201::decode_field(&b[0x40..0x43]),
        unknown_count: b[0x43],
        thumb_len,
        title_img_len,
        title_text,
    }
}

/// `h` is the 0x1AC-byte BbContentMetaDataHead (file offset 0x2800 in a full CMD).
fn parse_head(h: &[u8]) -> CmdHead {
    let issuer_raw = &h[0x58..0x98];
    let end = issuer_raw.iter().position(|&c| c == 0).unwrap_or(issuer_raw.len());
    CmdHead {
        ca_crl_version: u32_at(h, 0x04),
        cp_crl_version: u32_at(h, 0x08),
        size: u32_at(h, 0x0C),
        desc_flags: u32_at(h, 0x10),
        title_key_iv: arr(h, 0x14),
        hash: arr(h, 0x24),
        content_iv: arr(h, 0x38),
        exec_flags: u32_at(h, 0x48),
        hw_access_rights: u32_at(h, 0x4C),
        secure_kernel_rights: u32_at(h, 0x50),
        bbid: u32_at(h, 0x54),
        issuer: crate::jisx0201::decode_field(&issuer_raw[..end]),
        content_id: u32_at(h, 0x98),
        encrypted_title_key: arr(h, 0x9C),
        signature_present: h[0xAC..0x1AC].iter().any(|&c| c != 0),
    }
}

impl CmdFile {
    pub fn parse(path: &Path, data: &[u8]) -> anyhow::Result<Self> {
        let (desc, head) = if data.len() >= FULL_LEN {
            (Some(parse_desc(&data[..DESC_LEN])), parse_head(&data[DESC_LEN..FULL_LEN]))
        } else if data.len() == HEAD_LEN {
            (None, parse_head(data))
        } else {
            anyhow::bail!("unexpected .cmd size {} bytes (expected {FULL_LEN} with contentDesc, or {HEAD_LEN} without)", data.len());
        };
        Ok(CmdFile { path: path.to_path_buf(), file_size: data.len(), desc, head })
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Self::parse(path, &std::fs::read(path)?)
    }

    /// Compares the CMD's recorded app size and SHA-1 against a ROM's
    /// big-endian-normalized size and SHA-1 (hex, any case). A CMD describes
    /// the *plaintext* app, so an encrypted or modified ROM will not match.
    pub fn compare_to_rom(&self, rom_size: u64, rom_sha1_hex: &str) -> CmdComparison {
        let m = |b: bool| if b { CmdMatch::Match } else { CmdMatch::Mismatch };
        CmdComparison { size: m(u64::from(self.head.size) == rom_size), hash: m(hex(&self.head.hash).eq_ignore_ascii_case(rom_sha1_hex)) }
    }
}

/// Looks for a `.cmd` file in the same folder as `rom_path` with the same
/// file stem (case-insensitive), e.g. `0098967F.z64` -> `0098967F.cmd`.
pub fn find_alongside(rom_path: &Path) -> Option<PathBuf> {
    let dir = rom_path.parent()?;
    let stem = rom_path.file_stem()?.to_string_lossy().to_lowercase();
    std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).find(|p| {
        p.is_file()
            && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("cmd"))
            && p.file_stem().is_some_and(|s| s.to_string_lossy().to_lowercase() == stem)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut d = vec![0u8; FULL_LEN];
        d[0x04..0x08].copy_from_slice(&0x200u32.to_be_bytes());
        d[0x40..0x43].copy_from_slice(b"CAM");
        d[0x44..0x46].copy_from_slice(&2u16.to_be_bytes());
        d[0x46..0x48].copy_from_slice(&1u16.to_be_bytes());
        d[0x4B..0x4B + 4].copy_from_slice(b"TEST");
        let h = DESC_LEN;
        d[h + 0x0C..h + 0x10].copy_from_slice(&0x0800_0000u32.to_be_bytes());
        d[h + 0x24..h + 0x38].fill(0xAB);
        d[h + 0x58..h + 0x5C].copy_from_slice(b"Root");
        d[h + 0x98..h + 0x9C].copy_from_slice(&0x0098_967Fu32.to_be_bytes());
        d[h + 0xAC] = 1;
        d
    }

    #[test]
    fn parses_full_cmd() {
        let c = CmdFile::parse(Path::new("x.cmd"), &sample()).unwrap();
        let desc = c.desc.unwrap();
        assert_eq!(desc.eeprom_size, 0x200);
        assert_eq!(desc.tag, "CAM");
        assert_eq!(desc.title_text, vec!["TEST".to_string()]);
        assert_eq!(c.head.size, 0x0800_0000);
        assert_eq!(c.head.issuer, "Root");
        assert_eq!(c.head.content_id, 0x0098_967F);
        assert!(c.head.signature_present);
    }

    #[test]
    fn parses_head_only_and_rejects_bad_sizes() {
        let d = sample();
        assert!(CmdFile::parse(Path::new("x.cmd"), &d[DESC_LEN..]).unwrap().desc.is_none());
        assert!(CmdFile::parse(Path::new("x.cmd"), &d[..100]).is_err());
    }

    #[test]
    fn compares_against_rom() {
        let c = CmdFile::parse(Path::new("x.cmd"), &sample()).unwrap();
        let ok = c.compare_to_rom(0x0800_0000, &"ab".repeat(20));
        assert_eq!((ok.size, ok.hash), (CmdMatch::Match, CmdMatch::Match));
        let bad = c.compare_to_rom(1, &"00".repeat(20));
        assert_eq!((bad.size, bad.hash), (CmdMatch::Mismatch, CmdMatch::Mismatch));
    }
}
