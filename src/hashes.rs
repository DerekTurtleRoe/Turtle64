//! Modern file hashing: CRC32, MD5, SHA-1. Computed against the big-endian
//! normalized representation of the ROM, matching the convention used by
//! No-Intro / Redump style DAT databases for N64.

use md5::{Digest, Md5};
use sha1::Sha1;

#[derive(Debug, Clone)]
pub struct RomHashes {
    pub crc32: u32,
    pub md5: String,
    pub sha1: String,
    #[allow(dead_code)]
    pub size: u64,
}

pub fn compute_hashes(be_data: &[u8]) -> RomHashes {
    let mut crc_hasher = crc32fast::Hasher::new();
    crc_hasher.update(be_data);
    let crc32 = crc_hasher.finalize();

    let mut md5_hasher = Md5::new();
    md5_hasher.update(be_data);
    let md5 = hex::encode(md5_hasher.finalize());

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(be_data);
    let sha1 = hex::encode(sha1_hasher.finalize());

    RomHashes { crc32, md5, sha1, size: be_data.len() as u64 }
}

/// Minimal local hex-encoding helper to avoid pulling in the `hex` crate.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}
