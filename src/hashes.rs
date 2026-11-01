//! Modern file hashing: CRC32, MD5, SHA-1, plus the non-cryptographic FNV-1a (64-bit)
//! and xxHash (XXH64) checksums. Computed against the big-endian
//! normalized representation of the ROM, matching the convention used by
//! No-Intro / Redump style DAT databases for N64.

use md5::{Digest, Md5};
use sha1::Sha1;
use std::hash::Hasher;

#[derive(Debug, Clone)]
pub struct RomHashes {
    pub crc32: u32,
    pub md5: String,
    pub sha1: String,
    /// FNV-1a, 64-bit (via the `fnv64-rs` crate).
    pub fnv1a64: u64,
    pub xxh64: u64,
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

    let mut fnv = fnv64_rs::Fnv1aHasher::default();
    fnv.write(be_data);
    let fnv1a64 = fnv.finish();

    RomHashes { crc32, md5, sha1, fnv1a64, xxh64: xxhash_rust::xxh64::xxh64(be_data, 0), size: be_data.len() as u64 }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_cryptographic_hashes_match_known_vectors() {
        let empty = compute_hashes(b"");
        assert_eq!(empty.fnv1a64, 0xcbf2_9ce4_8422_2325);
        assert_eq!(empty.xxh64, 0xEF46_DB37_51D8_E999);
        assert_eq!(compute_hashes(b"a").fnv1a64, 0xaf63_dc4c_8601_ec8c);
    }
}
