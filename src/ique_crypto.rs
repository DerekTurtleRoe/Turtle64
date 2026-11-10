//! Decryption of encrypted iQue Player content (`.app` / `.rec` files).
//!
//! Turtle64 ships **no keys of any kind**. Every secret (common key, title
//! key, Virage2 dump, `recrypt.sys`) must be supplied by the user from their
//! own console or legally obtained files.
//!
//! Formats: iQueBrew wiki (CMD, Ticket, Recrypt.sys, Virage2). Independent
//! implementation; jbop1626/iquecrypt was used as a behavioral reference only.

use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};
use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};
use std::path::Path;

pub const VIRAGE2_SIZE: usize = 0x100;
const V2_BBID: usize = 0x94;
const V2_RECRYPT_LIST_KEY: usize = 0xC8;
const RSYS_ENTRIES_OFFSET: usize = 0x44;
const RSYS_ENTRY_SIZE: usize = 32;

/// How the AES-128 key for the content is obtained.
pub enum KeySource<'a> {
    /// A plaintext 16-byte key (e.g. a decrypted title key) and IV.
    Direct { key: [u8; 16], iv: [u8; 16] },
    /// Title key from the `.cmd`, decrypted once with the user's common key
    /// (valid for apps with the "SA" flag).
    CommonKey { common_key: [u8; 16], encrypted_title_key: [u8; 16], title_key_iv: [u8; 16], content_iv: [u8; 16] },
    /// A `.rec` re-encrypted by a console: key looked up in `recrypt.sys`.
    Recrypt { virage2: &'a [u8], recrypt_sys: &'a [u8], content_id: u32, content_iv: [u8; 16] },
}

pub fn parse_hex16(s: &str) -> Result<[u8; 16]> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    let clean = clean.strip_prefix("0x").unwrap_or(&clean);
    if clean.len() != 32 || !clean.is_ascii() {
        bail!("expected exactly 32 hexadecimal digits (16 bytes)");
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).map_err(|_| anyhow!("invalid hexadecimal digit"))?;
    }
    Ok(out)
}

/// Reads a 16-byte key from hex text, or from a 16-byte binary file.
pub fn read_key_file(path: &Path) -> Result<[u8; 16]> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if data.len() == 16 {
        let mut k = [0u8; 16];
        k.copy_from_slice(&data);
        return Ok(k);
    }
    let text = String::from_utf8(data).map_err(|_| anyhow!("key file must be 16 raw bytes or 32 hex digits"))?;
    parse_hex16(text.trim())
}

pub fn aes_cbc_decrypt(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        bail!("input size ({} bytes) is not a non-zero multiple of 16", data.len());
    }
    let mut buf = data.to_vec();
    cbc::Decryptor::<Aes128>::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| anyhow!("AES decryption failed"))?;
    Ok(buf)
}

/// Finds the recrypt key for `content_id` in `recrypt.sys` using the console's Virage2 dump.
pub fn find_recrypt_key(virage2: &[u8], recrypt_sys: &[u8], content_id: u32) -> Result<[u8; 16]> {
    if virage2.len() < VIRAGE2_SIZE {
        bail!("Virage2 dump must be at least {VIRAGE2_SIZE} bytes (got {})", virage2.len());
    }
    if recrypt_sys.len() < RSYS_ENTRIES_OFFSET {
        bail!("recrypt.sys is too small");
    }
    let mut list_key = [0u8; 16];
    list_key.copy_from_slice(&virage2[V2_RECRYPT_LIST_KEY..V2_RECRYPT_LIST_KEY + 16]);
    let bbid = u32::from_be_bytes(virage2[V2_BBID..V2_BBID + 4].try_into()?);
    let mut iv = [0u8; 16];
    for (i, chunk) in iv.chunks_mut(4).enumerate() {
        chunk.copy_from_slice(&bbid.wrapping_add(i as u32).to_be_bytes());
    }
    let count = u32::from_be_bytes(recrypt_sys[0x40..0x44].try_into()?) as usize;
    let avail = (recrypt_sys.len() - RSYS_ENTRIES_OFFSET) / RSYS_ENTRY_SIZE;
    if count == 0 || count > avail {
        bail!("recrypt.sys entry count ({count}) is invalid for its size");
    }
    let wanted = content_id.to_be_bytes();
    // Each 32-byte entry is its own CBC stream starting from the same IV.
    let entries = &recrypt_sys[RSYS_ENTRIES_OFFSET..RSYS_ENTRIES_OFFSET + count * RSYS_ENTRY_SIZE];
    let (entries, _) = entries.as_chunks::<RSYS_ENTRY_SIZE>();
    for e in entries {
        let plain = aes_cbc_decrypt(e, &list_key, &iv)?;
        if plain[..4] == wanted {
            let mut k = [0u8; 16];
            k.copy_from_slice(&plain[4..20]);
            return Ok(k);
        }
    }
    bail!("no recrypt.sys entry for content ID {content_id:08X} (wrong console's files?)")
}

pub fn decrypt(data: &[u8], source: &KeySource) -> Result<Vec<u8>> {
    match source {
        KeySource::Direct { key, iv } => aes_cbc_decrypt(data, key, iv),
        KeySource::CommonKey { common_key, encrypted_title_key, title_key_iv, content_iv } => {
            let tk = aes_cbc_decrypt(encrypted_title_key, common_key, title_key_iv)?;
            let key: [u8; 16] = tk[..16].try_into()?;
            aes_cbc_decrypt(data, &key, content_iv)
        }
        KeySource::Recrypt { virage2, recrypt_sys, content_id, content_iv } => {
            let key = find_recrypt_key(virage2, recrypt_sys, *content_id)?;
            aes_cbc_decrypt(data, &key, content_iv)
        }
    }
}

/// The CMD's size field is the real app size; the file may be padded up to a multiple of 16.
pub fn verify(plain: &[u8], cmd_size: u32, cmd_sha1: &[u8; 20]) -> bool {
    let n = cmd_size as usize;
    n != 0 && n <= plain.len() && plain.len() - n < 16 && Sha1::digest(&plain[..n]).as_slice() == cmd_sha1
}

const V2_ECC_PRIVATE_KEY: usize = 0x98;
const TICKET_CMD_LEN: usize = 0x29AC;
pub const TICKET_LEN: usize = 0x2B4C;

/// Select a unique content ID from the count-prefixed ticket.sys array.
/// Trailing NAND block padding is allowed.
pub fn select_ticket(data: &[u8], content_id: u32) -> Result<&[u8]> {
    let count_bytes = data.get(..4).ok_or_else(|| anyhow!("ticket.sys is missing its entry count"))?;
    let count = u32::from_be_bytes(count_bytes.try_into()?);
    let count = usize::try_from(count).map_err(|_| anyhow!("ticket.sys entry count is too large"))?;
    let end = count.checked_mul(TICKET_LEN).and_then(|n| n.checked_add(4)).ok_or_else(|| anyhow!("ticket.sys entry count overflows"))?;
    let entries = data.get(4..end).ok_or_else(|| anyhow!("ticket.sys is truncated for its declared {count} tickets"))?;
    let mut matching = entries.as_chunks::<TICKET_LEN>().0.iter().filter(|ticket| ticket[0x2898..0x289C] == content_id.to_be_bytes());
    let ticket = matching.next().ok_or_else(|| anyhow!("no ticket for content ID {content_id:08X}"))?;
    if matching.next().is_some() {
        bail!("multiple tickets have content ID {content_id:08X}; extract the intended individual ticket");
    }
    Ok(ticket.as_slice())
}

/// Result of unwrapping a non-SA app's title key from its ticket.
pub struct TicketKey {
    pub cmd: crate::cmd::CmdFile,
    pub title_key: [u8; 16],
    /// Ticket bbId equals the Virage2 bbId (a mismatch means wrong console's files).
    pub bbid_matches: bool,
}

/// Non-SA apps: the CMD's title key is encrypted with the common key and then
/// again with an ECDH-derived key (console ECC private key from Virage2 x the
/// ticket's server public key, IV = the ticket's `cmdIv`).
/// Ticket layout: CMD (0x29AC) + bbId, tid, ..., cmdIv @0x29BC, serverKey @0x29CC.
pub fn ticket_title_key(ticket: &[u8], virage2: &[u8], common_key: &[u8; 16]) -> Result<TicketKey> {
    if ticket.len() != TICKET_LEN {
        bail!("expected one {TICKET_LEN}-byte (0x2B4C) ticket, got {} bytes", ticket.len());
    }
    if virage2.len() < VIRAGE2_SIZE {
        bail!("Virage2 dump must be at least {VIRAGE2_SIZE} bytes (got {})", virage2.len());
    }
    let cmd = crate::cmd::CmdFile::parse(Path::new("ticket"), &ticket[..TICKET_CMD_LEN])?;
    let ticket_bbid = u32::from_be_bytes(ticket[0x29AC..0x29B0].try_into()?);
    let console_bbid = u32::from_be_bytes(virage2[V2_BBID..V2_BBID + 4].try_into()?);
    let titlekek = crate::ique_ecc::titlekek(&virage2[V2_ECC_PRIVATE_KEY..V2_ECC_PRIVATE_KEY + 32], &ticket[0x29CC..0x2A0C])?;
    let ticket_iv: [u8; 16] = ticket[0x29BC..0x29CC].try_into()?;
    let once = aes_cbc_decrypt(&cmd.head.encrypted_title_key, &titlekek, &ticket_iv)?;
    let once: [u8; 16] = once[..16].try_into()?;
    let plain = aes_cbc_decrypt(&once, common_key, &cmd.head.title_key_iv)?;
    Ok(TicketKey { title_key: plain[..16].try_into()?, cmd, bbid_matches: ticket_bbid == console_bbid })
}

const SK_LEN: usize = 0x10000;
const SA1_CMD_OFFSET: usize = 0x10000;
const SA_CMD_LEN: usize = 0x4000;
const CMD_HEAD_LEN: usize = 0x1AC;

/// Decrypts the 64 KiB secure kernel (AES-128-CBC with the user's SK key and IV).
pub fn sksa_decrypt_sk(sksa: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    if sksa.len() < SK_LEN {
        bail!("SKSA is smaller than the 64 KiB secure kernel");
    }
    aes_cbc_decrypt(&sksa[..SK_LEN], key, iv)
}

/// A decrypted system app from an SKSA image.
pub struct SaResult {
    pub data: Vec<u8>,
    pub content_id: u32,
    pub sha1_ok: bool,
}

/// Decompress a raw DEFLATE SA2 stream with an explicit output limit.
pub fn decompress_sa2(data: &[u8]) -> Result<Vec<u8>> {
    decompress_sa2_limited(data, 64 * 1024 * 1024)
}

fn decompress_sa2_limited(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut decoder = Decompress::new(false);
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let input_pos = usize::try_from(decoder.total_in())?;
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(&data[input_pos..], &mut buffer, FlushDecompress::None)
            .map_err(|e| anyhow!("invalid raw DEFLATE SA2: {e}"))?;
        let written = usize::try_from(decoder.total_out() - before_out)?;
        if written > limit.saturating_sub(output.len()) {
            bail!("decompressed SA2 exceeds the {limit}-byte limit");
        }
        output.extend_from_slice(&buffer[..written]);
        if status == Status::StreamEnd {
            return Ok(output);
        }
        if input_pos == usize::try_from(decoder.total_in())? && written == 0 {
            bail!("incomplete or invalid raw DEFLATE SA2");
        }
    }
}

/// Decrypts SA1 (`which == 1`) or SA2 (`which == 2`) of an SKSA image using the
/// user's common key. Layout: SK (0x10000), SA1 CMD (0x4000) + data, SA2 CMD (0x4000) + data.
/// Returns `None` when that SA is absent. SA2 may be further compressed in some
/// SKSAs; that is left untouched.
pub fn sksa_decrypt_sa(sksa: &[u8], which: u8, common_key: &[u8; 16]) -> Result<Option<SaResult>> {
    if !(1..=2).contains(&which) {
        bail!("SA number must be 1 or 2");
    }
    let sa1_data_start = SA1_CMD_OFFSET + SA_CMD_LEN;
    if sksa.len() < sa1_data_start {
        bail!("SKSA is too small to contain the SA1 CMD");
    }
    let sa1_size = sa_cmd(sksa, SA1_CMD_OFFSET)?.head.size as usize;
    let sa1_end = sa1_data_start.checked_add(sa1_size).ok_or_else(|| anyhow!("SA1 size overflows the file offset"))?;
    if !sa1_size.is_multiple_of(16) || sksa.len() < sa1_end {
        bail!("SA1 size {sa1_size} is invalid or runs past the end of the file");
    }
    let cmd_off = if which == 1 { SA1_CMD_OFFSET } else { sa1_end };
    if which == 2 && sksa.len() == cmd_off {
        return Ok(None);
    }
    let data_start = cmd_off.checked_add(SA_CMD_LEN).ok_or_else(|| anyhow!("SA{which} CMD offset overflows"))?;
    if sksa.len() < data_start {
        bail!("SKSA is too small to contain the complete SA{which} CMD");
    }
    let cmd = sa_cmd(sksa, cmd_off)?;
    let size = cmd.head.size as usize;
    if size == 0 {
        return Ok(None);
    }
    let end = data_start.checked_add(size).ok_or_else(|| anyhow!("SA{which} size overflows the file offset"))?;
    if !size.is_multiple_of(16) || sksa.len() < end {
        bail!("SA{which} size {size} is invalid or runs past the end of the file");
    }
    let src = KeySource::CommonKey {
        common_key: *common_key,
        encrypted_title_key: cmd.head.encrypted_title_key,
        title_key_iv: cmd.head.title_key_iv,
        content_iv: cmd.head.content_iv,
    };
    let data = decrypt(&sksa[data_start..end], &src)?;
    let sha1_ok = verify(&data, cmd.head.size, &cmd.head.hash);
    Ok(Some(SaResult { data, content_id: cmd.head.content_id, sha1_ok }))
}

fn sa_cmd(sksa: &[u8], off: usize) -> Result<crate::cmd::CmdFile> {
    let slice = sksa.get(off..off + CMD_HEAD_LEN).ok_or_else(|| anyhow!("SKSA is too small to contain the SA CMD at 0x{off:X}"))?;
    crate::cmd::CmdFile::parse(Path::new("sksa"), slice)
}

/// Plausibility check when no `.cmd` is available: does it look like an N64 ROM?
pub fn looks_like_rom(plain: &[u8]) -> bool {
    plain.len() >= 4 && matches!(plain[..4], [0x80, 0x37, 0x12, 0x40] | [0x40, 0x12, 0x37, 0x80] | [0x37, 0x80, 0x40, 0x12])
        || plain.len() >= 0x24 && plain[0x20..0x24] == [0x80, 0x37, 0x12, 0x40]
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockModeEncrypt;
    use std::io::Write;

    fn encrypt(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
        let mut buf = data.to_vec();
        cbc::Encryptor::<Aes128>::new(key.into(), iv.into()).encrypt_padded::<NoPadding>(&mut buf, data.len()).unwrap();
        buf
    }

    #[test]
    fn nist_cbc_vector() {
        // NIST SP 800-38A F.2.2 (CBC-AES128.Decrypt), first block.
        let key = parse_hex16("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = parse_hex16("000102030405060708090a0b0c0d0e0f").unwrap();
        let ct = parse_hex16("7649abac8119b246cee98e9b12e9197d").unwrap();
        let pt = aes_cbc_decrypt(&ct, &key, &iv).unwrap();
        assert_eq!(pt, parse_hex16("6bc1bee22e409f96e93d7e117393172a").unwrap());
    }

    #[test]
    fn hex_parsing() {
        assert!(parse_hex16("00").is_err());
        assert!(parse_hex16("zz000000000000000000000000000000").is_err());
        assert_eq!(parse_hex16("0x000102030405060708090A0B0C0D0E0F").unwrap()[15], 0x0F);
    }

    #[test]
    fn common_key_round_trip_and_verify() {
        let common = [7u8; 16];
        let tk_iv = [1u8; 16];
        let content_iv = [2u8; 16];
        let title_key = [9u8; 16];
        let enc_tk: [u8; 16] = encrypt(&title_key, &common, &tk_iv).try_into().unwrap();
        let mut rom = vec![0x80, 0x37, 0x12, 0x40];
        rom.resize(64, 0xAB);
        let enc = encrypt(&rom, &title_key, &content_iv);
        let src = KeySource::CommonKey { common_key: common, encrypted_title_key: enc_tk, title_key_iv: tk_iv, content_iv };
        let plain = decrypt(&enc, &src).unwrap();
        assert_eq!(plain, rom);
        assert!(looks_like_rom(&plain));
        let sha: [u8; 20] = Sha1::digest(&rom).into();

        assert!(verify(&plain, 64, &sha));
        assert!(!verify(&plain, 64, &[0; 20]));
    }

    #[test]
    fn recrypt_lookup() {
        let mut v2 = vec![0u8; VIRAGE2_SIZE];
        v2[V2_BBID..V2_BBID + 4].copy_from_slice(&0x1234_FFFEu32.to_be_bytes());
        let list_key = [5u8; 16];
        v2[V2_RECRYPT_LIST_KEY..V2_RECRYPT_LIST_KEY + 16].copy_from_slice(&list_key);
        let mut iv = [0u8; 16];
        for (i, c) in iv.chunks_mut(4).enumerate() {
            c.copy_from_slice(&0x1234_FFFEu32.wrapping_add(i as u32).to_be_bytes());
        }
        let rec_key = [0x33u8; 16];
        let mut rsys = vec![0u8; 0x40];
        rsys.extend_from_slice(&2u32.to_be_bytes());
        for cid in [0x1111_1111u32, 0x2222_2222] {
            let mut e = cid.to_be_bytes().to_vec();
            e.extend_from_slice(&rec_key);
            e.resize(32, 0);
            rsys.extend(encrypt(&e, &list_key, &iv));
        }
        assert_eq!(find_recrypt_key(&v2, &rsys, 0x2222_2222).unwrap(), rec_key);
        assert!(find_recrypt_key(&v2, &rsys, 0x3333_3333).is_err());
    }

    fn head(size: u32, sha1: &[u8; 20], tk_iv: &[u8; 16], c_iv: &[u8; 16], cid: u32, key: &[u8; 16]) -> Vec<u8> {
        let mut h = vec![0u8; CMD_HEAD_LEN];
        h[0x0C..0x10].copy_from_slice(&size.to_be_bytes());
        h[0x14..0x24].copy_from_slice(tk_iv);
        h[0x24..0x38].copy_from_slice(sha1);
        h[0x38..0x48].copy_from_slice(c_iv);
        h[0x98..0x9C].copy_from_slice(&cid.to_be_bytes());
        h[0x9C..0xAC].copy_from_slice(key);
        h
    }

    #[test]
    fn sksa_sa1_and_sa2() {
        let (common, tk, tk_iv, c_iv) = ([3u8; 16], [4u8; 16], [5u8; 16], [6u8; 16]);
        let enc_tk: [u8; 16] = encrypt(&tk, &common, &tk_iv).try_into().unwrap();
        let mut sksa = vec![0u8; SK_LEN];
        for (n, cid) in [(32usize, 1095u32), (16, 1107)] {
            let plain = vec![n as u8; n];
            let sha: [u8; 20] = Sha1::digest(&plain).into();
            let mut cmd = head(n as u32, &sha, &tk_iv, &c_iv, cid, &enc_tk);
            cmd.resize(SA_CMD_LEN, 0);
            sksa.extend(cmd);
            sksa.extend(encrypt(&plain, &tk, &c_iv));
        }
        let sa1 = sksa_decrypt_sa(&sksa, 1, &common).unwrap().unwrap();
        assert_eq!((sa1.data.len(), sa1.content_id, sa1.sha1_ok), (32, 1095, true));
        let sa2 = sksa_decrypt_sa(&sksa, 2, &common).unwrap().unwrap();
        assert_eq!((sa2.data.len(), sa2.content_id, sa2.sha1_ok), (16, 1107, true));
        assert!(!sksa_decrypt_sa(&sksa, 1, &[0; 16]).unwrap().unwrap().sha1_ok);
        sksa.truncate(SK_LEN + SA_CMD_LEN + 32);
        assert!(sksa_decrypt_sa(&sksa, 2, &common).unwrap().is_none());
        sksa.push(0);
        assert!(sksa_decrypt_sa(&sksa, 2, &common).is_err());
        sksa.truncate(SK_LEN + SA_CMD_LEN + 31);
        assert!(sksa_decrypt_sa(&sksa, 1, &common).is_err());
        assert!(sksa_decrypt_sa(&sksa, 2, &common).is_err());
        assert!(sksa_decrypt_sa(&sksa, 0, &common).is_err());
        let sk = sksa_decrypt_sk(&vec![0u8; SK_LEN], &[1; 16], &[2; 16]).unwrap();
        assert_eq!(sk.len(), SK_LEN);
    }

    #[test]
    fn ticket_non_sa_title_key() {
        let (common, title_key, tk_iv, ticket_iv) = ([3u8; 16], [0x77u8; 16], [5u8; 16], [8u8; 16]);
        let console_priv = {
            let mut k = [0u8; 32];
            k[31] = 0x2B;
            k[20] = 0x11;
            k
        };
        let server_priv = {
            let mut k = [0u8; 32];
            k[31] = 0x35;
            k[10] = 0x01;
            k
        };
        let kek = crate::ique_ecc::titlekek(&server_priv, &crate::ique_ecc::public_key(&console_priv)).unwrap();
        let once = encrypt(&title_key, &common, &tk_iv);
        let twice: [u8; 16] = encrypt(&once, &kek, &ticket_iv).try_into().unwrap();
        let mut ticket = vec![0u8; TICKET_LEN];
        ticket[0x2800..0x29AC].copy_from_slice(&head(16, &[0; 20], &tk_iv, &[0; 16], 0x0098_967F, &twice));
        ticket[0x29AC..0x29B0].copy_from_slice(&0xABCDu32.to_be_bytes());
        ticket[0x29BC..0x29CC].copy_from_slice(&ticket_iv);
        ticket[0x29CC..0x2A0C].copy_from_slice(&crate::ique_ecc::public_key(&server_priv));
        let mut v2 = vec![0u8; VIRAGE2_SIZE];
        v2[V2_ECC_PRIVATE_KEY..V2_ECC_PRIVATE_KEY + 32].copy_from_slice(&console_priv);
        v2[V2_BBID..V2_BBID + 4].copy_from_slice(&0xABCDu32.to_be_bytes());
        let r = ticket_title_key(&ticket, &v2, &common).unwrap();
        assert_eq!(r.title_key, title_key);
        assert!(r.bbid_matches);
        v2[V2_BBID + 3] ^= 1;
        assert!(!ticket_title_key(&ticket, &v2, &common).unwrap().bbid_matches);
        assert!(ticket_title_key(&ticket[..100], &v2, &common).is_err());
        let mut ticket_array = 1u32.to_be_bytes().to_vec();
        ticket_array.extend_from_slice(&ticket);
        assert!(ticket_title_key(&ticket_array, &v2, &common).is_err());
        let selected = select_ticket(&ticket_array, 0x0098_967F).unwrap();
        assert_eq!(ticket_title_key(selected, &v2, &common).unwrap().title_key, title_key);
    }

    #[test]
    fn selects_ticket_arrays_safely() {
        let mut first = vec![0u8; TICKET_LEN];
        let mut second = first.clone();
        first[0x2898..0x289C].copy_from_slice(&0x1234u32.to_be_bytes());
        second[0x2898..0x289C].copy_from_slice(&0x5678u32.to_be_bytes());
        let mut array = 2u32.to_be_bytes().to_vec();
        array.extend_from_slice(&first);
        array.extend_from_slice(&second);
        array.extend_from_slice(&[0; 31]);
        assert_eq!(select_ticket(&array, 0x1234).unwrap(), first);
        assert_eq!(select_ticket(&array, 0x5678).unwrap(), second);
        assert!(select_ticket(&array, 0).is_err());
        assert!(select_ticket(&array[..4 + TICKET_LEN], 0x1234).is_err());
        let mut duplicate = 2u32.to_be_bytes().to_vec();
        duplicate.extend_from_slice(&first);
        duplicate.extend_from_slice(&first);
        assert!(select_ticket(&duplicate, 0x1234).is_err());
        assert!(select_ticket(&[0; 3], 0).is_err());
        assert!(select_ticket(&u32::MAX.to_be_bytes(), 0).is_err());
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(aes_cbc_decrypt(&[0u8; 15], &[0; 16], &[0; 16]).is_err());
        assert!(aes_cbc_decrypt(&[], &[0; 16], &[0; 16]).is_err());
    }

    #[test]
    fn decompresses_sa2_and_rejects_bad_streams() {
        assert_eq!(decompress_sa2(&[0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]).unwrap(), b"hello");
        assert!(decompress_sa2(&[0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07]).is_err());
        let original = vec![0x42; 30_000];
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&original).unwrap();
        let mut encoded = encoder.finish().unwrap();
        encoded.extend_from_slice(&[0; 8]);
        assert_eq!(decompress_sa2(&encoded).unwrap(), original);
        assert_eq!(decompress_sa2_limited(&encoded, 30_000).unwrap().len(), 30_000);
        assert!(decompress_sa2_limited(&encoded, 100).is_err());
        assert!(decompress_sa2(&encoded[..2]).is_err());
        assert!(decompress_sa2(&[0xff, 0xff, 0xff]).is_err());
    }
}
