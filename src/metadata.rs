//! N64brew ROM Metadata (https://n64brew.dev/wiki/ROM_Metadata): a ZIP file
//! either appended to the ROM (advertised by bit 0 of header byte 0x38) or
//! stored next to it as `<rom name>.meta`, containing a `metadata.ini` plus
//! the images it references. External metadata takes priority over embedded.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

const MAX_INI_BYTES: u64 = 1024 * 1024;
const MAX_TEXT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataSource {
    External(PathBuf),
    Embedded,
}

impl MetadataSource {
    pub fn label(&self) -> String {
        match self {
            MetadataSource::External(p) => format!("External ({})", p.display()),
            MetadataSource::Embedded => "Embedded in ROM".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZipEntryInfo {
    pub name: String,
    pub size: u64,
    pub stored: bool,
}

#[derive(Debug, Clone)]
pub struct RomMetadata {
    pub source: MetadataSource,
    pub entries: Vec<ZipEntryInfo>,
    /// INI sections (`meta`, `meta.es`, `boxart`, ...) -> key -> value.
    pub sections: BTreeMap<String, BTreeMap<String, String>>,
    /// Contents of the file named by `long-desc`, if present.
    pub long_desc: Option<String>,
    pub warnings: Vec<String>,
}

impl RomMetadata {
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections.get(section).and_then(|s| s.get(key)).map(|v| v.as_str()).filter(|v| !v.is_empty())
    }

    /// Localized lookup: `[meta.<lang>]` wins over `[meta]`.
    pub fn get_localized(&self, lang: Option<&str>, key: &str) -> Option<&str> {
        lang.and_then(|l| self.get(&format!("meta.{l}"), key)).or_else(|| self.get("meta", key))
    }

    /// ISO 639-1 codes of every `[meta.<lang>]` section.
    pub fn languages(&self) -> Vec<String> {
        self.sections.keys().filter_map(|k| k.strip_prefix("meta.")).map(str::to_string).collect()
    }

    pub fn screenshots(&self) -> Vec<String> {
        self.get("meta", "screenshots")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }

    /// Every image filename referenced by `[boxart*]`, `[cartart*]` and `screenshots`,
    /// as `(label, filename)`.
    pub fn referenced_images(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (sec, kv) in &self.sections {
            if sec.starts_with("boxart") || sec.starts_with("cartart") {
                for (k, v) in kv {
                    if !v.is_empty() {
                        out.push((format!("{sec}.{k}"), v.clone()));
                    }
                }
            }
        }
        for s in self.screenshots() {
            out.push(("screenshot".to_string(), s));
        }
        out
    }

    pub fn has_entry(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name == name)
    }
}

/// Parses the spec's INI subset: `;` comment lines, `[section]` headers,
/// `key = value`; no inline comments, quoting or continuation. CRLF accepted.
pub fn parse_ini(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = String::new();
    for raw in text.trim_start_matches('\u{feff}').lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = name.trim().to_ascii_lowercase();
            out.entry(current.clone()).or_default();
        } else if let Some((k, v)) = line.split_once('=') {
            out.entry(current.clone()).or_default().insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    out
}

/// Finds the metadata for a ROM: the external `.meta` beside it first, then a
/// ZIP embedded at the end of the (big-endian normalized) ROM when the
/// homebrew header flags one. Returns `None` if there is none or it is unusable.
pub fn load_for_rom(rom_path: &Path, be_data: &[u8], embedded_flag: bool) -> Option<RomMetadata> {
    let external = rom_path.with_extension("meta");
    if external.is_file() {
        if let Ok(bytes) = std::fs::read(&external) {
            if let Some(m) = read_archive(Cursor::new(bytes), MetadataSource::External(external)) {
                return Some(m);
            }
        }
    }
    if embedded_flag {
        return read_archive(Cursor::new(be_data), MetadataSource::Embedded);
    }
    None
}

fn read_archive<R: Read + Seek>(reader: R, source: MetadataSource) -> Option<RomMetadata> {
    let mut zip = zip::ZipArchive::new(reader).ok()?;
    let mut warnings = Vec::new();
    let mut entries = Vec::new();
    for i in 0..zip.len() {
        if let Ok(f) = zip.by_index_raw(i) {
            if f.is_dir() {
                continue;
            }
            let name = f.name().map(|n| n.into_owned()).unwrap_or_default();
            let stored = f.compression() == zip::CompressionMethod::Stored;
            if !stored {
                warnings.push(format!("'{name}' is compressed; the spec requires uncompressed (stored) files"));
            }
            entries.push(ZipEntryInfo { name, size: f.size(), stored });
        }
    }

    let ini = read_entry_text(&mut zip, "metadata.ini", MAX_INI_BYTES);
    let sections = match ini {
        Some(Ok(t)) => parse_ini(&t),
        Some(Err(e)) => {
            warnings.push(format!("metadata.ini: {e}"));
            BTreeMap::new()
        }
        None => {
            warnings.push("metadata.ini is missing from the ZIP".to_string());
            BTreeMap::new()
        }
    };

    let long_desc =
        sections.get("meta").and_then(|m| m.get("long-desc")).filter(|n| !n.is_empty()).and_then(|name| {
            match read_entry_text(&mut zip, name, MAX_TEXT_BYTES) {
                Some(Ok(t)) => Some(t),
                Some(Err(e)) => {
                    warnings.push(format!("{name}: {e}"));
                    None
                }
                None => {
                    warnings.push(format!("long-desc file '{name}' is missing from the ZIP"));
                    None
                }
            }
        });

    Some(RomMetadata { source, entries, sections, long_desc, warnings })
}

fn read_entry_text<R: Read + Seek>(zip: &mut zip::ZipArchive<R>, name: &str, limit: u64) -> Option<Result<String, String>> {
    let f = zip.by_name(name).ok()?;
    let mut buf = Vec::new();
    if let Err(e) = f.take(limit + 1).read_to_end(&mut buf) {
        return Some(Err(e.to_string()));
    }
    if buf.len() as u64 > limit {
        return Some(Err(format!("larger than {} bytes, ignored", limit)));
    }
    Some(String::from_utf8(buf).map_err(|_| "is not valid UTF-8".to_string()))
}

/// Extracts every file from the metadata archive into `dest`, skipping
/// directories and any entry whose path would escape `dest`. Returns the
/// number of files written.
pub fn extract_all(source: &MetadataSource, be_data: &[u8], dest: &Path) -> anyhow::Result<usize> {
    fn run<R: Read + Seek>(mut zip: zip::ZipArchive<R>, dest: &Path) -> anyhow::Result<usize> {
        std::fs::create_dir_all(dest)?;
        let mut n = 0;
        for i in 0..zip.len() {
            let mut f = zip.by_index(i)?;
            let Some(rel) = f.enclosed_name() else { continue };
            if f.is_dir() {
                continue;
            }
            let out = dest.join(rel);
            if let Some(p) = out.parent() {
                std::fs::create_dir_all(p)?;
            }
            let mut w = std::fs::File::create(out)?;
            std::io::copy(&mut f, &mut w)?;
            n += 1;
        }
        Ok(n)
    }
    match source {
        MetadataSource::External(p) => run(zip::ZipArchive::new(Cursor::new(std::fs::read(p)?))?, dest),
        MetadataSource::Embedded => run(zip::ZipArchive::new(Cursor::new(be_data))?, dest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(ini: &str) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("metadata.ini", opts).unwrap();
        w.write_all(ini.as_bytes()).unwrap();
        w.start_file("description.txt", opts).unwrap();
        w.write_all("Long\ntext".as_bytes()).unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn parses_ini_with_localization_and_crlf() {
        let ini = "; c\r\n[meta]\r\nname = Shooter\r\nshort-desc = Hi\r\nscreenshots = a.png, b.png\r\n[meta.es]\r\nshort-desc = Hola\r\n[boxart]\r\nfront = f.jpg\r\n";
        let s = parse_ini(ini);
        assert_eq!(s["meta"]["name"], "Shooter");
        assert_eq!(s["meta.es"]["short-desc"], "Hola");
        assert_eq!(s["boxart"]["front"], "f.jpg");
    }

    #[test]
    fn reads_embedded_zip_appended_to_rom() {
        let mut rom = vec![0u8; 0x1000];
        rom.extend(make_zip("[meta]\nname = Test\nlong-desc = description.txt\nscreenshots = x.png\n[meta.it]\nname = Prova\n"));
        let m = load_for_rom(Path::new("nonexistent_rom.z64"), &rom, true).expect("metadata");
        assert_eq!(m.source, MetadataSource::Embedded);
        assert_eq!(m.get_localized(None, "name"), Some("Test"));
        assert_eq!(m.get_localized(Some("it"), "name"), Some("Prova"));
        assert_eq!(m.long_desc.as_deref(), Some("Long\ntext"));
        assert_eq!(m.languages(), vec!["it".to_string()]);
        assert_eq!(m.referenced_images().len(), 1);
        assert!(load_for_rom(Path::new("nonexistent_rom.z64"), &rom, false).is_none());
    }

    #[test]
    fn extract_all_writes_files() {
        let rom = make_zip("[meta]\nname = T\n");
        let dir = std::env::temp_dir().join("turtle64_meta_test");
        let _ = std::fs::remove_dir_all(&dir);
        let n = extract_all(&MetadataSource::Embedded, &rom, &dir).unwrap();
        assert_eq!(n, 2);
        assert!(dir.join("metadata.ini").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
