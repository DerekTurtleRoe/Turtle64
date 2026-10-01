# Turtle64 🐢

[![CI](https://github.com/derekturtleroe/Turtle64/actions/workflows/ci.yml/badge.svg)](https://github.com/derekturtleroe/Turtle64/actions/workflows/ci.yml)
[![Super Linter](https://github.com/derekturtleroe/Turtle64/actions/workflows/super-linter.yml/badge.svg)](https://github.com/derekturtleroe/Turtle64/actions/workflows/super-linter.yml)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE.md)
[![Latest release](https://img.shields.io/github/v/release/derekturtleroe/Turtle64?include_prereleases)](https://github.com/derekturtleroe/Turtle64/releases)

A native Rust + [egui](https://github.com/emilk/egui) desktop application for
working with Nintendo 64 ROM images. Turtle64 was heavily inspired by two
excellent community tools, [ROM64](https://github.com/mroach/rom64) and
[romjudge](https://github.com/jkbenaim/romjudge), and aims to carry their
spirit forward in a single cross-platform GUI that combines format
conversion, header inspection, checksum/hash calculation, and No-Intro DAT
verification.

## Features

- **Endianness detection from content, not file extension.** Every ROM is
  identified as big-endian (`.z64`), byte-swapped (`.v64`), or little-endian
  (`.n64`) by inspecting the header magic bytes, with a heuristic fallback
  for ROMs with non-standard PI BSD DOM1 configuration bytes.
- **Conversion between all three formats**, for a single ROM or in batch
  across many files/whole folders (recursive), with a live progress bar and
  ETA, backed by a multi-threaded worker pool.
- **Full ROM header parsing**, including title, game code (category /
  unique code / region), ROM version, boot address, clock rate, libultra
  version, and the header's embedded check code — per the public
  [N64brew ROM Header wiki](https://n64brew.dev/wiki/ROM_Header). The game
  title is decoded with proper Shift-JIS (Japan)/GBK (China/iQue) support
  via `encoding_rs`, not naive ASCII/UTF-8, so Japanese and Chinese titles
  display correctly instead of as mojibake.
- **Advanced Homebrew ROM Header** support: save type, RTC/region-free
  flags, per-port controller/accessory suggestions, and embedded metadata
  flag, decoded whenever the `"ED"` marker is present.
- **Legacy IPL3 CRC1/CRC2 checksum** calculation (with CIC boot-chip
  auto-detection for 6101/6102/6103/6105/6106/7102/5101/8303/iQue/HW1, plus
  all 8 [libdragon open-source IPL3](https://github.com/DragonMinded/libdragon/tree/trunk/boot)
  revisions r1-r8, fingerprinted individually rather than lumped in with
  6102)
  compared against the value stored in the header, for compatibility with
  legacy emulators/ROM databases.
- **iQue Player & Aleck64 Arcade support**: automatic detection of the
  prepended 32-byte container header on iQue dumps (safely parsed and
  noted), recognition of the `'C'` destination (China / iQue), Aleck64
  arcade game pak category (`'Z'`), and identification of Aleck64 arcade
  CICs (`CIC-NUS-5101` and `CIC-NUS-8303`).
- **Modern hashing**: CRC32, MD5, and SHA-1, for use with ROM databases. An
  optional "don't convert to big-endian when checking ROM info" toggle on
  the Single ROM tab additionally computes this same hash set against the
  ROM's original, native on-disk byte order (shown alongside, not instead
  of, the normalized hashes — No-Intro/Redump verification always uses the
  normalized form).
- **No-Intro DAT verification**: load any Logiqx-style `.dat`/`.xml` file
  and classify a ROM as a verified good dump, a CRC-match-but-hash-mismatch
  ("bad dump"), or simply not present in the database. Turtle64 can hold up
  to 8 DAT files loaded simultaneously — one per No-Intro N64 DAT kind (N64
  BigEndian, N64 ByteSwapped, 64DD, Mario no Photopie SmartMedia, iQue CDN,
  iQue Decrypted, Aleck64 BigEndian, Aleck64 ByteSwapped) — so a ROM is
  checked against every relevant DAT at once instead of requiring you to
  switch which single DAT is active. "Load DAT…" loads one file; "Load all
  DATs…" lets you multi-select several (or all 8) at once, each
  auto-detected and routed to its matching slot by its own `<header><name>`
  text. The top bar shows each loaded DAT's name, version/date, and entry
  count. A "Check for DAT updates" button **only re-reads already-loaded
  DAT files from disk** — it never downloads anything automatically or on
  launch: No-Intro's DAT-o-MATIC site explicitly prohibits automated/bot
  access in its terms of service (and will ban the offending IP), so if you
  want a newer DAT you must download it yourself from No-Intro and then use
  this button (or just reload the file) to pick up the change.
- **IPL3 boot-code dumping & patching**: extract a ROM's 0xFC0-byte IPL3
  stage (offset `0x40`-`0x1000`, per the
  [N64brew IPL wiki](https://n64brew.dev/wiki/Initial_Program_Load)) to a
  file for separate inspection, or patch in any previously-dumped IPL3 from
  a `bootcodes` folder kept next to the executable. Patching can optionally
  recalculate and rewrite the header's CRC1/CRC2 to match the new IPL3/CIC
  pairing before you save the result. All 8 libdragon open-source IPL3
  revisions (r1-r8; public domain/Unlicense) are bundled in the executable
  and auto-seeded into `bootcodes` on startup, ready to patch in
  immediately — libdragon's production builds are GPU-bruteforced to match
  CIC-NUS-6102's checksum so they boot on real hardware, but Turtle64 still
  identifies each revision by its own fingerprint rather than reporting it
  as a plain 6102.
- **Full N64DD (64DD disk drive) support**, in its own "64DD Disk" tab:
  - Content-based format detection (never by file extension) for the three
    known disk image formats: `.d64` (SDK master disk format), `.ndd`
    (64DD Disk Dumper's LBA-ordered raw dump), and MAME's physical
    track-ordered format — following the layouts documented on
    [LuigiBlood's 64dd wiki](https://github.com/LuigiBlood/64dd/wiki/Disk-Image-Formats).
  - System Data / Disk ID parsing (region, disk type, retail vs.
    development, game code, company code, production date, IPL load
    address/size, ROM/RAM area LBA bounds).
  - Conversion between all three disk formats. **`.d64` is lossy and heavily
    trimmed**: it keeps only the System Data, Disk ID, and the actually-used
    ROM/RAM Area (typically tens of MB), discarding the defect-track table,
    exact physical LBA sizing, and all disk padding that a full NDD/MAME
    dump carries (a fixed ~64.5 MB regardless of how much of the disk the
    game uses). Converting to `.d64` permanently discards that data, and
    converting a `.d64` back to NDD/MAME reconstructs an idealized,
    defect-free disk rather than the original bit-exact dump — the app
    warns about this in the UI whenever D64 is involved. NDD/MAME
    conversion, by contrast, round-trips exactly for defect-free disks
    (disks reporting defect/bad tracks are flagged in the UI, since the
    converter does not model alternate-track substitution).
  - 64DD IPL CIC identification (`CIC-8303`/`8401`/`8501`/etc., per
    [LuigiBlood's 64dd CIC wiki](https://github.com/LuigiBlood/64dd/wiki/CIC)).
  - CRC32/MD5/SHA-1 hashing of the whole disk image, plus a separate SHA-1
    of just the ROM Area (matching the field jkbenaim's leotools reports for
    disk verification).
  - MFS (the 64DD's FAT-like RAM filesystem) volume info and a directory
    listing with per-file size/date (also Shift-JIS decoded, matching
    cartridge header titles), plus best-effort file extraction.

- **Export ROM/disk info to a text report**, for a single ROM/disk or in
  batch across a whole folder — report filenames include the source file's
  extension (e.g. `game.z64_info.txt`) so same-named ROMs of different
  formats don't clobber each other. Conversion can also optionally write
  the converted output's info report immediately afterward, with no second
  save dialog.

## Building

```powershell
cargo build --release
```

The binary is produced at `target/release/turtle64.exe`.

### Linux packages

In addition to the plain binary, Turtle64 can be packaged for Linux as a `.deb`, `.rpm`,
`.AppImage`, or `.flatpak`. The `Linux Packaging` GitHub Actions workflow
(`.github/workflows/linux-packaging.yml`) builds all four on every push/PR, and `release.yml`
attaches them to tagged GitHub Releases. To build them locally:

```bash
# .deb (Debian/Ubuntu) - requires `cargo install cargo-deb`
cargo build --release
cargo deb --no-build

# .rpm (Fedora/openSUSE/RHEL) - requires `cargo install cargo-generate-rpm`
cargo build --release
cargo generate-rpm

# .AppImage - requires `linuxdeploy` (https://github.com/linuxdeploy/linuxdeploy)
cargo build --release
mkdir -p AppDir/usr/bin && cp target/release/turtle64 AppDir/usr/bin/
linuxdeploy --appdir AppDir \
  --executable AppDir/usr/bin/turtle64 \
  --desktop-file packaging/linux/io.github.derekturtleroe.Turtle64.desktop \
  --icon-file assets/icons/turtle64_256.png \
  --output appimage

# .flatpak - requires flatpak-builder and the org.freedesktop.Platform//24.08 runtime +
# org.freedesktop.Sdk.Extension.rust-stable//24.08 installed. Generate cargo-sources.json
# first with flatpak-builder-tools' cargo generator (not committed; regenerate from Cargo.lock):
python3 flatpak-cargo-generator.py Cargo.lock -o packaging/flatpak/cargo-sources.json
flatpak-builder --force-clean build-dir packaging/flatpak/io.github.derekturtleroe.Turtle64.yml
```

The `.deb`/`.rpm` metadata (dependencies, installed files, icons, desktop entry) lives in
`Cargo.toml` under `[package.metadata.deb]`/`[package.metadata.generate-rpm]`. The shared
`.desktop` file and AppStream metainfo live under `packaging/linux/`.

## Running

```powershell
cargo run --release
```

## Project layout

| Module | Responsibility |
| --- | --- |
| `rom_format.rs` | Byte-order detection & big-endian conversion |
| `header.rs` | Standard + Advanced Homebrew ROM header parsing |
| `cjk.rs` | Shared Shift-JIS/GBK decoding for header titles & MFS file names |
| `checksum.rs` | CIC identification + legacy IPL3 CRC1/CRC2 |
| `hashes.rs` | CRC32 / MD5 / SHA-1 hashing |
| `dat.rs` | No-Intro DAT parsing & verification |
| `bootcode.rs` | IPL3 boot-code dumping & patching, `bootcodes/` folder management |
| `rom.rs` | Ties the above together into a single `RomInfo` |
| `batch.rs` | Multi-threaded batch conversion engine |
| `dd_geometry.rs` | 64DD disk zone/track/LBA geometry tables & math |
| `dd_cic.rs` | 64DD IPL CIC identification |
| `dd_convert.rs` | Conversion between D64 / NDD / MAME disk formats |
| `dd_mfs.rs` | MFS filesystem listing & file extraction |
| `dd_disk.rs` | Ties the above together into a single `DdDiskInfo` |
| `app.rs` + `app/*.rs` | egui UI (Single ROM / Batch / 64DD Disk / About tabs) |

## Tests

```powershell
cargo test
```

## Attribution

Turtle64 does not use code from ROM64 or romjudge, but owes a debt of
gratitude to both projects — their design and feature set were a huge
inspiration for what Turtle64 aims to be. The legacy IPL3
checksum construction (seeds + rolling-checksum algorithm) is a
long-standing, publicly documented algorithm used throughout the N64
homebrew/emulation ecosystem and has been independently reimplemented here.

The 64DD disk support was written independently from the disk geometry and
field layouts publicly documented by LuigiBlood's
[64dd wiki](https://github.com/LuigiBlood/64dd/wiki) and
[leo64dd_python](https://github.com/LuigiBlood/leo64dd_python), and by
jkbenaim's [leotools](https://github.com/jkbenaim/leotools) (disk-info
fields and MFS layout only — no asset-extraction code was used). No source
code from those projects, or from Happy-yappH's
[ddconvert](https://github.com/Happy-yappH/ddconvert) /
LuigiBlood's [ddconvert_back](https://github.com/LuigiBlood/ddconvert_back),
was copied; their publicly documented algorithms for physical disk layout
were reimplemented fresh in Rust.

One exception to "no code/binaries copied": the 8 bundled
[libdragon](https://github.com/DragonMinded/libdragon) open-source IPL3
bootcode dumps (`r1`-`r8`) are redistributed unmodified. Libdragon's IPL3
is dedicated to the public domain under
[the Unlicense](https://github.com/DragonMinded/libdragon/blob/trunk/LICENSE.md),
so bundling the official, signed binaries — rather than reimplementing
them — is both legally fine and the only way to guarantee byte-exact,
hardware-bootable dumps.

## Contributing

Bug reports, feature requests, and pull requests are welcome! Please see
[CONTRIBUTING.md](CONTRIBUTING.md) for how to get set up and what checks CI
runs.

## License

Turtle64 is licensed under the GNU General Public License v2.0 or later
(GPL-2.0-or-later). See [LICENSE.md](LICENSE.md) for the full text.
