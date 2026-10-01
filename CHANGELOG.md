# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

## [Unreleased]

### Added

- Linux packaging: Turtle64 can now be built as a `.deb` (via `cargo-deb`), `.rpm` (via
  `cargo-generate-rpm`), a portable `.AppImage` (via `linuxdeploy`), and a `.flatpak` (via
  `flatpak-builder` against the `org.freedesktop.Platform` runtime, with Cargo dependencies
  vendored at build time so the sandboxed build needs no network access). A shared `.desktop`
  file and AppStream metainfo live under `packaging/linux/`, and a Flatpak manifest lives under
  `packaging/flatpak/`. A new `Linux Packaging` CI workflow builds and uploads all four package
  types as artifacts on every push/PR; `release.yml` attaches them to tagged GitHub Releases
  alongside the existing per-OS archives. An app icon (procedurally generated turtle-shell
  design) was also added and is now used for the window icon and all packaging formats.
- No-Intro DAT verification now supports loading up to **8 DAT files at once**, one per No-Intro
  N64 DAT kind (N64 BigEndian, N64 ByteSwapped, 64DD, Mario no Photopie SmartMedia, iQue CDN, iQue
  Decrypted, Aleck64 BigEndian, Aleck64 ByteSwapped), so a ROM/disk is checked against every
  relevant DAT simultaneously instead of only whichever single DAT was last loaded. "Load DAT…"
  loads one file; "Load all DATs…" multi-selects several (or all 8) at once — each file is
  auto-routed to the correct kind by matching its own `<header><name>` text. The top bar shows a
  collapsible table of every loaded DAT's name, version/date, and entry count. A "Check for DAT
  updates" button re-reads already-loaded DAT files from disk — it performs **no automatic or
  network-based update check on launch or otherwise**, since No-Intro's DAT-o-MATIC site
  explicitly prohibits automated/bot access (and bans offending IPs); users must download updated
  DATs themselves and this button (or a reload) simply picks up the change from disk.
- Full recognition of all 8 [libdragon open-source IPL3](https://github.com/DragonMinded/libdragon/tree/trunk/boot)
  revisions (r1-r8): CIC/bootcode identification now fingerprints each revision by its own
  SHA-1 (rather than reporting "Unknown"), labeling it e.g. "Libdragon open-source IPL3 (r8)",
  while still computing CRC1/CRC2 against CIC-6102's seed, since every libdragon production
  build is GPU-bruteforced specifically to match that checksum. All 8 revisions' raw 0xFC0-byte
  dumps (public domain/Unlicense) are bundled directly in the executable and auto-seeded into the
  `bootcodes` folder on startup, so they're immediately available to dump/patch with — no manual
  download needed. (r3 and r4 are bit-identical in this region, so both are included for
  completeness even though they're the same bytes.)
- GitHub Actions CI (fmt, clippy, build & test on Windows/macOS/Linux), a release workflow that
  builds and publishes binaries for all three platforms on tagged releases, and a Super Linter
  workflow for non-Rust files. I don't have a Mac, so that is just for testing and won't be supported. Linux is also pre-alpha at best. I'm working on it. :D
- Dependabot configuration, issue/PR templates, `CONTRIBUTING.md`, and a GPL-2.0-or-later `LICENSE.md`.
- Single-ROM and single-disk "Export Info to Text" buttons, plus a batch "Export info to text"
  action (the Batch tab was renamed from "Batch Convert" to just "Batch"). Exported report
  filenames include the source file's own extension (e.g. `game.z64_info.txt`) so same-named ROMs
  of different formats don't overwrite each other.
- "Convert & export info" option for both the single ROM/disk tabs (a checkbox next to the convert
  button) and the Batch tab (a third Action), writing a report for the converted output
  immediately after conversion, no second save dialog required.
- Proper Shift-JIS/GBK decoding (via `encoding_rs`) for the ROM header's Game Title field and 64DD
  MFS file/volume names, replacing the previous naive lossy UTF-8 decoding. China/iQue-region
  titles are tried as GBK first; everything else tries Shift-JIS first (a superset of the
  documented JIS X 0201 encoding), falling back to the other on decode errors.
- A "don't convert to big-endian when checking ROM info" option on the Single ROM tab: computes an
  additional CRC32/MD5/SHA-1 set against the ROM's original, native on-disk byte order, shown
  alongside (not replacing) the normalized hashes used for No-Intro/Redump verification. Header
  fields, CIC detection, and CRC1/CRC2 always use the normalized form, since they're only
  meaningful in the correct byte order.

## [0.1.0] - Initial feature set

### Added

- egui-based GUI for inspecting and converting N64 cartridge ROMs, with single-file and
  batch/folder processing modes and a live progress bar.
- ROM byte-order detection (big-endian `.z64`, byte-swapped `.v64`, little-endian `.n64`) based on
  file content, never file extension, plus lossless conversion between all three.
- Full N64 ROM header parsing, including the advanced homebrew header
  ([n64brew.dev ROM Header](https://n64brew.dev/wiki/ROM_Header)), and general ROM info (size,
  padding, etc.).
- CRC1/CRC2 boot checksum calculation (matching legacy emulator/ROM database expectations) plus
  CRC32, MD5, and SHA1 hashing.
- No-Intro `.dat` XML verification: match a ROM's hash against a loaded DAT to identify verified
  good dumps, unrecognized ROMs, or likely corrupt/modified dumps.
- CIC/boot-chip identification, including iQue (BBPlayer) and Aleck64 arcade variants.
- IPL3 boot code dumping (for inspection) and patching a ROM's IPL3 from dumps stored in a
  `bootcodes/` folder next to the application.
- PI (Peripheral Interface) timing extraction and grading, matching romjudge's PI-timing checks.
- Full N64DD (64DD) disk image support in its own tab: `.d64`, `.ndd` (raw), and MAME-format disk
  detection, hashing, info display, and conversion between formats (with explicit warnings that
  `.d64` is a lossy, trimmed format). Includes 64DD-specific CIC identification and MFS filesystem
  listing/extraction.
- About tab crediting ROM64, romjudge, and the N64DD tooling/documentation that informed this
  project's independent implementation.

[Unreleased]: https://github.com/derekturtleroe/Turtle64/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/derekturtleroe/Turtle64/releases/tag/v0.1.0
