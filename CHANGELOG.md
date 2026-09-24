# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

## [Unreleased]

### Added

- GitHub Actions CI (fmt, clippy, build & test on Windows/macOS/Linux), a release workflow that
  builds and publishes binaries for all three platforms on tagged releases, and a Super Linter
  workflow for non-Rust files. I don't have a Mac, so that is just for testing and won't be supported. Linux is also pre-alpha at best. I'm working on it. :D
- Dependabot configuration, issue/PR templates, `CONTRIBUTING.md`, and GPLv2 `LICENSE`.

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
