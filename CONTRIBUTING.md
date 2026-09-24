# Contributing to Turtle64

Thanks for your interest in improving Turtle64! Contributions of all kinds are welcome —
bug reports, bug fixes, new format/CIC/header support, docs, and UI polish.

## Getting started

1. Install a recent stable [Rust toolchain](https://rustup.rs/).
2. Clone the repo and build it:

   ```sh
   cargo build
   cargo run
   ```

3. On Linux you'll need the usual `eframe`/`rfd` GUI dependencies, e.g. on Debian/Ubuntu:

   ```sh
   sudo apt-get install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
     libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
   ```

## Before opening a pull request

Please make sure the following all pass locally — CI runs the same checks:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Guidelines

- Keep changes focused; unrelated refactors make review harder.
- Add or update unit tests for any new parsing/conversion/checksum logic.
- Update `README.md` and `CHANGELOG.md` for user-facing changes.
- Do not copy code from other projects (including ROM64 or romjudge). Reimplement behavior
  from first principles or from public documentation/specs — see the About tab and README
  for the reference material this project already draws on.
- Do not include copyrighted ROM/disk image files in issues, PRs, or test fixtures.

## Reporting bugs / requesting features

Please use the issue templates provided when opening a new issue.
