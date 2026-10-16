# TODO

## Coverage-guided fuzzing

Add long-running fuzz tests with `cargo-fuzz` (libFuzzer).

- Create `fuzz/` with fuzz targets that feed raw bytes to:
  - `pe::parse` (import and delay-import tables, DLL names)
  - the API-set schema parser (`ApiSetSchema::parse`)
  - `valid_dll_name`
- The `object` crate is already fuzzed by OSS-Fuzz; the targets should cover our own code.
- `cargo-fuzz` needs nightly Rust and does not support the `x86_64-pc-windows-gnu`
  toolchain used here, so run it under WSL or on Linux (the parsing code is not
  Windows-specific). `cargo-afl` is an alternative.
- Keep the corpus and any crashing inputs as regression tests.
