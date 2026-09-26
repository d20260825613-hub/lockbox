# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-26

### Added

- `lockbox encrypt`, `lockbox decrypt` and `lockbox inspect`.
- scrypt key derivation with the parameters stored in the file header, so a
  future build can still open files written today.
- AES-256-GCM in 4 MiB chunks, each chunk authenticated against the header
  digest, its own index and whether it is the final chunk. Truncating,
  reordering or editing a container therefore fails authentication instead of
  producing wrong plaintext.
- Self-describing container format (`LBOXv1`), 40-byte header, documented in the
  README.
- Safety rules the CLI enforces: the input file is never modified, an existing
  output file is never replaced without `--force`, and a failed decryption
  deletes its partial output.
- Password input from an environment variable, from a file, or from a terminal
  prompt that reads `/dev/tty` rather than stdin. Encryption asks twice.
- 29 tests, mostly asserting that damaged or forged input is rejected.

[Unreleased]: https://github.com/d20260825613-hub/lockbox/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/d20260825613-hub/lockbox/releases/tag/v0.1.0
