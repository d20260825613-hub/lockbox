# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--debug` (or `LOCKBOX_DEBUG=1`) prints a stack trace for an unexpected error.
  Without it an error is a message and a hint, never a wall of `node:internal`.
- "did you mean" suggestions for a mistyped option, and an explicit message when
  an option that needs a value does not get one.
- The shared process handlers for a broken pipe, Ctrl-C and the two leftover
  error events: `lockbox decrypt x | head` now exits quietly instead of printing
  an EPIPE stack trace.

### Changed

- Exit codes are now uniform: 2 for bad arguments, an unknown command, a missing
  file and a container that fails its format check; 1 for a failed operation, a
  wrong password included.
- Refusing to overwrite an existing output without `--force`, or to write the
  output over the input, now exits 2 instead of 1. Both are decisions made before
  anything is touched — the arguments describe something impossible — so they
  belong with the usage errors, and the README always said so. Only the code
  disagreed.
- Errors are printed as one `lockbox: ...` line with the hint under it. Reporting
  went through `formatError` before, but the message alone was written out, so
  every hint was silently dropped.

### Fixed

- A password prompt on a closed stdin no longer hangs. `readline` emits no
  `line`, no `error` and — for a stream that had already ended before the prompt
  started — no `close`, so the promise never settled. Node then reported
  "Detected unsettled top-level await" and exited 13, an errno rather than one of
  this tool's exit codes. `lockbox encrypt f < /dev/null` and a here-string with
  a single line (the confirm prompt is the one that hangs) now exit 1 with an
  explanation and the flags that would have supplied a password.
- `installHandlers` was called only from the direct-run block in `src/cli.js`, so
  it never fired for the installed `lockbox` command: the bin entry imports the
  module rather than running it. `bin/lockbox.js` now installs the handlers
  itself, which is what makes the broken-pipe and Ctrl-C cases work in real use.
- `PasswordError` carries a `hint` again. `formatError` reads that field by name,
  so the constructor dropping it meant an error could explain the problem and
  stay silent about the way out.

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
