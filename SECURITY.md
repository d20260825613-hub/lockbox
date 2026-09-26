# Security

## Reporting a problem

Open a private report at
https://github.com/d20260825613-hub/lockbox/security/advisories/new rather than a
public issue. If that is unavailable, open an issue that says only "security
report - please contact me" and nothing more.

Please include what you did, what happened, and what an attacker gains. A
proof of concept against a file you created yourself is the most useful thing
you can send.

Expect an initial reply within a week. This is a spare-time project with one
maintainer, so that is the honest estimate rather than a promise.

## What lockbox is designed to do

Protect the **contents of a file at rest**, with a password, against someone who
gets a copy of the encrypted file.

| Attack | Covered? | Why |
| --- | --- | --- |
| Reading the file without the password | Yes | AES-256-GCM with a scrypt-derived key |
| Guessing the password offline | Slowed, not prevented | scrypt costs about 64 MB and ~0.1 s per attempt. A weak password still falls to a dictionary attack |
| Editing the encrypted file | Yes | GCM is authenticated; the change is detected, not decrypted |
| Truncating the file | Yes | Every chunk binds a final-chunk marker, so a short file fails |
| Reordering or swapping chunks | Yes | Every chunk binds its own index |
| Editing the header (KDF cost, recorded size) | Yes | The header is hashed into every chunk's additional data |
| Reusing a nonce across files | No | 16 random bytes per file, so the chance is negligible by design |

## What it does not do

These are not bugs. They are outside the design, and reporting them will get a
pointer back to this file.

- **It does not protect a file while it is open.** Once decrypted, the plaintext
  is an ordinary file on an ordinary disk. Full-disk encryption is the tool for
  that.
- **It does not hide that a file exists**, or how large it is, or when it was
  last changed. The container's size reveals the plaintext size to within a few
  bytes. There is no padding and no plausible deniability.
- **It does not protect against a compromised machine.** Malware that can read
  your keystrokes, your terminal, or your process memory gets the password and
  the plaintext. Nothing user-space can fix that.
- **It does not resist a determined attacker with a weak password.** scrypt buys
  time, not immunity. Several random words or a password manager are the answer.
- **There is no password recovery, by design.** No escrow, no hint, no reset. If
  the password is lost the data is gone. This is worth repeating.
- **It does not shred anything.** Deleting a file does not erase it from a disk,
  and lockbox never deletes anyway.
- **The format has not been audited** by anyone outside this project. The
  primitives come from Node, but their arrangement here is mine.

## Threat model in one paragraph

Assume the attacker has a copy of the encrypted file and full knowledge of this
format and this code. They do not have the password, and they cannot run code on
your machine while you decrypt. Under those assumptions, the attacker learns only
the approximate size of the plaintext. Everything else requires the password.

## Supported versions

Pre-1.0. Only the latest release is fixed. Please confirm an issue against `main`
before reporting it.

## Dependencies

There are none. `package.json` has no `dependencies` field, and everything the
program uses comes from Node's standard library. If a dependency ever appears, it
is a bug.
