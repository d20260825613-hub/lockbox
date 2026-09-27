# lockbox

Encrypt a file with a password.

```console
$ lockbox encrypt tax-return.pdf
Password:
Repeat password:
tax-return.pdf -> tax-return.pdf.locked
  2.4 MB of data, 1 chunk(s)
  scrypt log2(N)=16, about 64 MB of memory per attempt
  the original file was not touched

$ lockbox decrypt tax-return.pdf.locked
Password:
tax-return.pdf.locked -> tax-return.pdf
  2.4 MB (2,441,673 bytes) restored
```

Three commands, no configuration file, no dependencies. Node 18.17 or newer.

## Read this before you trust it with anything important

I would rather you use this correctly than use it at all.

**There is no password recovery.** The password is not stored anywhere, in any
form. Nobody can reset it, including whoever wrote this. If you forget it, the
file is permanently unreadable. There is no backdoor and no support channel that
can help. **Keep a backup of anything you encrypt.**

**The container format is mine, and nobody has reviewed it.** The primitives are
not mine - scrypt and AES-256-GCM both come from Node's own crypto module - but
the way they are combined into a file format is specific to this tool. It has not
been audited by anyone. Do not treat it as equivalent to an established tool like
age, VeraCrypt or GnuPG, which have had years of scrutiny.

**A password is only as strong as the password.** scrypt makes each guess cost
about 64 MB of memory, which is expensive on purpose, but a short or common
password is still broken by dictionary attack. Use a passphrase of several
random words, or a password manager.

**This is not a replacement for full-disk encryption.** It protects a file at
rest. It does not protect a file while you have it open, it does not hide that
you have a file, and it does not stop malware already running on your machine.

**No plausible deniability, no key files, no hardware keys.** If you need any of
those, this is the wrong tool.

## Install

```bash
npx lockbox-cli encrypt notes.txt

# or install it once
npm install -g lockbox-cli
lockbox encrypt notes.txt
```

The package name is `lockbox-cli` because `lockbox` was taken on npm; the
command it installs is `lockbox`.

## Commands

### `lockbox encrypt <file>`

Writes `<file>.locked` and **leaves the original alone**. Nothing is deleted or
modified, so a mistake costs you nothing.

| Option | Meaning |
| --- | --- |
| `-o, --out <file>` | Write somewhere other than `<file>.locked` |
| `-f, --force` | Allow overwriting an existing output file |
| `--cost <n>` | scrypt log2(N), 12 to 22. Default 16, about 64 MB per attempt |
| `--password-env <VAR>` | Read the password from an environment variable |
| `--password-file <file>` | Read the first line of a file as the password |
| `--no-progress` | Do not print a progress line |

### `lockbox decrypt <file.locked>`

Writes the original bytes back. With no `--out`, `<file.locked>` becomes
`<file>`. **A failed decryption deletes its partial output**, so a wrong password
never leaves a file that looks like it worked.

### `lockbox inspect <file.locked>`

Reads the header without a password: format version, KDF parameters, memory
cost, the recorded plaintext size, and whether the file's actual size matches
what the header describes. Exits 2 if the container is truncated or has extra
data appended.

```console
$ lockbox inspect notes.txt.locked
notes.txt.locked
  format          lockbox v1
  key derivation  scrypt, log2(N)=16, r=8, p=1
  memory cost     about 64 MB per attempt
  plaintext       70 bytes
  chunks          1
  container       126 bytes  (matches the header)
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | the command did what it was asked |
| 1 | the operation failed: a wrong password, a damaged container, an unreadable file |
| 2 | the request was impossible: a bad option, a missing file, refusing to overwrite without `--force`, output and input being the same file |

The split matters in a script. `2` means nothing was attempted and passing
`--force` (or fixing the command) may be all that is needed; `1` means the tool
tried and the data, the password or the disk said no, so retrying the same way
will not help. A failed decryption is always `1` and always leaves no output
behind.

## How it works

Two layers, and both are worth understanding before you rely on this.

### The key

scrypt turns your password into a 32-byte key:

```
key = scrypt(password, salt, N=2^16, r=8, p=1)
```

`N`, `r` and `p` are written into the file header, so a file encrypted today can
still be opened if the defaults change later. The salt is 16 random bytes per
file, so the same password on the same content produces a different key every
time and the same file encrypted twice shares nothing.

### The data

AES-256-GCM, in 4 MiB chunks, each one authenticated on its own. The file is
never held in memory in full, so a 10 GB file needs about 8 MB of RAM.

Each chunk's authentication also covers:

- a digest of the whole header, so no KDF parameter can be edited
- the chunk's index, so chunks cannot be reordered
- whether the chunk is the last one, so **the file cannot be truncated**

That last point is the reason for the chunking design. A naive scheme that just
concatenates encrypted blocks lets an attacker cut the file short and you would
never know. Here, a missing or reordered chunk fails authentication and
decryption stops with an error.

### The container

```
offset  size  field
0       8     magic "LBOXv1\0\0"
8       1     format version
9       1     key derivation id (1 = scrypt)
10      1     log2(N)
11      1     r
12      1     p
13      1     log2(chunk size)
14      2     reserved
16      16    salt (also the nonce base)
32      8     plaintext length, big-endian
40      ...   chunks: ciphertext || 16-byte GCM tag
```

Every field is authenticated: the first 40 bytes are hashed into the additional
data of every chunk. Changing the recorded length, the KDF parameters or the
chunk size makes decryption fail rather than produce wrong output.

## Passwords, honestly

**Prefer `--password-env` or `--password-file` in scripts.** A password given as
a command-line argument would be visible to every process on the machine.

**Interactive prompts read from the terminal**, not from stdin, so
`cat secret | lockbox encrypt f` still prompts properly. On Windows there is no
`/dev/tty`, so the prompt is used with echo.

**Encryption asks twice.** A typo would lock the file forever, so it is worth
one extra line.

## Testing

```bash
npm test
```

29 tests. The ones that matter most are the negative ones: a wrong password, a
single flipped byte, an edited header, a truncated file, a removed chunk, two
swapped chunks. Each of those must fail loudly, and each has a test asserting it
does.

## What the API looks like

```js
import { encryptFile, decryptFile, inspectFile } from 'lockbox-cli';

await encryptFile({ input: 'notes.txt', output: 'notes.txt.locked', password });
await decryptFile({ input: 'notes.txt.locked', output: 'notes.txt', password });
console.log(await inspectFile('notes.txt.locked'));
```

## License

MIT. See [LICENSE](LICENSE).
