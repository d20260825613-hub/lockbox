# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-15

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
- `inspect` 现在和 `encrypt`、`decrypt` 使用同一套退出码:文件不存在、容器格式检查失败
  都返回 2(此前一律返回 1),与 README 的退出码表和本文件的既有承诺一致。
- 把目录当输入时三个命令都以 2 拒绝,并明确说明这是一个目录(此前 `encrypt` 在
  Windows 上会静默成功、生成一个空容器并声称原文件未被动过,`decrypt`/`inspect`
  则抛出原始的 `EISDIR`)。
- `--out=`(显式给出的空值)现在报 `--out needs a non-empty file name` 并以 2 退出,
  而不是悄悄回退到默认文件名。
- `-h`/`--help`/`-v`/`--version` 在子命令之后同样可用。此前 `encrypt --help` 的答复是
  `unknown option --help` 加一句 `did you mean --help?`,自相矛盾且毫无帮助。

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
- 同文件守卫不再被 Windows 的大小写绕过。此前判定基于 `path.resolve` 的字符串比较,
  于是 `encrypt notes.txt -o NOTES.TXT --force` 会以 `w` 打开同一个文件、把正在读取的
  输入截断,再报告「原文件未被动过」;解密方向更严重,`decrypt a.bin.locked -o
  A.BIN.LOCKED --force` 会删掉密文的唯一副本。现在输出已存在时用 (dev, ino) 判定同一
  文件,不存在时比较 realpath 并按平台做大小写不敏感比较,硬链接、junction、8.3 短名
  同样能被识别。加密结束后还会校验输入未被改动,发现即丢弃输出。
- 失败路径不再删除输出路径上既有的文件。此前只要 `--force` 通过了存在性检查,之后任何
  失败都执行 `fs.rm(output)`:输入文件不存在、容器头非法,都会连带删掉一个本次运行从未
  打开过的文件。现在只有本次运行创建的文件才可能被删除,`--force` 覆盖时先写同目录临时
  文件、全部完成后再 rename 到位,失败时目标文件原样保留;清理本身的错误也不会再掩盖
  原始错误。
- 容器头部的 `r`/`p` 不再无上界。密钥派生先于任何标签校验,攻击者只要提供一个 40 字节的
  文件就能让本机按 128 * N * r 去分配内存(实测 `r=255` 时 `inspect` 会心安理得地报告
  「约 128 GB」)。现在读写两侧一致地限制 `r<=32`、`p<=16`,且一次派生可申请的内存不超过
  本构建自身能写出的最贵容器(`log2(N)=22`、`r=8`,即 4 GiB),超限直接以格式错误退出 2。
  API 侧同样校验,不会再写出自己都打不开的容器(`{ r: 0 }` 以前能成功落盘却永远无法解密)。
- 分块 nonce 的索引不再溢出。nonce 是盐值异或进 32 位索引,于是第 `i` 块与第 `i + 2^32`
  块会用同一个 nonce;同一密钥下 GCM 的 nonce 复用等于泄露密钥流,最终可恢复认证密钥。
  现在 `chunkNonce` 拒绝放不下的索引,`parseHeader`/`buildHeader` 拒绝块数超过 `2^32 - 1`
  的容器(CLI 路径本已不可达,通道是 API 传入自定义分块大小)。
- 输出目录不存在时不再误报成输入文件不存在。ENOENT 现在按 `error.path` 区分方向,输出侧
  给出 `cannot write <output>: its directory does not exist`,而不是让用户去检查一个完好
  的输入文件。
- `--password-file` 不再把 UTF-8 BOM 当成口令的一部分,也不再只认 `\n` 行尾:Windows 记事本
  默认带 BOM,老式 Mac 行尾是单独的 `\r`,两者都会生成一个人工无法输入的口令,文件一旦丢失
  数据即永久不可解。
- `test:files` 脚本指向一个从未提交的 `scripts/test-files.js`,执行只会得到
  `MODULE_NOT_FOUND`;`npm test` 的 glob 在 Node 18–20 上无效,而 `engines` 承诺支持
  `>=18.17`。前者删除,后者改为显式列出测试文件,与 `build.ps1` 的做法一致。

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

[Unreleased]: https://github.com/d20260825613-hub/lockbox/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/d20260825613-hub/lockbox/releases/tag/v0.2.0
[0.1.0]: https://github.com/d20260825613-hub/lockbox/releases/tag/v0.1.0
