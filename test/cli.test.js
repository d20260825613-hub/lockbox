import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import test from 'node:test';

import { installHandlers, run } from '../src/cli.js';
import { encryptFile } from '../src/crypto.js';
import { bytes, makeTempDir, sha256, writeFixture } from './helpers.js';

/** Capture stdout/stderr while running the CLI in-process. */
async function runCli(argv, env = {}) {
  const out = [];
  const err = [];
  const originalOut = process.stdout.write.bind(process.stdout);
  const originalErr = process.stderr.write.bind(process.stderr);
  const saved = {};
  for (const [key, value] of Object.entries(env)) {
    saved[key] = process.env[key];
    process.env[key] = value;
  }
  process.stdout.write = (chunk) => (out.push(String(chunk)), true);
  process.stderr.write = (chunk) => (err.push(String(chunk)), true);
  try {
    const code = await run(argv);
    return { code, stdout: out.join(''), stderr: err.join('') };
  } finally {
    process.stdout.write = originalOut;
    process.stderr.write = originalErr;
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

const PASSWORD = 'a-strong-test-password';
const ENV = { LOCKBOX_TEST_PW: PASSWORD };

async function fixtureDir(content = bytes(2048, 21)) {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'notes.bin', content);
  return { dir, input, content };
}

test('encrypt writes a container and leaves the original byte-identical', async () => {
  const { input, content } = await fixtureDir();
  const result = await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /original file was not touched/);
  assert.equal(sha256(await fs.readFile(input)), sha256(content), 'the input was modified');
  assert.equal((await fs.stat(`${input}.locked`)).isFile(), true);
});

test('decrypt restores the exact bytes to a new file by default', async () => {
  const { input, dir, content } = await fixtureDir();
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  // Remove the original so the default output name is free; this also mirrors
  // the real workflow of decrypting back to the name you started with.
  await fs.rm(input);
  const result = await runCli(['decrypt', `${input}.locked`, '--password-env', 'LOCKBOX_TEST_PW'], ENV);
  assert.equal(result.code, 0, result.stderr);
  const restored = path.join(dir, 'notes.bin');
  assert.equal(sha256(await fs.readFile(restored)), sha256(content));
});

test('an existing output file is never overwritten without --force', async () => {
  const { input, dir } = await fixtureDir();
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);

  const blocked = await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  // 2, not 1: refusing to clobber is the tool declining an impossible request
  // ("you asked for something I will not do"), which is the same category as a
  // typo -- the fix is to pass --force. This used to come back as 1, the code for
  // "the operation failed", so the README's table and the code disagreed.
  assert.equal(blocked.code, 2);
  assert.match(blocked.stderr, /already exists/);

  const forced = await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12', '--force'], ENV);
  assert.equal(forced.code, 0, forced.stderr);
  assert.equal((await fs.stat(path.join(dir, 'notes.bin.locked'))).isFile(), true);
});

test('a wrong password exits 1, says nothing was written, and leaves no output', async () => {
  const { input, dir } = await fixtureDir();
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  const output = path.join(dir, 'attempt.bin');

  const result = await runCli(
    ['decrypt', `${input}.locked`, '-o', output, '--password-env', 'SOME_OTHER_VAR'],
    { SOME_OTHER_VAR: 'definitely-not-the-password' },
  );
  assert.equal(result.code, 1);
  assert.match(result.stderr, /wrong password|modified/i);
  assert.match(result.stderr, /partial output was deleted/i);
  await assert.rejects(() => fs.access(output), 'a partial file survived a failed decryption');
});

test('the default output name for decrypt strips .locked', async () => {
  const { input, dir } = await fixtureDir();
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  await fs.rm(input);
  const result = await runCli(['decrypt', `${input}.locked`, '--password-env', 'LOCKBOX_TEST_PW'], ENV);
  assert.equal(result.code, 0, result.stderr);
  assert.equal((await fs.stat(path.join(dir, 'notes.bin'))).size, 2048);
});

test('decrypt refuses to write over its own input', async () => {
  const { input } = await fixtureDir();
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  const result = await runCli(
    ['decrypt', `${input}.locked`, '-o', `${input}.locked`, '--password-env', 'LOCKBOX_TEST_PW'],
    ENV,
  );
  // 2, not 1, for the same reason as the --force case above: nothing was
  // attempted and no I/O failed, the arguments describe something impossible.
  assert.equal(result.code, 2);
  assert.match(result.stderr, /same file/);
});

test('encrypt refuses to write over its own input', async () => {
  // The same rule on the encrypt side. It was checked in `resolveOutput` and
  // thrown as a plain Error, so it reached the generic handler and exited 1.
  const { input } = await fixtureDir();
  const result = await runCli(
    ['encrypt', input, '-o', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'],
    ENV,
  );
  assert.equal(result.code, 2);
  assert.match(result.stderr, /same file/);
});

test('two names for one file are refused as the same file', async () => {
  // A string comparison is not enough to answer "is this the same file", and
  // every way it falls short destroys data. A hard link is one file with two
  // names: `--force` used to write straight through it and truncate the input
  // while the read handle was still open, leaving a container that could not be
  // decrypted and a message saying the original had not been touched.
  const { dir, input, content } = await fixtureDir();
  const alias = path.join(dir, 'alias.bin');
  await fs.link(input, alias);

  const result = await runCli(
    ['encrypt', input, '-o', alias, '--force', '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'],
    ENV,
  );
  assert.equal(result.code, 2, `expected a refusal, got ${result.code}: ${result.stderr}`);
  assert.match(result.stderr, /same file/);
  assert.equal(sha256(await fs.readFile(input)), sha256(content), 'the input was destroyed through another name');

  await fs.rm(alias, { force: true });
});

test('the same name in different case is refused on a case-insensitive filesystem', async () => {
  // Windows and macOS treat `NOTES.BIN` and `notes.bin` as one file, while
  // `path.resolve` -- and `fs.realpath` on Windows -- keep whichever spelling
  // they were handed. Both directions used to end in a destroyed file: the
  // encrypt side truncated the input to a 96-byte broken container, and the
  // decrypt side deleted the only copy of the ciphertext.
  const caseInsensitive = process.platform === 'win32' || process.platform === 'darwin';
  const { dir, input, content } = await fixtureDir();
  const shouty = path.join(dir, 'NOTES.BIN');

  const encrypted = await runCli(
    ['encrypt', input, '-o', shouty, '--force', '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'],
    ENV,
  );
  assert.equal(encrypted.code, 2, `expected a refusal, got ${encrypted.code}: ${encrypted.stderr}`);
  if (caseInsensitive) {
    assert.match(encrypted.stderr, /same file/);
    assert.equal(sha256(await fs.readFile(input)), sha256(content), 'the input was truncated in place');
  } else {
    // On a case-sensitive filesystem these are two files, so the write is
    // allowed and the original has to survive it.
    assert.equal(sha256(await fs.readFile(input)), sha256(content));
    await fs.rm(shouty, { force: true });
  }

  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  const container = `${input}.locked`;
  const decrypted = await runCli(
    ['decrypt', container, '-o', container.toUpperCase(), '--force', '--password-env', 'LOCKBOX_TEST_PW'],
    ENV,
  );
  if (caseInsensitive) {
    assert.equal(decrypted.code, 2, `expected a refusal, got ${decrypted.code}: ${decrypted.stderr}`);
    assert.match(decrypted.stderr, /same file/);
    assert.equal((await fs.stat(container)).isFile(), true, 'the only copy of the container was deleted');
  }
});

test('a failure never deletes a file this run did not create', async () => {
  // The cleanup deleted the output *path* on any error, so the two failures
  // below -- a container that is not a container, and an input that is not
  // there -- destroyed files that had never been opened, let alone written.
  const { dir } = await fixtureDir();
  const precious = await writeFixture(dir, 'precious.txt', 'IRREPLACEABLE USER DATA');
  const alsoPrecious = await writeFixture(dir, 'precious2.locked', 'ALSO PRECIOUS');
  const bad = await writeFixture(dir, 'bad.locked', Buffer.alloc(4096, 0x41));

  const failedDecrypt = await runCli(
    ['decrypt', bad, '-o', precious, '--force', '--password-env', 'LOCKBOX_TEST_PW'],
    ENV,
  );
  assert.equal(failedDecrypt.code, 2, failedDecrypt.stderr);
  assert.equal(String(await fs.readFile(precious)), 'IRREPLACEABLE USER DATA');

  const missingInput = await runCli(
    ['encrypt', path.join(dir, 'no-such-input.txt'), '-o', alsoPrecious, '--force', '--password-env', 'LOCKBOX_TEST_PW'],
    ENV,
  );
  assert.equal(missingInput.code, 2, missingInput.stderr);
  assert.equal(String(await fs.readFile(alsoPrecious)), 'ALSO PRECIOUS');

  // Nothing temporary is left in the directory either.
  assert.deepEqual(
    (await fs.readdir(dir)).filter((name) => name.includes('.tmp')),
    [],
  );
});

test('a directory is refused as input instead of being encrypted into an empty file', async () => {
  // On Windows `fs.open` on a directory succeeds and reports a size of zero, so
  // the chunk loop read nothing and encrypt reported success: a 56-byte
  // container, "0 bytes of data" and "the original file was not touched". The
  // other two commands leaked a raw EISDIR instead of naming the argument.
  const { dir } = await fixtureDir();
  const nested = path.join(dir, 'proj');
  await fs.mkdir(nested);
  await writeFixture(nested, 'secret.txt', bytes(200, 26));

  const encrypted = await runCli(['encrypt', nested, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  assert.equal(encrypted.code, 2, `expected a refusal, got ${encrypted.code}: ${encrypted.stderr}`);
  assert.match(encrypted.stderr, /is a directory/);
  await assert.rejects(() => fs.access(`${nested}.locked`), 'a directory was turned into a container');

  for (const command of ['decrypt', 'inspect']) {
    // `decrypt` asks for a password before it opens the input, so it needs one
    // here; without it the test would sit at the prompt instead of testing the
    // directory check.
    const result = await runCli([command, nested, '--password-env', 'LOCKBOX_TEST_PW'], ENV);
    assert.equal(result.code, 2, `${command}: expected 2, got ${result.code}: ${result.stderr}`);
    assert.match(result.stderr, /is a directory/, command);
    assert.doesNotMatch(result.stderr, /EISDIR/, `${command} leaked the raw platform error`);
  }
});

test('an interrupted run reports it and leaves no partial output behind', async () => {
  // Ctrl-C used to exit the process from the signal handler, which skipped the
  // cleanup that removes a partial output -- while printing that none had been
  // left. The container here is built with 256-byte chunks so the decrypt has
  // thousands of chunks to work through and the signal lands in the middle of it.
  // A real signal would end this process, so the handler is driven the way the
  // OS drives it: `process.emit('SIGINT', 'SIGINT')`.
  const dir = await makeTempDir();
  const plain = bytes(1024 * 1024, 27);
  const input = await writeFixture(dir, 'big.bin', plain);
  const container = path.join(dir, 'big.locked');
  const output = path.join(dir, 'big.out');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: 256, log2N: 12 });

  const remove = installHandlers();
  let result;
  try {
    const pending = runCli(['decrypt', container, '-o', output, '--password-env', 'LOCKBOX_TEST_PW'], ENV);
    // Wait for the write to be under way, then interrupt it. The output file is
    // created before the first chunk is decrypted, so this is not a race with
    // the start of the run.
    const deadline = Date.now() + 30_000;
    for (;;) {
      try {
        await fs.access(output);
        break;
      } catch {
        if (Date.now() > deadline) throw new Error('the decrypt never started writing');
        await new Promise((resolve) => setTimeout(resolve, 1));
      }
    }
    process.emit('SIGINT', 'SIGINT');
    result = await pending;
  } finally {
    remove();
  }

  assert.equal(result.code, 130, `expected 130 for Ctrl-C, got ${result.code}: ${result.stderr}`);
  assert.match(result.stderr, /stopped/);
  await assert.rejects(() => fs.access(output), 'a partial plaintext file survived the interruption');
  assert.deepEqual(
    (await fs.readdir(dir)).filter((name) => name.includes('.tmp')),
    [],
  );
});

test('inspect uses the same exit codes as encrypt and decrypt', async () => {
  // The README and the changelog both promise 2 for a missing file and for a
  // container that fails its format check, and a script that branches on those
  // codes got the opposite answer from `inspect`: every failure came back as 1.
  const { dir, input } = await fixtureDir();
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);

  const missing = await runCli(['inspect', path.join(dir, 'nope.locked')]);
  assert.equal(missing.code, 2, missing.stderr);
  assert.match(missing.stderr, /no such file/);

  const plain = await writeFixture(dir, 'plain.bin', Buffer.alloc(4096, 0x41));
  const notAContainer = await runCli(['inspect', plain]);
  assert.equal(notAContainer.code, 2, notAContainer.stderr);
  assert.match(notAContainer.stderr, /not a lockbox file/);

  const tiny = await writeFixture(dir, 'tiny.bin', Buffer.from('LBOXv1'));
  const tooShort = await runCli(['inspect', tiny]);
  assert.equal(tooShort.code, 2, tooShort.stderr);
  assert.match(tooShort.stderr, /too short/);
});

test('an unwritable output is reported as an output problem, not a missing input', async () => {
  // Both failures arrive as ENOENT from the same function, and both used to be
  // reported as `<input> is missing` -- which sends the user to check a file
  // that is perfectly fine.
  const { dir, input } = await fixtureDir();
  const missingDirectory = path.join(dir, 'nodir');

  const encrypting = await runCli(
    ['encrypt', input, '-o', path.join(missingDirectory, 'out.locked'), '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'],
    ENV,
  );
  assert.equal(encrypting.code, 2, encrypting.stderr);
  assert.match(encrypting.stderr, /cannot write/);
  assert.doesNotMatch(encrypting.stderr, /no such file: .*notes\.bin/);

  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  const decrypting = await runCli(
    ['decrypt', `${input}.locked`, '-o', path.join(missingDirectory, 'out.bin'), '--password-env', 'LOCKBOX_TEST_PW'],
    ENV,
  );
  assert.equal(decrypting.code, 2, decrypting.stderr);
  assert.match(decrypting.stderr, /cannot write/);
  assert.doesNotMatch(decrypting.stderr, /no such file: .*notes\.bin\.locked/);
});

test('a header asking for an impossible scrypt cost is refused before any key is derived', async () => {
  // The key used to be derived with whatever r and p the header named, before a
  // single tag was checked, so a 40-byte file could make this machine allocate
  // hundreds of gigabytes and stall for minutes -- and then report the same
  // "wrong password" it could have reported at once.
  const { dir, input } = await fixtureDir();
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  const data = await fs.readFile(`${input}.locked`);

  const greedy = Buffer.from(data);
  greedy.writeUInt8(255, 11);
  greedy.writeUInt8(255, 12);
  const greedyPath = await writeFixture(dir, 'greedy.locked', greedy);

  const started = Date.now();
  const inspected = await runCli(['inspect', greedyPath]);
  const elapsed = Date.now() - started;
  assert.equal(inspected.code, 2, inspected.stderr);
  assert.match(inspected.stderr, /r=255/);
  assert.doesNotMatch(inspected.stdout, /GB/, 'the cost of a hostile header was reported as if it were usable');
  assert.ok(elapsed < 5000, `the refusal took ${elapsed} ms, so work was done before the parameters were checked`);

  const decrypted = await runCli(
    ['decrypt', greedyPath, '-o', path.join(dir, 'greedy.out'), '--password-env', 'LOCKBOX_TEST_PW'],
    ENV,
  );
  assert.equal(decrypted.code, 2, decrypted.stderr);
  await assert.rejects(() => fs.access(path.join(dir, 'greedy.out')), 'a rejected container produced output');
});

test('a password file saved with a UTF-8 BOM still opens the file', async () => {
  // Notepad writes a BOM by default, and the BOM used to become part of the
  // password: the file could then only be opened by that same file, and losing
  // it meant losing the data. A lone `\r` was not a line ending either, so a
  // password file with Mac line endings became one long password.
  const { dir, input } = await fixtureDir();
  const withBom = path.join(dir, 'pw-bom.txt');
  const plain = path.join(dir, 'pw-plain.txt');
  await fs.writeFile(withBom, `\uFEFF${PASSWORD}\n`);
  await fs.writeFile(plain, `${PASSWORD}\n`);
  await fs.writeFile(path.join(dir, 'pw-cr.txt'), `${PASSWORD}\rignored\r`);

  const encrypted = await runCli(['encrypt', input, '--password-file', withBom, '--cost', '12'], ENV);
  assert.equal(encrypted.code, 0, encrypted.stderr);

  for (const passwordFile of [plain, path.join(dir, 'pw-cr.txt')]) {
    const output = path.join(dir, `back-${path.basename(passwordFile)}`);
    const decrypted = await runCli(['decrypt', `${input}.locked`, '-o', output, '--password-file', passwordFile], ENV);
    assert.equal(decrypted.code, 0, `${path.basename(passwordFile)}: ${decrypted.stderr}`);
    assert.equal(sha256(await fs.readFile(output)), sha256(bytes(2048, 21)));
  }
});

test('an empty --out is an error instead of being quietly ignored', async () => {
  const { input } = await fixtureDir();
  const result = await runCli(['encrypt', input, '--out=', '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  assert.equal(result.code, 2, result.stderr);
  assert.match(result.stderr, /--out needs a non-empty file name/);
  await assert.rejects(() => fs.access(`${input}.locked`), 'the default name was used after an explicit empty --out');
});

test('inspect takes exactly one file, like the other two commands', async () => {
  const { input } = await fixtureDir();
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);
  const result = await runCli(['inspect', `${input}.locked`, input]);
  assert.equal(result.code, 2, result.stderr);
  assert.match(result.stderr, /exactly one file/);
});

test('--help and --version work after a command, not only before it', async () => {
  // Both are listed under Options, but only the top level accepted them, so
  // `encrypt --help` answered "unknown option --help / did you mean --help?".
  for (const command of ['encrypt', 'decrypt', 'inspect']) {
    const help = await runCli([command, '--help']);
    assert.equal(help.code, 0, `${command} --help: ${help.stderr}`);
    assert.match(help.stdout, /lockbox - encrypt a file with a password/, command);

    const shortHelp = await runCli([command, '-h']);
    assert.equal(shortHelp.code, 0, `${command} -h: ${shortHelp.stderr}`);

    const version = await runCli([command, '--version']);
    assert.equal(version.code, 0, `${command} --version: ${version.stderr}`);
    assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+$/, command);
  }
});

test('inspect reports the header and flags a truncated container', async () => {
  const { input } = await fixtureDir(bytes(3000, 22));
  await runCli(['encrypt', input, '--password-env', 'LOCKBOX_TEST_PW', '--cost', '12'], ENV);

  const good = await runCli(['inspect', `${input}.locked`]);
  assert.equal(good.code, 0, good.stderr);
  assert.match(good.stdout, /format\s+lockbox v1/);
  assert.match(good.stdout, /scrypt, log2\(N\)=12/);
  assert.match(good.stdout, /matches the header/);

  const data = await fs.readFile(`${input}.locked`);
  await fs.writeFile(`${input}.locked`, data.subarray(0, data.length - 32));
  const bad = await runCli(['inspect', `${input}.locked`]);
  assert.equal(bad.code, 2, 'a damaged container should be reported, not silently accepted');
  assert.match(bad.stdout, /TRUNCATED/);
});

test('bad arguments exit 2, which is a different code from a failed operation', async () => {
  // 2 means "you typed it wrong"; 1 means "the operation failed". A script can
  // tell them apart, which it cannot when both are 1.
  assert.equal((await runCli(['encrypt'])).code, 2);
  assert.equal((await runCli(['decrypt'])).code, 2);
  assert.equal((await runCli(['frobnicate', 'x'])).code, 2);
  assert.equal((await runCli(['encrypt', 'x', '--cost', '4'])).code, 2);
  assert.equal((await runCli(['encrypt', 'missing-file.txt', '--password-env', 'NOPE'])).code, 1);
});

test('a mistyped option comes back with a suggestion', async () => {
  const typo = await runCli(['encrypt', 'x', '--colr']);
  assert.equal(typo.code, 2);
  assert.match(typo.stderr, /unknown option --colr/);
  assert.match(typo.stderr, /did you mean --cost\?/);

  const nonsense = await runCli(['encrypt', 'x', '--totally-made-up']);
  assert.match(nonsense.stderr, /unknown option/);
  assert.match(nonsense.stderr, /run with --help/);
});

test('an option that needs a value says so instead of reading undefined', async () => {
  const result = await runCli(['encrypt', 'x', '--out']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /--out needs a value/);
  assert.match(result.stderr, /for example --out <value>/);
});

test('an unknown command lists what the commands are', async () => {
  const result = await runCli(['encrpty', 'x']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /unknown command: encrpty/);
  assert.match(result.stderr, /encrypt, decrypt and inspect/);
});

test('a usage error does not print a stack trace, and --debug makes it', async () => {
  const plain = await runCli(['encrypt', 'x', '--nonsense']);
  assert.equal(/at .*\(.*:\d+:\d+\)/.test(plain.stderr), false, 'no stack frames in a friendly error');

  const debug = await runCli(['encrypt', 'x', '--cost', '4', '--debug']);
  assert.match(debug.stderr, /--cost must be an integer/);
});

test('errors cannot hide the hint behind a stack trace', async () => {
  const result = await runCli(['encrypt', 'a', 'b']);
  assert.match(result.stderr, /exactly one file/);
  assert.equal(result.stderr.split('\n').filter((l) => l.trim()).length, 1, 'one line, no stack');
});

test('--help and --version do not touch the filesystem', async () => {
  const help = await runCli(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /lockbox - encrypt a file with a password/);
  assert.match(help.stdout, /has not been audited/);

  const version = await runCli(['--version']);
  assert.equal(version.code, 0);
  assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('a missing environment variable is reported instead of prompting', async () => {
  const { input } = await fixtureDir(bytes(64, 23));
  const result = await runCli(['encrypt', input, '--password-env', 'NOT_SET_ANYWHERE'], { NOT_SET_ANYWHERE: '' });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /NOT_SET_ANYWHERE/);
});

test('a password file works and only its first line is used', async () => {
  const { input, dir } = await fixtureDir(bytes(512, 24));
  const passwordFile = path.join(dir, 'pw.txt');
  await fs.writeFile(passwordFile, `${PASSWORD}\nignored second line\n`);

  const encrypted = await runCli(['encrypt', input, '--password-file', passwordFile, '--cost', '12']);
  assert.equal(encrypted.code, 0, encrypted.stderr);

  const output = path.join(dir, 'back.bin');
  const decrypted = await runCli(['decrypt', `${input}.locked`, '-o', output, '--password-file', passwordFile]);
  assert.equal(decrypted.code, 0, decrypted.stderr);
  assert.equal(sha256(await fs.readFile(output)), sha256(bytes(512, 24)));
});

test('an interactive prompt on a closed stdin fails cleanly instead of hanging', async () => {
  // The bug this pins down, and it needs a real subprocess to see: when stdin
  // reaches end-of-file before a newline, readline emits `close` and no `line`
  // and no `error`. The prompt's promise therefore never settled, so
  // `lockbox encrypt f < /dev/null` died with "Detected unsettled top-level
  // await" and exited 13 -- an errno, not one of this tool's exit codes.
  //
  // Both shapes of the failure are covered, because they end in different places:
  // an empty stdin ends the stream while the first prompt waits, while one line
  // ends it before the confirm prompt starts -- and there readline stays silent
  // even about `close`, which is why the source checks `readableEnded` too.
  const { input, dir } = await fixtureDir(bytes(64, 25));
  const bin = fileURLToPath(new URL('../bin/lockbox.js', import.meta.url));

  for (const [what, stdin] of [
    ['empty stdin', ''],
    ['one line, so the confirm prompt never gets an answer', `${PASSWORD}\n`],
  ]) {
    const result = spawnSync(process.execPath, [bin, 'encrypt', input, '--cost', '12'], {
      cwd: dir,
      input: stdin,
      encoding: 'utf8',
      timeout: 60_000,
    });

    assert.equal(result.error, undefined, `${what}: the CLI did not exit: ${result.error?.message}`);
    assert.equal(result.signal, null, `${what}: the CLI had to be killed by ${result.signal}`);
    assert.equal(result.status, 1, `${what}: expected exit 1, got ${result.status}: ${result.stderr}`);
    assert.match(result.stderr, /no password was given/i, what);
    // The way out belongs in the message: without it the user is stuck.
    assert.match(result.stderr, /pass --password-file, --password-env/, what);
    assert.doesNotMatch(result.stderr, /unsettled top-level await/, what);
  }
});
