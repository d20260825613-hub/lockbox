import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import test from 'node:test';

import { run } from '../src/cli.js';
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
