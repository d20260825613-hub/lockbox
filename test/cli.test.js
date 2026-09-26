import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
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
  assert.equal(blocked.code, 1);
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
  assert.equal(result.code, 1);
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

test('bad arguments are rejected with a clear message', async () => {
  assert.equal((await runCli(['encrypt'])).code, 1);
  assert.equal((await runCli(['decrypt'])).code, 1);
  assert.equal((await runCli(['frobnicate', 'x'])).code, 1);
  assert.match((await runCli(['encrypt', 'x', '--cost', '4'])).stderr, /--cost must be an integer/);
  assert.match((await runCli(['encrypt', 'x', '--nonsense'])).stderr, /unknown option/);
  assert.match((await runCli(['encrypt', 'a', 'b'])).stderr, /exactly one file/);
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
