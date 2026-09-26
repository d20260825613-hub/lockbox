import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { DecryptError, decryptFile, deriveKey, encryptFile, inspectFile } from '../src/crypto.js';
import {
  CHUNK_SIZE,
  FormatError,
  HEADER_SIZE,
  buildHeader,
  chunkAad,
  chunkNonce,
  containerSize,
  parseHeader,
} from '../src/format.js';
import { bytes, makeTempDir, sha256, writeFixture } from './helpers.js';

const PASSWORD = 'correct horse battery staple';
// A 1 KiB chunk keeps the multi-chunk paths fast to exercise.
const CHUNK = 1024;

async function roundTrip(content, { chunkSize = CHUNK, password = PASSWORD, name = 'sample.bin' } = {}) {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, name, content);
  const container = path.join(dir, `${name}.locked`);
  const restored = path.join(dir, `${name}.out`);
  await encryptFile({ input, output: container, password, chunkSize, log2N: 12 });
  await decryptFile({ input: container, output: restored, password, chunkSize });
  return { dir, input, container, restored };
}

test('round trip preserves every byte, for sizes around a chunk boundary', async () => {
  const sizes = [0, 1, 2, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK * 3, CHUNK * 3 + 7];
  for (const size of sizes) {
    const content = bytes(size, size + 1);
    const { restored } = await roundTrip(content);
    const result = await fs.readFile(restored);
    assert.equal(result.length, size, `size ${size} came back as ${result.length}`);
    assert.equal(sha256(result), sha256(content), `content changed for size ${size}`);
  }
});

test('an empty file round trips and produces a valid container', async () => {
  const { container } = await roundTrip(Buffer.alloc(0));
  const info = await inspectFile(container);
  assert.equal(info.plaintextLength, 0);
  assert.equal(info.chunkCount, 1);
  assert.equal(info.containerBytes, containerSize(0));
});

test('the container size matches what the format predicts', async () => {
  for (const size of [0, 10, CHUNK, CHUNK * 2 + 5]) {
    const dir = await makeTempDir();
    const input = await writeFixture(dir, 'f.bin', bytes(size, 3));
    const container = path.join(dir, 'f.locked');
    await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });
    const stat = await fs.stat(container);
    assert.equal(stat.size, containerSize(size, CHUNK), `wrong container size for ${size} plaintext bytes`);
  }
});

test('the same password and file produce different containers each time', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(2048, 9));
  const first = path.join(dir, 'a.locked');
  const second = path.join(dir, 'b.locked');
  await encryptFile({ input, output: first, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });
  await encryptFile({ input, output: second, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });
  assert.notEqual(sha256(await fs.readFile(first)), sha256(await fs.readFile(second)), 'salts or nonces repeat');
});

test('a wrong password fails cleanly and leaves no output file', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(4096, 4));
  const container = path.join(dir, 'f.locked');
  const output = path.join(dir, 'out.bin');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });

  await assert.rejects(
    () => decryptFile({ input: container, output, password: 'not the password', chunkSize: CHUNK }),
    (error) => error instanceof DecryptError && /wrong password|modified/i.test(error.message),
  );
  await assert.rejects(() => fs.access(output), 'a partial output file was left behind');
});

test('a single flipped ciphertext byte is detected', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(3000, 5));
  const container = path.join(dir, 'f.locked');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });

  const data = await fs.readFile(container);
  data[HEADER_SIZE + 10] ^= 0x01;
  await fs.writeFile(container, data);

  await assert.rejects(
    () => decryptFile({ input: container, output: path.join(dir, 'out.bin'), password: PASSWORD, chunkSize: CHUNK }),
    DecryptError,
  );
});

test('editing the header breaks authentication instead of changing behaviour', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(2048, 6));
  const container = path.join(dir, 'f.locked');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });

  const data = await fs.readFile(container);
  data[32] ^= 0xff; // a byte of the recorded plaintext length
  await fs.writeFile(container, data);

  await assert.rejects(
    () => decryptFile({ input: container, output: path.join(dir, 'o.bin'), password: PASSWORD, chunkSize: CHUNK }),
    (error) => error instanceof FormatError || error instanceof DecryptError,
  );
});

test('a truncated container is rejected before any decryption', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(4096, 7));
  const container = path.join(dir, 'f.locked');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });

  const data = await fs.readFile(container);
  await fs.writeFile(container, data.subarray(0, data.length - 100));

  await assert.rejects(
    () => decryptFile({ input: container, output: path.join(dir, 'o.bin'), password: PASSWORD, chunkSize: CHUNK }),
    (error) => error instanceof FormatError && /truncated|extra data/i.test(error.message),
  );
});

test('dropping a whole chunk is detected (no silent truncation)', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(CHUNK * 3, 8));
  const container = path.join(dir, 'f.locked');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });

  const data = await fs.readFile(container);
  // Remove the middle chunk, keeping the header and the last chunk intact.
  const stripped = Buffer.concat([
    data.subarray(0, HEADER_SIZE + CHUNK + 16),
    data.subarray(HEADER_SIZE + 2 * (CHUNK + 16)),
  ]);
  await fs.writeFile(container, stripped);

  await assert.rejects(
    () => decryptFile({ input: container, output: path.join(dir, 'o.bin'), password: PASSWORD, chunkSize: CHUNK }),
    (error) => error instanceof FormatError || error instanceof DecryptError,
  );
});

test('swapping two chunks is detected (order is authenticated)', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(CHUNK * 3, 11));
  const container = path.join(dir, 'f.locked');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });

  const data = await fs.readFile(container);
  const body = data.subarray(HEADER_SIZE);
  const size = CHUNK + 16;
  const swapped = Buffer.concat([body.subarray(size, size * 2), body.subarray(0, size), body.subarray(size * 2)]);
  await fs.writeFile(container, Buffer.concat([data.subarray(0, HEADER_SIZE), swapped]));

  await assert.rejects(
    () => decryptFile({ input: container, output: path.join(dir, 'o.bin'), password: PASSWORD, chunkSize: CHUNK }),
    DecryptError,
  );
});

test('a non-lockbox file is rejected as a format error, not a password error', async () => {
  const dir = await makeTempDir();
  // Long enough to hold a header, so the failure is the magic bytes and not
  // the length check that runs first.
  const input = await writeFixture(dir, 'plain.bin', Buffer.alloc(4096, 0x41));
  await assert.rejects(() => inspectFile(input), (error) => error instanceof FormatError && /magic/i.test(error.message));

  const short = await writeFixture(dir, 'short.bin', Buffer.from('tiny'));
  await assert.rejects(() => inspectFile(short), (error) => error instanceof FormatError && /too short/i.test(error.message));
});

test('deriveKey is deterministic, length-correct and password sensitive', async () => {
  const salt = Buffer.alloc(16, 7);
  const a = await deriveKey(PASSWORD, salt, { log2N: 12 });
  const b = await deriveKey(PASSWORD, salt, { log2N: 12 });
  const c = await deriveKey(`${PASSWORD}x`, salt, { log2N: 12 });
  const d = await deriveKey(PASSWORD, Buffer.alloc(16, 8), { log2N: 12 });
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
  assert.notDeepEqual(a, d);
});

test('scrypt parameters from the header are the ones used', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(64, 12));
  const container = path.join(dir, 'f.locked');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 13, r: 8, p: 1 });
  const info = await inspectFile(container);
  assert.equal(info.log2N, 13);
  assert.equal(info.r, 8);
  assert.equal(info.p, 1);
  await decryptFile({ input: container, output: path.join(dir, 'out.bin'), password: PASSWORD, chunkSize: CHUNK });
  assert.equal(sha256(await fs.readFile(path.join(dir, 'out.bin'))), sha256(bytes(64, 12)));
});

test('header helpers reject nonsense instead of writing a broken file', () => {
  assert.throws(() => buildHeader({ salt: Buffer.alloc(4), plaintextLength: 0 }), FormatError);
  assert.throws(() => buildHeader({ salt: Buffer.alloc(16), plaintextLength: -1 }), FormatError);
  assert.throws(() => buildHeader({ salt: Buffer.alloc(16), plaintextLength: 0, log2N: 4 }), FormatError);
  assert.throws(() => buildHeader({ salt: Buffer.alloc(16), plaintextLength: 0, log2N: 40 }), FormatError);
});

test('parseHeader refuses short, wrong-magic and future-version input', () => {
  assert.throws(() => parseHeader(Buffer.alloc(10)), FormatError);
  assert.throws(() => parseHeader(Buffer.alloc(HEADER_SIZE, 0x41)), (e) => /magic/.test(e.message));

  const header = buildHeader({ salt: Buffer.alloc(16, 1), plaintextLength: 5 });
  const future = Buffer.from(header);
  future.writeUInt8(9, 8);
  assert.throws(() => parseHeader(future), (e) => /version 9/.test(e.message));
});

test('chunk nonces differ per chunk and repeat deterministically', () => {
  const base = Buffer.alloc(12, 0xab);
  assert.notDeepEqual(chunkNonce(base, 0), chunkNonce(base, 1));
  assert.deepEqual(chunkNonce(base, 5), chunkNonce(base, 5));
  assert.equal(chunkNonce(base, 0).length, 12);
});

test('chunk AAD binds index and finality', () => {
  const header = buildHeader({ salt: Buffer.alloc(16, 2), plaintextLength: 100 });
  const a = chunkAad(header, 0, false);
  const b = chunkAad(header, 1, false);
  const c = chunkAad(header, 0, true);
  assert.equal(a.length, 41);
  assert.notDeepEqual(a, b, 'index is not covered');
  assert.notDeepEqual(a, c, 'finality is not covered');
});

test('a file whose size matches the chunk size exactly needs no empty tail chunk', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(CHUNK, 13));
  const container = path.join(dir, 'f.locked');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });
  const info = await inspectFile(container);
  assert.equal(info.chunkCount, 1, 'an exact multiple must not add an empty final chunk');
  assert.equal(info.containerBytes, containerSize(CHUNK, CHUNK));
});

export { CHUNK_SIZE };
