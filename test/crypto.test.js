import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { DecryptError, decryptFile, deriveKey, encryptFile, inspectFile } from '../src/crypto.js';
import {
  CHUNK_SIZE,
  FormatError,
  HEADER_SIZE,
  MAX_KDF_MEMORY,
  MAX_R,
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

test('buildHeader refuses the scrypt parameters parseHeader would refuse', () => {
  // The two sides used to disagree: the reader demanded r>=1 and p>=1, the
  // writer checked neither, so `encryptFile({ r: 0 })` happily wrote a container
  // that this same build could never open -- the file was simply lost. One byte
  // each also meant an out-of-range value escaped as a bare `RangeError` from
  // `writeUInt8` rather than as a format error.
  const salt = Buffer.alloc(16, 1);
  for (const parameters of [{ r: 0 }, { p: 0 }, { r: 256 }, { p: 256 }, { r: -1 }, { r: MAX_R + 1 }]) {
    assert.throws(
      () => buildHeader({ salt, plaintextLength: 0, ...parameters }),
      (error) => error instanceof FormatError,
      `${JSON.stringify(parameters)} was accepted by the writer`,
    );
  }

  // The container the reader accepts must be the container the writer writes,
  // and vice versa: what is written has to parse back as the same parameters.
  const header = parseHeader(buildHeader({ salt, plaintextLength: 0, log2N: 12, r: 8, p: 1 }));
  assert.equal(header.r, 8);
  assert.equal(header.p, 1);
});

test('an API write with parameters nobody can read fails before it writes anything', async () => {
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(64, 31));
  const output = path.join(dir, 'f.locked');

  await assert.rejects(
    () => encryptFile({ input, output, password: PASSWORD, r: 0, log2N: 12 }),
    FormatError,
  );
  await assert.rejects(() => fs.access(output), 'a container nobody can open was left on disk');
});

test('parseHeader refuses a header that asks for more scrypt work than this build allows', () => {
  const salt = Buffer.alloc(16, 3);
  // A 40-byte file used to be enough to make `decrypt` allocate hundreds of
  // gigabytes: r and p are one byte each and the key is derived before any tag
  // is checked, so the header alone decided how much work this machine did.
  const bytes255 = buildHeader({ salt, plaintextLength: 0, log2N: 12, r: MAX_R, p: 16 });
  const greedy = Buffer.from(bytes255);
  greedy.writeUInt8(255, 11);
  greedy.writeUInt8(255, 12);
  assert.throws(() => parseHeader(greedy), (error) => error instanceof FormatError && /r=255/.test(error.message));

  // Each parameter is in range here; it is their product that is not.
  const overspend = Buffer.from(bytes255);
  overspend.writeUInt8(22, 10);
  overspend.writeUInt8(32, 11);
  assert.throws(
    () => parseHeader(overspend),
    (error) => error instanceof FormatError && /memory/.test(error.message),
  );

  // The most expensive header this build can write must still be readable, or
  // containers written with --cost 22 would stop opening.
  const allowed = parseHeader(buildHeader({ salt, plaintextLength: 0, log2N: 22, r: 8, p: 1 }));
  assert.equal(128 * 2 ** allowed.log2N * allowed.r, MAX_KDF_MEMORY);
});

test('a chunk index that does not fit the nonce is refused instead of repeated', () => {
  const base = Buffer.alloc(12, 0xab);
  // The nonce is the salt with the index XORed into its last four bytes, so the
  // index has to fit in 32 bits: 0 and 2**32 used to produce the same nonce, and
  // one AES-GCM nonce used twice under one key is a break, not a collision.
  assert.throws(() => chunkNonce(base, 2 ** 32), FormatError);
  assert.throws(() => chunkNonce(base, 2 ** 32 + 5), FormatError);
  assert.notDeepEqual(chunkNonce(base, 2 ** 32 - 1), chunkNonce(base, 0));
});

test('a header describing more chunks than the nonce can carry is refused', () => {
  const salt = Buffer.alloc(16, 4);
  // 256-byte chunks and a plaintext 2^32 chunks long. No such file can be built
  // by this code, so the header is assembled by hand and inflated -- which is
  // exactly what a hostile one looks like.
  const plaintextLength = 2 ** 32 * 256;
  const header = buildHeader({ salt, plaintextLength: 0, log2N: 12, chunkSize: 256 });
  header.writeUInt8(8, 13);
  header.writeBigUInt64BE(BigInt(plaintextLength), 32);
  assert.throws(
    () => parseHeader(header),
    (error) => error instanceof FormatError && /chunks/.test(error.message),
  );
  assert.throws(
    () => buildHeader({ salt, plaintextLength, log2N: 12, chunkSize: 256 }),
    FormatError,
    'the writer must not create what the reader refuses',
  );
});

test('a directory is refused as input instead of being encrypted as an empty file', async () => {
  // On Windows `fs.open` on a directory succeeds and reports a size of zero, so
  // the chunk loop had nothing to read and the run finished "successfully" with
  // a container holding an empty file -- and printed that the original was not
  // touched. On other systems the read fails with a raw EISDIR instead.
  const dir = await makeTempDir();
  const nested = path.join(dir, 'proj');
  await fs.mkdir(nested);
  await writeFixture(nested, 'secret.txt', bytes(200, 32));

  await assert.rejects(() => inspectFile(nested), (error) => error instanceof FormatError && /directory/.test(error.message));
  await assert.rejects(
    () => decryptFile({ input: nested, output: path.join(dir, 'out.bin'), password: PASSWORD }),
    (error) => error instanceof FormatError && /directory/.test(error.message),
  );
  await assert.rejects(
    () => encryptFile({ input: nested, output: path.join(dir, 'proj.locked'), password: PASSWORD, log2N: 12 }),
    (error) => error instanceof FormatError && /directory/.test(error.message),
  );
  await assert.rejects(() => fs.access(path.join(dir, 'proj.locked')), 'the directory became a container');
});

test('a failed write leaves a file it was allowed to replace exactly as it was', async () => {
  // `--force` means "you may replace this", not "destroy it even if the
  // replacement never happens". The output used to be opened with the truncating
  // flag and then removed by the cleanup, so an input that could not even be
  // read cost the user the file that was already at the output path.
  const dir = await makeTempDir();
  const precious = await writeFixture(dir, 'precious.txt', 'IRREPLACEABLE USER DATA');
  const bad = await writeFixture(dir, 'bad.locked', Buffer.alloc(4096, 0x41));
  const input = await writeFixture(dir, 'in.bin', bytes(500, 33));
  const container = path.join(dir, 'in.locked');

  await assert.rejects(
    () => decryptFile({ input: bad, output: precious, password: PASSWORD, force: true }),
    FormatError,
  );
  assert.equal(String(await fs.readFile(precious)), 'IRREPLACEABLE USER DATA', 'an existing file was destroyed');

  // The same on the encrypt side, and this time the failure comes after the
  // output was already opened: a chunk size the writer cannot honour.
  await assert.rejects(
    () => encryptFile({ input, output: precious, password: PASSWORD, force: true, chunkSize: 1000, log2N: 12 }),
    FormatError,
  );
  assert.equal(String(await fs.readFile(precious)), 'IRREPLACEABLE USER DATA', 'an existing file was destroyed');

  // And a wrong password over an existing file: the file stays, untouched.
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });
  await assert.rejects(
    () => decryptFile({ input: container, output: precious, password: 'not the password', force: true }),
    DecryptError,
  );
  assert.equal(String(await fs.readFile(precious)), 'IRREPLACEABLE USER DATA', 'an existing file was destroyed');

  // Nothing temporary is left lying around either.
  const leftovers = (await fs.readdir(dir)).filter((name) => name.includes('.tmp'));
  assert.deepEqual(leftovers, []);
});

test('an abort removes the partial output instead of leaving it behind', async () => {
  // Ctrl-C used to exit the process on the spot, skipping the cleanup, so the
  // half-decrypted file stayed on disk while the message said it had not. The
  // abort below is the same path the signal handler now takes.
  const dir = await makeTempDir();
  const input = await writeFixture(dir, 'f.bin', bytes(CHUNK * 3, 34));
  const container = path.join(dir, 'f.locked');
  const output = path.join(dir, 'out.bin');
  await encryptFile({ input, output: container, password: PASSWORD, chunkSize: CHUNK, log2N: 12 });

  const controller = new AbortController();
  await assert.rejects(
    () =>
      decryptFile({
        input: container,
        output,
        password: PASSWORD,
        signal: controller.signal,
        onProgress: () => {
          if (!controller.signal.aborted) controller.abort();
        },
      }),
    (error) => error.name === 'AbortError',
  );
  await assert.rejects(() => fs.access(output), 'a partial output survived the interruption');
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
