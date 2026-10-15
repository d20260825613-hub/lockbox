/**
 * The encryption engine. Standard library only.
 *
 * Key derivation is scrypt; encryption is AES-256-GCM, an AEAD, so decryption
 * tells you whether the data is authentic instead of handing back plausible
 * garbage. Nothing here invents a primitive: the design work is in the
 * container format (see format.js) and in writing output in a way that cannot
 * leave a half-decrypted file behind.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import process from 'node:process';

import {
  CHUNK_SIZE,
  DEFAULT_LOG2_N,
  DEFAULT_P,
  DEFAULT_R,
  FormatError,
  HEADER_SIZE,
  SALT_SIZE,
  TAG_SIZE,
  buildHeader,
  chunkAad,
  chunkNonce,
  kdfMemoryBytes,
  parseHeader,
} from './format.js';

export const KEY_BYTES = 32;
export const NONCE_BYTES = 12;

/** A wrong password and a tampered file are the same failure to the user. */
export class DecryptError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DecryptError';
  }
}

/**
 * Open the output for writing without being able to damage what is already there.
 *
 * Without `force` this is an exclusive create, which refuses to touch a file that
 * exists. With `force` the bytes go to a temporary file beside the destination
 * and are renamed over it only once they are complete, so a failure halfway
 * through leaves whatever was there exactly as it was.
 *
 * Both halves are load-bearing. The exclusive create is what makes it safe for
 * the caller to delete the output on failure -- the only file this run may
 * remove is one it created -- and the temporary file is what keeps a
 * `--force` overwrite from destroying the file it was allowed to replace until
 * the replacement is known to be good.
 *
 * @param {string} output
 * @param {boolean} force
 * @returns {Promise<{handle: import('node:fs/promises').FileHandle, temporary: string|null}>}
 */
async function openOutput(output, force) {
  try {
    if (!force) return { handle: await fs.open(output, 'wx'), temporary: null };
    // Beside the destination, so the rename stays a rename rather than a copy
    // across devices. The random part keeps two runs in one directory apart.
    const temporary = `${output}.lockbox-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`;
    return { handle: await fs.open(temporary, 'wx'), temporary };
  } catch (error) {
    // Report the path the caller asked for rather than the temporary file
    // beside it: the caller has to be able to tell a missing input from a
    // missing output directory, and only one of those paths is the one it knows.
    if (error.code === 'ENOENT') error.path = output;
    throw error;
  }
}

/**
 * Put a finished writer in place, closing it first.
 *
 * Until this runs, the previous file at the destination is untouched; after it,
 * the new file is complete and authenticated. Mutates `out` so the caller's
 * cleanup knows there is no handle and no temporary file left to remove.
 */
async function publishOutput(out, output) {
  await out.handle.close();
  out.handle = null;
  if (out.temporary) await fs.rename(out.temporary, output);
  out.temporary = null;
}

/** Close a handle without letting a close that already happened mask an error. */
function closeQuietly(handle) {
  return handle.close().catch(() => {});
}

/** Remove a file without letting a cleanup failure replace the real error. */
function removeQuietly(target) {
  if (!target) return Promise.resolve();
  return fs.rm(target, { force: true }).catch(() => {});
}

/**
 * Throw unless the path is a regular file to read.
 *
 * `fs.open` on a directory succeeds on Windows and reports a size of zero, so
 * the chunk loop had nothing to read and `encrypt` finished "successfully" with
 * a container holding an empty file while printing that the original was not
 * touched. On Linux the read fails instead, with a raw EISDIR that says nothing
 * about which argument was wrong.
 */
function requireRegularFile(stats, input) {
  if (stats.isFile()) return;
  if (stats.isDirectory()) throw new FormatError(`${input} is a directory, not a file`);
  throw new FormatError(`${input} is not a regular file`);
}

/**
 * Derive a 32-byte key from a password.
 *
 * scrypt is memory-hard, which is what makes an attacker's GPU farm less useful
 * than it would be against a plain hash. The parameters are stored in the file
 * header so a future build can still open files written today.
 */
export function deriveKey(password, salt, { log2N = DEFAULT_LOG2_N, r = DEFAULT_R, p = DEFAULT_P, keylen = KEY_BYTES } = {}) {
  if (typeof password !== 'string' && !Buffer.isBuffer(password)) {
    throw new TypeError('password must be a string or a Buffer');
  }
  const N = 2 ** log2N;
  // maxmem must be raised explicitly: Node's default refuses N=2^16 with r=8.
  const maxmem = 256 * N * r;
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, { N, r, p, maxmem }, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

/**
 * Encrypt a file.
 *
 * @param {object} options
 * @param {string} options.input
 * @param {string} options.output
 * @param {string} options.password
 * @param {number} [options.log2N]
 * @param {number} [options.r]
 * @param {number} [options.p]
 * @param {(progress: {bytes: number, total: number}) => void} [options.onProgress]
 * @param {number} [options.chunkSize]
 * @param {boolean} [options.force] allow replacing an existing output file
 * @param {AbortSignal} [options.signal] stop between chunks and clean up
 */
export async function encryptFile({
  input,
  output,
  password,
  log2N = DEFAULT_LOG2_N,
  r = DEFAULT_R,
  p = DEFAULT_P,
  chunkSize = CHUNK_SIZE,
  force = false,
  onProgress = null,
  signal = null,
}) {
  const handle = await fs.open(input, 'r');
  let out = null;
  try {
    const before = await handle.stat({ bigint: true });
    requireRegularFile(before, input);
    const size = Number(before.size);
    const salt = crypto.randomBytes(SALT_SIZE);
    const header = buildHeader({ salt, plaintextLength: size, log2N, r, p, chunkSize });
    const key = await deriveKey(password, salt, { log2N, r, p });

    out = await openOutput(output, force);
    await out.handle.write(header);

    const chunkCount = Math.max(1, Math.ceil(size / chunkSize));
    let position = 0;

    for (let index = 0; index < chunkCount; index += 1) {
      signal?.throwIfAborted();
      const wanted = Math.min(chunkSize, size - position);
      const plaintext = Buffer.allocUnsafe(Math.max(0, wanted));
      let filled = 0;
      while (filled < wanted) {
        const { bytesRead } = await handle.read(plaintext, filled, wanted - filled, position + filled);
        if (bytesRead === 0) break;
        filled += bytesRead;
      }
      const block = filled === wanted ? plaintext : plaintext.subarray(0, filled);

      const cipher = crypto.createCipheriv('aes-256-gcm', key, chunkNonce(salt.subarray(0, NONCE_BYTES), index));
      const isFinal = index === chunkCount - 1;
      cipher.setAAD(chunkAad(header, index, isFinal));
      const ciphertext = Buffer.concat([cipher.update(block), cipher.final()]);
      const tag = cipher.getAuthTag();
      await out.handle.write(ciphertext);
      await out.handle.write(tag);

      position += filled;
      onProgress?.({ bytes: position, total: size });
    }

    // The output existed while this file was being read, so the one thing that
    // must not have happened is a write to the input: on Windows `NOTES.TXT` and
    // `notes.txt` are one file, and the CLI's check compares names that only it
    // can spell. A file that changed under the reader is a container that
    // describes something that is no longer there, so it is discarded.
    const after = await handle.stat({ bigint: true });
    if (
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs
    ) {
      throw new FormatError(`${input} was modified while it was being encrypted; the output was discarded`);
    }

    await publishOutput(out, output);
    out = null; // publishOutput closed the handle and moved the temporary file
    return { bytes: size, chunks: chunkCount, header };
  } finally {
    await handle.close();
    if (out) {
      if (out.handle) await closeQuietly(out.handle);
      // With --force the destination was never opened, so only the temporary
      // file goes; otherwise the exclusive create guarantees that what is at
      // `output` is this run's own half-written container.
      await removeQuietly(out.temporary ?? output);
    }
  }
}

/**
 * Decrypt a file.
 *
 * Returns the plaintext length. Throws DecryptError for a wrong password or any
 * modification, and always removes a partial output file first so a failed run
 * cannot leave something that looks like a decrypted file.
 *
 * @param {object} options
 * @param {string} options.input
 * @param {string} options.output
 * @param {string} options.password
 * @param {(progress: {bytes: number, total: number}) => void} [options.onProgress]
 * @param {number} [options.chunkSize] override for testing; must be a power of two
 * @param {boolean} [options.force] allow replacing an existing output file
 * @param {AbortSignal} [options.signal] stop between chunks and clean up
 */
export async function decryptFile({
  input,
  output,
  password,
  chunkSize = null,
  force = false,
  onProgress = null,
  signal = null,
}) {
  const handle = await fs.open(input, 'r');
  let out = null;
  try {
    const stats = await handle.stat();
    requireRegularFile(stats, input);
    const { size: containerBytes } = stats;
    const headerBuffer = Buffer.alloc(HEADER_SIZE);
    const { bytesRead } = await handle.read(headerBuffer, 0, HEADER_SIZE, 0);
    if (bytesRead < HEADER_SIZE) throw new FormatError('the file is too short to be a lockbox container');
    const header = parseHeader(headerBuffer);

    const expected = HEADER_SIZE + header.plaintextLength + header.chunkCount * TAG_SIZE;
    if (containerBytes !== expected) {
      throw new FormatError(
        `the file is ${containerBytes} bytes but its header describes ${expected}; it is truncated or has extra data`,
      );
    }

    const key = await deriveKey(password, header.salt, { log2N: header.log2N, r: header.r, p: header.p });

    // The chunk size comes from the header, so a container written with a
    // different chunk size still opens. An override only exists for tests.
    const effectiveChunkSize = chunkSize ?? header.chunkSize;

    out = await openOutput(output, force);
    let position = HEADER_SIZE;
    let written = 0;

    for (let index = 0; index < header.chunkCount; index += 1) {
      signal?.throwIfAborted();
      const isFinal = index === header.chunkCount - 1;
      // Every non-final chunk holds a full chunk of plaintext; the last one
      // holds whatever is left.
      const cipherBytes = isFinal ? header.plaintextLength - written : effectiveChunkSize;
      if (cipherBytes < 0) throw new FormatError('the container ends in the middle of a chunk');

      const ciphertext = Buffer.allocUnsafe(cipherBytes);
      await readFully(handle, ciphertext, position);
      position += cipherBytes;

      const tag = Buffer.allocUnsafe(TAG_SIZE);
      await readFully(handle, tag, position);
      position += TAG_SIZE;

      const decipher = crypto.createDecipheriv('aes-256-gcm', key, chunkNonce(header.salt.subarray(0, NONCE_BYTES), index));
      decipher.setAAD(chunkAad(headerBuffer, index, isFinal));
      decipher.setAuthTag(tag);
      let plaintext;
      try {
        plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch {
        throw new DecryptError('wrong password, or the file has been modified');
      }
      await out.handle.write(plaintext);
      written += plaintext.length;
      onProgress?.({ bytes: written, total: header.plaintextLength });
    }

    if (written !== header.plaintextLength) {
      throw new DecryptError('the decrypted length does not match the header');
    }
    await publishOutput(out, output);
    out = null; // publishOutput closed the handle and moved the temporary file
    return { bytes: written, header };
  } finally {
    // A failed decryption must not leave a partial file behind, and it must not
    // touch one it did not create: removing the *output path* unconditionally is
    // how `decrypt bad.locked -o precious.txt --force` deleted precious.txt
    // without ever having opened it. `openOutput` decides which file that is.
    await handle.close();
    if (out) {
      if (out.handle) await closeQuietly(out.handle);
      await removeQuietly(out.temporary ?? output);
    }
  }
}

/** Read exactly `buffer.length` bytes or fail; a short read means truncation. */
async function readFully(handle, buffer, position) {
  let filled = 0;
  while (filled < buffer.length) {
    const { bytesRead } = await handle.read(buffer, filled, buffer.length - filled, position + filled);
    if (bytesRead === 0) throw new FormatError('unexpected end of file');
    filled += bytesRead;
  }
}

/**
 * Read a container's header without decrypting it.
 *
 * Useful to answer "can this build open the file, and how expensive will it be"
 * before asking for a password.
 */
export async function inspectFile(input) {
  const handle = await fs.open(input, 'r');
  try {
    const stats = await handle.stat();
    requireRegularFile(stats, input);
    const { size } = stats;
    const headerBuffer = Buffer.alloc(HEADER_SIZE);
    const { bytesRead } = await handle.read(headerBuffer, 0, HEADER_SIZE, 0);
    if (bytesRead < HEADER_SIZE) throw new FormatError('the file is too short to be a lockbox container');
    const header = parseHeader(headerBuffer);
    const expected = HEADER_SIZE + header.plaintextLength + header.chunkCount * TAG_SIZE;
    return {
      ...header,
      containerBytes: size,
      expectedBytes: expected,
      truncated: size < expected,
      extraData: size > expected,
      kdfMemoryBytes: kdfMemoryBytes(header.log2N, header.r),
    };
  } finally {
    await handle.close();
  }
}
