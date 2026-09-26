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
}) {
  const handle = await fs.open(input, 'r');
  let out = null;
  try {
    const { size } = await handle.stat();
    const salt = crypto.randomBytes(SALT_SIZE);
    const header = buildHeader({ salt, plaintextLength: size, log2N, r, p, chunkSize });
    const key = await deriveKey(password, salt, { log2N, r, p });

    out = await fs.open(output, force ? 'w' : 'wx');
    await out.write(header);

    const chunkCount = Math.max(1, Math.ceil(size / chunkSize));
    let position = 0;

    for (let index = 0; index < chunkCount; index += 1) {
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
      await out.write(ciphertext);
      await out.write(tag);

      position += filled;
      onProgress?.({ bytes: position, total: size });
    }
    return { bytes: size, chunks: chunkCount, header };
  } finally {
    await handle.close();
    if (out) await out.close();
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
 */
export async function decryptFile({ input, output, password, chunkSize = null, force = false, onProgress = null }) {
  const handle = await fs.open(input, 'r');
  let out = null;
  try {
    const { size: containerBytes } = await handle.stat();
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

    out = await fs.open(output, force ? 'w' : 'wx');
    let position = HEADER_SIZE;
    let written = 0;

    for (let index = 0; index < header.chunkCount; index += 1) {
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
      await out.write(plaintext);
      written += plaintext.length;
      onProgress?.({ bytes: written, total: header.plaintextLength });
    }

    if (written !== header.plaintextLength) {
      throw new DecryptError('the decrypted length does not match the header');
    }
    return { bytes: written, header };
  } catch (error) {
    // A failed decryption must not leave a partial file behind.
    if (out) {
      await out.close();
      out = null;
    }
    await fs.rm(output, { force: true });
    throw error;
  } finally {
    await handle.close();
    if (out) await out.close();
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
    const { size } = await handle.stat();
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
      kdfMemoryBytes: 128 * 2 ** header.log2N * header.r,
    };  } finally {
    await handle.close();
  }
}
