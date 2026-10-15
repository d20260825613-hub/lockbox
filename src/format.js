/**
 * On-disk container format for lockbox.
 *
 *   offset  size  field
 *   0       8     magic "LBOXv1\0\0"
 *   8       1     format version (1)
 *   9       1     kdf id (1 = scrypt)
 *   10      1     log2(N)
 *   11      1     r
 *   12      1     p
 *   13      1     log2(chunk size)
 *   14      2     reserved (zero)
 *   16      16    salt == base nonce
 *   32      8     plaintext length, uint64 big-endian
 *   40      ...   chunks: ciphertext || 16-byte GCM tag
 *
 * The chunk size is stored rather than assumed: the container's total length,
 * and therefore the chunk count, depend on it. Leaving it implicit would make a
 * header unable to describe its own file.
 */

import crypto from 'node:crypto';

export const MAGIC = Buffer.from('LBOXv1\0\0', 'binary');
export const FORMAT_VERSION = 1;
export const KDF_SCRYPT = 1;

export const HEADER_SIZE = 40;
export const SALT_SIZE = 16;
export const TAG_SIZE = 16;

/** 4 MiB of plaintext per chunk. */
export const CHUNK_SIZE = 4 * 1024 * 1024;

/** Default scrypt cost: 2^16 iterations, ~64 MiB of memory, r=8, p=1. */
export const DEFAULT_LOG2_N = 16;
export const DEFAULT_R = 8;
export const DEFAULT_P = 1;

/** Refuse to create files nobody can open: scrypt needs a floor for r and p. */
export const MIN_LOG2_N = 12;
export const MAX_LOG2_N = 22;

/**
 * The largest scrypt parameters a container may carry.
 *
 * r and p are one byte each, so a header can name anything up to 255 -- and the
 * key is derived before a single tag is checked, which turns those two bytes
 * into a lever on this machine's memory. Unbounded, a 40-byte file was enough to
 * make `decrypt` allocate hundreds of gigabytes and stall for minutes before
 * reporting the same "wrong password" it would have reported at once.
 *
 * The memory ceiling is what the most expensive container this build writes
 * needs: log2(N)=22 with r=8, at 128 * N * r bytes. A header may not ask for
 * more than that, and the parameters themselves stay far below one byte's worth.
 */
export const MAX_R = 32;
export const MAX_P = 16;
export const MAX_KDF_MEMORY = 128 * 2 ** MAX_LOG2_N * DEFAULT_R;

/**
 * The most chunks one container may hold.
 *
 * A chunk nonce is the salt with a 32-bit index XORed into its tail, so index i
 * and index i + 2^32 would share a nonce -- and a repeated GCM nonce leaks the
 * keystream and eventually the authentication key. Refusing a header that needs
 * more than 2^32 - 1 chunks is what keeps the nonce space large enough for every
 * container this build will open; the parameter is not written down anywhere
 * else, so the limit lives beside the calculation.
 */
export const MAX_CHUNK_COUNT = 2 ** 32 - 1;

/** Memory one scrypt call asks for: 128 * N * r bytes, independent of p. */
export function kdfMemoryBytes(log2N, r) {
  return 128 * 2 ** log2N * r;
}

/** Chunk size lives in one header byte as its base-2 logarithm. */
export const MIN_CHUNK_LOG2 = 8; // 256 B
export const MAX_CHUNK_LOG2 = 32; // 4 GiB
export const DEFAULT_CHUNK_LOG2 = 22; // 4 MiB, matching CHUNK_SIZE

export const KDF_IDS = new Map([[KDF_SCRYPT, 'scrypt']]);

/** Thrown for malformed input. Never for a wrong password or a bad tag. */
export class FormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FormatError';
  }
}

/**
 * @param {object} options
 * @param {Buffer} options.salt 16 random bytes; doubles as the nonce base
 * @param {number} options.plaintextLength
 * @param {number} [options.log2N]
 * @param {number} [options.r]
 * @param {number} [options.p]
 * @param {number} [options.chunkSize] must be the size the writer actually uses
 * @returns {Buffer} the 40-byte header
 */
export function buildHeader({
  salt,
  plaintextLength,
  log2N = DEFAULT_LOG2_N,
  r = DEFAULT_R,
  p = DEFAULT_P,
  chunkSize = CHUNK_SIZE,
}) {
  if (!Buffer.isBuffer(salt) || salt.length !== SALT_SIZE) {
    throw new FormatError(`salt must be ${SALT_SIZE} bytes`);
  }
  if (!Number.isSafeInteger(plaintextLength) || plaintextLength < 0) {
    throw new FormatError('plaintextLength must be a non-negative safe integer');
  }
  if (!Number.isInteger(log2N) || log2N < MIN_LOG2_N || log2N > MAX_LOG2_N) {
    throw new FormatError(`log2(N) must be between ${MIN_LOG2_N} and ${MAX_LOG2_N}`);
  }
  // The read side refuses these, so the write side has to as well: writing a
  // container this build will then reject produces a file that can never be
  // opened, and the whole point of validating here is that it never exists.
  // Checking r and p by hand also keeps the range error from `writeUInt8` -- a
  // bare `RangeError` for r=256 -- from escaping to the caller.
  if (!Number.isInteger(r) || r < 1 || r > MAX_R) {
    throw new FormatError(`r must be an integer between 1 and ${MAX_R}`);
  }
  if (!Number.isInteger(p) || p < 1 || p > MAX_P) {
    throw new FormatError(`p must be an integer between 1 and ${MAX_P}`);
  }
  if (kdfMemoryBytes(log2N, r) > MAX_KDF_MEMORY) {
    throw new FormatError(`log2(N)=${log2N} with r=${r} would need more memory than this build allows`);
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new FormatError('chunkSize must be a positive integer');
  }
  const chunkLog2 = Math.round(Math.log2(chunkSize));
  if (2 ** chunkLog2 !== chunkSize || chunkLog2 < MIN_CHUNK_LOG2 || chunkLog2 > MAX_CHUNK_LOG2) {
    throw new FormatError(`chunkSize must be a power of two between 2^${MIN_CHUNK_LOG2} and 2^${MAX_CHUNK_LOG2}`);
  }
  const chunkCount = Math.max(1, Math.ceil(plaintextLength / chunkSize));
  if (chunkCount > MAX_CHUNK_COUNT) {
    throw new FormatError(
      `a plaintext of ${plaintextLength} bytes in ${chunkSize}-byte chunks needs ${chunkCount} chunks, more than the ${MAX_CHUNK_COUNT} the format carries`,
    );
  }

  const header = Buffer.alloc(HEADER_SIZE);
  MAGIC.copy(header, 0);
  header.writeUInt8(FORMAT_VERSION, 8);
  header.writeUInt8(KDF_SCRYPT, 9);
  header.writeUInt8(log2N, 10);
  header.writeUInt8(r, 11);
  header.writeUInt8(p, 12);
  header.writeUInt8(chunkLog2, 13);
  salt.copy(header, 16);
  header.writeBigUInt64BE(BigInt(plaintextLength), 32);
  return header;
}

/**
 * Parse and validate a header. Does not verify the password or any tag.
 *
 * @param {Buffer} buffer at least HEADER_SIZE bytes
 * @returns {{version:number, kdf:string, kdfId:number, log2N:number, r:number, p:number, salt:Buffer, plaintextLength:number, chunkCount:number}}
 */
export function parseHeader(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < HEADER_SIZE) {
    throw new FormatError(`not a lockbox file: need at least ${HEADER_SIZE} bytes`);
  }
  if (!buffer.subarray(0, 8).equals(MAGIC)) {
    throw new FormatError('not a lockbox file: bad magic bytes');
  }
  const version = buffer.readUInt8(8);
  if (version !== FORMAT_VERSION) {
    throw new FormatError(
      `unsupported format version ${version}; this build reads version ${FORMAT_VERSION}`,
    );
  }
  const kdfId = buffer.readUInt8(9);
  const kdf = KDF_IDS.get(kdfId);
  if (!kdf) throw new FormatError(`unsupported key derivation id ${kdfId}`);

  const log2N = buffer.readUInt8(10);
  const r = buffer.readUInt8(11);
  const p = buffer.readUInt8(12);
  const chunkLog2 = buffer.readUInt8(13);
  if (log2N < MIN_LOG2_N || log2N > MAX_LOG2_N) {
    throw new FormatError(`log2(N)=${log2N} is outside the supported range ${MIN_LOG2_N}..${MAX_LOG2_N}`);
  }
  if (r < 1 || p < 1) throw new FormatError('invalid scrypt parameters');
  if (r > MAX_R || p > MAX_P) {
    throw new FormatError(
      `scrypt r=${r} and p=${p} are outside the range this build supports (at most r=${MAX_R}, p=${MAX_P})`,
    );
  }
  if (kdfMemoryBytes(log2N, r) > MAX_KDF_MEMORY) {
    throw new FormatError(
      `scrypt log2(N)=${log2N} with r=${r} asks for more memory than this build allows`,
    );
  }
  if (chunkLog2 < MIN_CHUNK_LOG2 || chunkLog2 > MAX_CHUNK_LOG2) {
    throw new FormatError(`chunk size 2^${chunkLog2} is outside the supported range`);
  }
  const chunkSize = 2 ** chunkLog2;

  const plaintextLength = Number(buffer.readBigUInt64BE(32));
  if (!Number.isSafeInteger(plaintextLength) || plaintextLength < 0) {
    // Guards against a header claiming a size this runtime cannot address.
    throw new FormatError('the header declares an implausible plaintext length');
  }

  const chunkCount = Math.max(1, Math.ceil(plaintextLength / chunkSize));
  if (chunkCount > MAX_CHUNK_COUNT) {
    // Two chunks this far apart would share a nonce; see MAX_CHUNK_COUNT.
    throw new FormatError(
      `the header describes ${chunkCount} chunks, more than the ${MAX_CHUNK_COUNT} the format carries`,
    );
  }

  return {
    version,
    kdf,
    kdfId,
    log2N,
    r,
    p,
    chunkSize,
    salt: Buffer.from(buffer.subarray(16, 32)),
    plaintextLength,
    chunkCount,
  };
}

/**
 * Additional authenticated data for one chunk (41 bytes).
 *
 * Binding the header digest, the chunk index and a final-chunk marker means an
 * attacker cannot alter a KDF parameter, reorder chunks or cut the file short:
 * each of those changes the tag input, so decryption fails loudly instead of
 * returning wrong plaintext. The header is hashed rather than copied so the AAD
 * stays small no matter how many chunks a file has.
 */
export function chunkAad(header, index, isFinal) {
  const aad = Buffer.alloc(41);
  crypto.createHash('sha256').update(header).digest().copy(aad, 0);
  aad.writeBigUInt64BE(BigInt(index), 32);
  aad.writeUInt8(isFinal ? 1 : 0, 40);
  return aad;
}

/**
 * Nonce for chunk `index`: the salt with the chunk index XORed into its tail.
 *
 * The tail is 32 bits wide, which is exactly what the index may be, so an index
 * that does not fit is refused instead of being truncated into another chunk's
 * nonce: `chunkNonce(base, 0)` and `chunkNonce(base, 2**32)` used to be the same
 * twelve bytes, and two chunks encrypted under one nonce share a GCM keystream
 * and eventually the authentication key. Headers with that many chunks are
 * rejected by `parseHeader`, so no container can reach this.
 */
export function chunkNonce(baseNonce, index) {
  if (!Buffer.isBuffer(baseNonce) || baseNonce.length !== 12) {
    throw new FormatError('the nonce base must be 12 bytes');
  }
  if (!Number.isSafeInteger(index) || index < 0 || index > MAX_CHUNK_COUNT) {
    throw new FormatError(`chunk index must be between 0 and ${MAX_CHUNK_COUNT}`);
  }
  const nonce = Buffer.from(baseNonce);
  // `^` yields a signed 32-bit value; >>> 0 puts it back in unsigned range or
  // writeUInt32BE rejects a legitimately high index.
  nonce.writeUInt32BE((nonce.readUInt32BE(8) ^ index) >>> 0, 8);
  return nonce;
}

/** Total bytes a container of `plaintextLength` bytes will occupy. */
export function containerSize(plaintextLength, chunkSize = CHUNK_SIZE) {
  const chunks = Math.max(1, Math.ceil(plaintextLength / chunkSize));
  return HEADER_SIZE + plaintextLength + chunks * TAG_SIZE;
}