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
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new FormatError('chunkSize must be a positive integer');
  }
  const chunkLog2 = Math.round(Math.log2(chunkSize));
  if (2 ** chunkLog2 !== chunkSize || chunkLog2 < MIN_CHUNK_LOG2 || chunkLog2 > MAX_CHUNK_LOG2) {
    throw new FormatError(`chunkSize must be a power of two between 2^${MIN_CHUNK_LOG2} and 2^${MAX_CHUNK_LOG2}`);
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
  if (chunkLog2 < MIN_CHUNK_LOG2 || chunkLog2 > MAX_CHUNK_LOG2) {
    throw new FormatError(`chunk size 2^${chunkLog2} is outside the supported range`);
  }
  const chunkSize = 2 ** chunkLog2;

  const plaintextLength = Number(buffer.readBigUInt64BE(32));
  if (!Number.isSafeInteger(plaintextLength) || plaintextLength < 0) {
    // Guards against a header claiming a size this runtime cannot address.
    throw new FormatError('the header declares an implausible plaintext length');
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
    chunkCount: Math.max(1, Math.ceil(plaintextLength / chunkSize)),
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

/** Nonce for chunk `index`: the salt with the chunk index XORed into its tail. */
export function chunkNonce(baseNonce, index) {
  if (!Buffer.isBuffer(baseNonce) || baseNonce.length !== 12) {
    throw new FormatError('the nonce base must be 12 bytes');
  }
  if (!Number.isSafeInteger(index) || index < 0) throw new FormatError('chunk index must be >= 0');
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