/**
 * Programmatic API.
 *
 * The same functions the CLI uses, so a script can encrypt a directory or
 * batch of files without shelling out.
 */

export { DecryptError, decryptFile, deriveKey, encryptFile, inspectFile } from './crypto.js';
export {
  CHUNK_SIZE,
  DEFAULT_LOG2_N,
  DEFAULT_P,
  DEFAULT_R,
  FormatError,
  HEADER_SIZE,
  MAX_LOG2_N,
  MIN_LOG2_N,
  SALT_SIZE,
  TAG_SIZE,
  containerSize,
  parseHeader,
} from './format.js';
export { PasswordError, readPassword } from './password.js';
export { formatBytes, formatBytesLong } from './util.js';
