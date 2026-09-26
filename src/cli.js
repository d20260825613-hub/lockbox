#!/usr/bin/env node
/**
 * lockbox - encrypt and decrypt files with a password.
 *
 * Three commands, and only three:
 *   encrypt   password -> a .locked container
 *   decrypt   a .locked container -> the original bytes
 *   inspect   read the header without a password
 *
 * Two rules the whole design follows:
 *   - nothing is ever overwritten unless --force is given, so a mistake cannot
 *     destroy the only copy of a file
 *   - a failed decryption deletes its partial output instead of leaving a file
 *     that looks like it worked
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import { DecryptError, decryptFile, encryptFile, inspectFile } from './crypto.js';
import { DEFAULT_LOG2_N, MAX_LOG2_N, MIN_LOG2_N, FormatError } from './format.js';
import { readPassword } from './password.js';
import { formatBytes, formatBytesLong } from './util.js';

const VERSION = '0.1.0';
const SUFFIX = '.locked';

const USAGE = `lockbox - encrypt a file with a password

Usage
  lockbox encrypt <file>            write <file>.locked, leave the original alone
  lockbox decrypt <file.locked>     write the original bytes back
  lockbox inspect <file.locked>     read the header without a password

Options
  -o, --out <file>       write here instead of the default name
  -f, --force            allow overwriting an existing output file
      --cost <n>         scrypt log2(N), ${MIN_LOG2_N}..${MAX_LOG2_N} (default ${DEFAULT_LOG2_N}, about 64 MiB)
      --password-env <VAR>  read the password from an environment variable
      --password-file <file>  read the first line of a file as the password
      --no-progress      do not print progress
  -h, --help             this text
  -v, --version          version

What this does and does not promise
  Uses scrypt for the key and AES-256-GCM for the data, both from Node's own
  crypto module. AES-GCM is authenticated, so a wrong password or an edited file
  is reported as an error rather than producing corrupt output.
  The container format is specific to this tool and has not been audited by
  anyone. There is no password recovery. If you lose the password, the file is
  gone. Keep a backup of anything you encrypt.

Examples
  lockbox encrypt notes.txt
  lockbox decrypt notes.txt.locked -o notes-copy.txt
  lockbox inspect notes.txt.locked
`;

function fail(message) {
  process.stderr.write(`lockbox: ${message}\n`);
  return 1;
}

function parseArgs(argv) {
  const values = { out: null, force: false, cost: DEFAULT_LOG2_N, passwordEnv: null, passwordFile: null, progress: true };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (token === '-f' || token === '--force') values.force = true;
    else if (token === '--no-progress') values.progress = false;
    else if (token === '-o' || token === '--out') values.out = argv[++i];
    else if (token.startsWith('--out=')) values.out = token.slice(6);
    else if (token === '--cost') values.cost = Number(argv[++i]);
    else if (token.startsWith('--cost=')) values.cost = Number(token.slice(7));
    else if (token === '--password-env') values.passwordEnv = argv[++i];
    else if (token.startsWith('--password-env=')) values.passwordEnv = token.slice(15);
    else if (token === '--password-file') values.passwordFile = argv[++i];
    else if (token.startsWith('--password-file=')) values.passwordFile = token.slice(16);
    else if (token.startsWith('-') && token !== '-') return { error: `unknown option: ${token}` };
    else positional.push(token);
  }
  if (!Number.isInteger(values.cost) || values.cost < MIN_LOG2_N || values.cost > MAX_LOG2_N) {
    return { error: `--cost must be an integer between ${MIN_LOG2_N} and ${MAX_LOG2_N}` };
  }
  return { values, positional };
}

/** Default output name, and the guard against clobbering something. */
async function resolveOutput({ input, out, force, decrypting }) {
  let target = out;
  if (!target) {
    target = decrypting
      ? input.endsWith(SUFFIX)
        ? input.slice(0, -SUFFIX.length)
        : `${input}.unlocked`
      : `${input}${SUFFIX}`;
  }
  const absolute = path.resolve(target);
  if (absolute === path.resolve(input)) {
    throw new Error('input and output are the same file');
  }
  if (!force) {
    try {
      await fs.access(absolute);
      throw new Error(`${target} already exists; pass --force to overwrite it`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return target;
}

function progressReporter(enabled, label) {
  if (!enabled || !process.stderr.isTTY) return null;
  let last = 0;
  return ({ bytes, total }) => {
    const now = Date.now();
    if (now - last < 120 && bytes < total) return;
    last = now;
    const percent = total === 0 ? 100 : Math.floor((bytes / total) * 100);
    process.stderr.write(`\r${label}: ${percent}% (${formatBytes(bytes)} / ${formatBytes(total)})   `);
  };
}

async function commandEncrypt(argv) {
  const parsed = parseArgs(argv);
  if (parsed.error) return fail(parsed.error);
  const { values, positional } = parsed;
  const input = positional[0];
  if (!input) return fail('encrypt needs a file to encrypt');
  if (positional.length > 1) return fail('encrypt takes exactly one file');

  let output;
  try {
    output = await resolveOutput({ input, out: values.out, force: values.force, decrypting: false });
  } catch (error) {
    return fail(error.message);
  }

  // A password from the environment or a file is used as given: confirmation
  // only makes sense for something a human just typed. Password problems are
  // reported like any other user error — a stack trace here would be noise.
  let password;
  try {
    password = await readPassword(values, { confirm: true });
  } catch (error) {
    return fail(error?.message ?? String(error));
  }

  try {
    await encryptFile({
      input,
      output,
      password,
      log2N: values.cost,
      force: values.force,
      onProgress: progressReporter(values.progress, 'encrypting'),
    });
  } catch (error) {
    // Never leave a half-written container behind, whatever went wrong.
    await fs.rm(output, { force: true });
    if (error.code === 'ENOENT') return fail(`no such file: ${input}`);
    return fail(error.message);
  }

  const info = await inspectFile(output);
  if (values.progress && process.stderr.isTTY) process.stderr.write('\r\u001b[K');
  process.stdout.write(
    `${input} -> ${output}\n` +
      `  ${formatBytesLong(info.plaintextLength)} of data, ${info.chunkCount} chunk(s)\n` +
      `  scrypt log2(N)=${info.log2N}, about ${formatBytes(info.kdfMemoryBytes)} of memory per attempt\n` +
      `  the original file was not touched\n`,
  );
  return 0;
}

async function commandDecrypt(argv) {
  const parsed = parseArgs(argv);
  if (parsed.error) return fail(parsed.error);
  const { values, positional } = parsed;
  const input = positional[0];
  if (!input) return fail('decrypt needs a .locked file');
  if (positional.length > 1) return fail('decrypt takes exactly one file');

  let output;
  try {
    output = await resolveOutput({ input, out: values.out, force: values.force, decrypting: true });
  } catch (error) {
    return fail(error.message);
  }

  let password;
  try {
    password = await readPassword(values);
  } catch (error) {
    return fail(error?.message ?? String(error));
  }
  try {
    const result = await decryptFile({
      input,
      output,
      password,
      force: values.force,
      onProgress: progressReporter(values.progress, 'decrypting'),
    });
    if (values.progress && process.stderr.isTTY) process.stderr.write('\r\u001b[K');
    process.stdout.write(`${input} -> ${output}\n  ${formatBytesLong(result.bytes)} restored\n`);
    return 0;
  } catch (error) {
    if (values.progress && process.stderr.isTTY) process.stderr.write('\r\u001b[K');
    if (error instanceof DecryptError) {
      return fail(`${error.message}\n  the partial output was deleted; nothing was written`);
    }
    if (error instanceof FormatError) return fail(error.message);
    if (error.code === 'ENOENT') return fail(`no such file: ${input}`);
    return fail(error.message);
  }
}

async function commandInspect(argv) {
  const parsed = parseArgs(argv);
  if (parsed.error) return fail(parsed.error);
  const input = parsed.positional[0];
  if (!input) return fail('inspect needs a .locked file');

  try {
    const info = await inspectFile(input);
    process.stdout.write(
      `${input}\n` +
        `  format          lockbox v${info.version}\n` +
        `  key derivation  ${info.kdf}, log2(N)=${info.log2N}, r=${info.r}, p=${info.p}\n` +
        `  memory cost     about ${formatBytes(info.kdfMemoryBytes)} per attempt\n` +
        `  plaintext       ${formatBytesLong(info.plaintextLength)}\n` +
        `  chunks          ${info.chunkCount}\n` +
        `  container       ${formatBytesLong(info.containerBytes)}` +
        `${info.truncated ? '  TRUNCATED' : info.extraData ? '  EXTRA DATA APPENDED' : '  (matches the header)'}\n`,
    );
    return info.truncated || info.extraData ? 2 : 0;
  } catch (error) {
    return fail(error.message);
  }
}

async function main() {
  return run(process.argv.slice(2));
}

/**
 * Run the CLI and resolve to an exit code.
 *
 * Split out from `main` so tests can drive it in-process without spawning a
 * child, and so the bin entry stays a one-liner.
 *
 * @param {string[]} argv arguments after the script name
 */
export async function run(argv) {
  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help' || argv[0] === 'help') {
    process.stdout.write(USAGE);
    return 0;
  }
  if (argv[0] === '-v' || argv[0] === '--version') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  const [command, ...rest] = argv;
  switch (command) {
    case 'encrypt':
      return commandEncrypt(rest);
    case 'decrypt':
      return commandDecrypt(rest);
    case 'inspect':
      return commandInspect(rest);
    default:
      return fail(`unknown command: ${command}. Try "lockbox --help"`);
  }
}

// Only run when invoked directly, so importing this module in a test is safe.
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, '/')}`).href) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(`lockbox: ${error?.stack ?? error}\n`);
      process.exitCode = 1;
    },
  );
}
