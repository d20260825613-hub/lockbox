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
import { pathToFileURL } from 'node:url';

import { UsageError, formatError, installCliHandlers, unknownOptionError } from './cli-kit.js';
import { DecryptError, decryptFile, encryptFile, inspectFile } from './crypto.js';
import { DEFAULT_LOG2_N, MAX_LOG2_N, MIN_LOG2_N, FormatError } from './format.js';
import { readPassword } from './password.js';
import { formatBytes, formatBytesLong } from './util.js';

const VERSION = '0.2.0';
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

/**
 * Every option this command line accepts, for the "did you mean" suggestion.
 * Kept next to the parser so the two cannot drift apart unnoticed.
 */
export const OPTION_NAMES = [
  'out',
  'force',
  'cost',
  'password-env',
  'password-file',
  'no-progress',
  'debug',
  'help',
  'version',
];

/**
 * Report a problem and return the exit code.
 *
 * 2 is "you asked for something impossible" and 1 is "the operation failed".
 * Keeping the two apart is the only way a script can tell a typo from a bad
 * password, and mixing them is how a caller ends up retrying something that can
 * never work.
 *
 * The message goes through `formatError` rather than being written directly, so
 * an error that carries a `hint` keeps it. Reading `error.message` here silently
 * dropped every hint on this path -- including the one that tells a user at a
 * closed stdin which options would have given a password instead.
 *
 * @param {string|Error|{message: string, hint?: string|null}} message
 * @param {number} [code]
 */
function fail(message, code = 1) {
  const error = typeof message === 'string' ? { message } : message;
  process.stderr.write(formatError(error, { tool: 'lockbox' }));
  return code;
}

/** Shorthand for the argument-shaped failures. */
function failUsageMessage(message) {
  return fail(message, 2);
}

/** Print a usage error the same way everywhere: message, hint, then nothing. */
function failUsage(error) {
  process.stderr.write(formatError(error, { tool: 'lockbox', usage: () => USAGE, debug: isDebug() }));
  return error.code ?? 2;
}

/** `--debug` anywhere in argv turns stack traces on. Read lazily, not cached. */
function isDebug() {
  return process.argv.includes('--debug') || process.env.LOCKBOX_DEBUG === '1';
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
    // An option that needs a value but is the last token: say so, rather than
    // silently reading `undefined` and failing later with something confusing.
    const needsValue = (name) => {
      const value = argv[i + 1];
      if (value === undefined) {
        return { error: new UsageError(`${name} needs a value`, { hint: `for example ${name} <value>` }) };
      }
      i += 1;
      return { value };
    };

    if (token === '-f' || token === '--force') values.force = true;
    else if (token === '--no-progress') values.progress = false;
    else if (token === '--debug') values.debug = true;
    else if (token === '-o' || token === '--out') {
      const taken = needsValue('--out');
      if (taken.error) return taken;
      values.out = taken.value;
    } else if (token.startsWith('--out=')) values.out = token.slice(6);
    else if (token === '--cost') {
      const taken = needsValue('--cost');
      if (taken.error) return taken;
      values.cost = Number(taken.value);
    } else if (token.startsWith('--cost=')) values.cost = Number(token.slice(7));
    else if (token === '--password-env') {
      const taken = needsValue('--password-env');
      if (taken.error) return taken;
      values.passwordEnv = taken.value;
    } else if (token.startsWith('--password-env=')) values.passwordEnv = token.slice(15);
    else if (token === '--password-file') {
      const taken = needsValue('--password-file');
      if (taken.error) return taken;
      values.passwordFile = taken.value;
    } else if (token.startsWith('--password-file=')) values.passwordFile = token.slice(16);
    else if (token.startsWith('-') && token !== '-') return { error: unknownOptionError(token, OPTION_NAMES) };
    else positional.push(token);
  }
  if (!Number.isInteger(values.cost) || values.cost < MIN_LOG2_N || values.cost > MAX_LOG2_N) {
    return {
      error: new UsageError(`--cost must be an integer between ${MIN_LOG2_N} and ${MAX_LOG2_N}`, {
        hint: `higher costs more memory per guess; ${DEFAULT_LOG2_N} is about 64 MB`,
      }),
    };
  }
  // An empty `--out=` is a value the user gave, not the absence of one, and
  // treating the two alike silently wrote to the default name instead.
  if (values.out === '') {
    return {
      error: new UsageError('--out needs a non-empty file name', {
        hint: 'for example --out notes.txt.locked',
      }),
    };
  }
  return { values, positional };
}

/**
 * A refusal to do what was asked, not a failure to do it.
 *
 * Both look like errors and both stop the run, but a script has to tell them
 * apart: "pass --force and try again" is fixable, "the disk said no" is not.
 * The two conditions below are decisions this tool makes before it touches
 * anything, which is exactly the `2` category. Without a type to recognise them
 * by they fell through to the generic `1` handler, so the README's exit-code
 * table and the code disagreed.
 */
export class OutputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OutputError';
  }
}

/** Default output name, and the guard against clobbering something. */
async function resolveOutput({ input, out, force, decrypting }) {
  let target = out;
  if (target === null) {
    target = decrypting
      ? input.endsWith(SUFFIX)
        ? input.slice(0, -SUFFIX.length)
        : `${input}.unlocked`
      : `${input}${SUFFIX}`;
  }
  if (await sameFile(target, input)) {
    throw new OutputError('input and output are the same file');
  }
  if (!force) {
    try {
      await fs.access(target);
      throw new OutputError(`${target} already exists; pass --force to overwrite it`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return target;
}

/**
 * Would writing to `output` destroy `input`?
 *
 * Comparing the two as strings is not enough, and every way it falls short is a
 * way to lose a file. `NOTES.TXT` and `notes.txt` are one file on Windows, and
 * `path.resolve` keeps whichever spelling it was handed -- `fs.realpath` on
 * Windows does too, so it cannot be leaned on for this. Short 8.3 names,
 * junctions and hard links likewise give two strings for one file.
 *
 * So the filesystem is asked instead. When both names exist, device and inode
 * settle it: `notes.txt` and `NOTES.TXT` report the same pair, as do two hard
 * links to one file. When the output does not exist the only way it can still be
 * the input is a difference in spelling, so the two paths are resolved and
 * compared case-insensitively where the platform compares them that way.
 */
async function sameFile(output, input) {
  try {
    const [left, right] = await Promise.all([fs.stat(output, { bigint: true }), fs.stat(input, { bigint: true })]);
    // Some filesystems report no inode at all; falling through to the names
    // beats declaring every pair of files identical.
    if (left.ino !== 0n || right.ino !== 0n) return left.dev === right.dev && left.ino === right.ino;
  } catch {
    // The output does not exist, which is the ordinary case for a new name.
  }
  const [left, right] = await Promise.all([canonicalPath(output), canonicalPath(input)]);
  if (left === right) return true;
  return (process.platform === 'win32' || process.platform === 'darwin') && left.toLowerCase() === right.toLowerCase();
}

/**
 * The most complete name this file has without it existing.
 *
 * `realpath` folds away `..`, symlinks and, on macOS, the name's real case. When
 * the file itself is not there yet, resolving its directory still removes the
 * `..` and the symlinked parent -- which is what lets `notes.txt` and
 * `sub/../notes.txt` compare equal.
 */
async function canonicalPath(target) {
  const resolved = path.resolve(target);
  try {
    return await fs.realpath(resolved);
  } catch {
    const directory = await fs.realpath(path.dirname(resolved)).catch(() => path.dirname(resolved));
    return path.join(directory, path.basename(resolved));
  }
}

/**
 * The write a Ctrl-C should interrupt, if one is running.
 *
 * A signal handler that exits on the spot skips the cleanup the write already
 * has, so the half-written file stayed on disk while the message said it had
 * not. The handler below aborts the write instead and lets it unwind.
 */
let currentRun = null;

/** The signal that asked the current run to stop, for the exit status. */
let stopSignal = null;

/** 130 is Ctrl-C and 143 is SIGTERM, which is what a shell expects. */
function stopStatus() {
  return stopSignal === 'SIGTERM' ? 143 : 130;
}

/** Start the writing half of a command, so a signal has something to abort. */
function beginWrite() {
  const controller = new AbortController();
  currentRun = controller;
  stopSignal = null;
  return controller;
}

function endWrite(controller) {
  if (currentRun === controller) currentRun = null;
}

/**
 * Say which file is not there.
 *
 * An ENOENT from opening the *output* used to be reported as a missing input,
 * which sends the user to check a file that is perfectly fine; the real problem
 * is that the output's directory does not exist. The paths are compared rather
 * than the error's text, because only the path says which one failed.
 */
function missingFileMessage(error, input, output) {
  const failed = typeof error.path === 'string' ? path.resolve(error.path) : null;
  if (failed && failed === path.resolve(output)) {
    return `cannot write ${output}: its directory does not exist`;
  }
  return `no such file: ${input}`;
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
  if (parsed.error) return failUsage(parsed.error);
  const { values, positional } = parsed;
  const input = positional[0];
  if (!input) return failUsageMessage('encrypt needs a file to encrypt');
  if (positional.length > 1) return failUsageMessage('encrypt takes exactly one file');

  let output;
  try {
    output = await resolveOutput({ input, out: values.out, force: values.force, decrypting: false });
  } catch (error) {
    // A refusal (2), not a failure (1). See OutputError.
    return fail(error, error instanceof OutputError ? 2 : 1);
  }

  // A password from the environment or a file is used as given: confirmation
  // only makes sense for something a human just typed. Password problems are
  // reported like any other user error — a stack trace here would be noise.
  let password;
  try {
    password = await readPassword(values, { confirm: true });
  } catch (error) {
    // Pass the object, not `error.message`: a PasswordError carries the way out
    // in `hint`, and flattening it to a string is what dropped it.
    return fail(error ?? String(error));
  }

  const controller = beginWrite();
  try {
    await encryptFile({
      input,
      output,
      password,
      log2N: values.cost,
      force: values.force,
      signal: controller.signal,
      onProgress: progressReporter(values.progress, 'encrypting'),
    });
  } catch (error) {
    if (values.progress && process.stderr.isTTY) process.stderr.write('\r\u001b[K');
    // Removing the output is the write's own job now: it knows whether this run
    // created the file, and deleting the output *path* on any error is how a
    // failure to even read the input used to destroy a file that was already
    // there. See `openOutput`.
    if (controller.signal.aborted) return fail(stoppedMessage(), stopStatus());
    if (error instanceof FormatError) return fail(error.message, 2);
    if (error.code === 'ENOENT') return fail(missingFileMessage(error, input, output), 2);
    return fail(error.message);
  } finally {
    endWrite(controller);
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
  if (parsed.error) return failUsage(parsed.error);
  const { values, positional } = parsed;
  const input = positional[0];
  if (!input) return failUsageMessage('decrypt needs a .locked file');
  if (positional.length > 1) return failUsageMessage('decrypt takes exactly one file');

  let output;
  try {
    output = await resolveOutput({ input, out: values.out, force: values.force, decrypting: true });
  } catch (error) {
    // A refusal (2), not a failure (1). See OutputError.
    return fail(error, error instanceof OutputError ? 2 : 1);
  }

  let password;
  try {
    password = await readPassword(values);
  } catch (error) {
    // Same as `encrypt`: the hint has to survive, or the user is left with a
    // puzzle instead of the flag that fixes it.
    return fail(error ?? String(error));
  }
  const controller = beginWrite();
  try {
    const result = await decryptFile({
      input,
      output,
      password,
      force: values.force,
      signal: controller.signal,
      onProgress: progressReporter(values.progress, 'decrypting'),
    });
    if (values.progress && process.stderr.isTTY) process.stderr.write('\r\u001b[K');
    process.stdout.write(`${input} -> ${output}\n  ${formatBytesLong(result.bytes)} restored\n`);
    return 0;
  } catch (error) {
    if (values.progress && process.stderr.isTTY) process.stderr.write('\r\u001b[K');
    if (controller.signal.aborted) return fail(stoppedMessage(), stopStatus());
    if (error instanceof DecryptError) {
      return fail(`${error.message}\n  the partial output was deleted; nothing was written`);
    }
    if (error instanceof FormatError) return fail(error.message, 2);
    if (error.code === 'ENOENT') return fail(missingFileMessage(error, input, output), 2);
    return fail(error.message);
  } finally {
    endWrite(controller);
  }
}

async function commandInspect(argv) {
  const parsed = parseArgs(argv);
  if (parsed.error) return failUsage(parsed.error);
  const input = parsed.positional[0];
  if (!input) return failUsageMessage('inspect needs a .locked file');
  if (parsed.positional.length > 1) return failUsageMessage('inspect takes exactly one file');

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
    // The same split the other two commands use, and the one the README and the
    // changelog already promised: 2 for "this file cannot work" and 1 for "the
    // operation failed". A missing file and a failed format check both fell
    // through to 1 here, so a script branching on the documented codes got the
    // opposite answer.
    if (error.code === 'ENOENT') return fail(`no such file: ${input}`, 2);
    if (error instanceof FormatError) return fail(error.message, 2);
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
 * A UsageError that escapes to here is printed as a message rather than a stack
 * trace, and its own `code` becomes the exit status. That keeps "you typed it
 * wrong" (2) separate from "the operation failed" (1), which a script can act
 * on.
 *
 * @param {string[]} argv arguments after the script name
 */
export async function run(argv) {
  try {
    return await dispatch(argv);
  } catch (error) {
    process.stderr.write(formatError(error, { tool: 'lockbox', usage: () => USAGE, debug: isDebug() }));
    return error instanceof UsageError ? (error.code ?? 2) : 1;
  }
}

async function dispatch(argv) {
  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help' || argv[0] === 'help') {
    process.stdout.write(USAGE);
    return 0;
  }
  if (argv[0] === '-v' || argv[0] === '--version') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  const [command, ...rest] = argv;

  // `-h`, `--help` and `-v`, `--version` work after a command too. They are
  // listed under Options, so refusing them made the tool answer
  // `encrypt --help` with "unknown option --help / did you mean --help?" and
  // leave the user with nothing at all.
  const known = command === 'encrypt' || command === 'decrypt' || command === 'inspect';
  if (known && (rest.includes('-h') || rest.includes('--help'))) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (known && (rest.includes('-v') || rest.includes('--version'))) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  switch (command) {
    case 'encrypt':
      return commandEncrypt(rest);
    case 'decrypt':
      return commandDecrypt(rest);
    case 'inspect':
      return commandInspect(rest);
    default:
      return failUsage(
        new UsageError(`unknown command: ${command}`, {
          hint: 'the commands are encrypt, decrypt and inspect',
        }),
      );
  }
}

/**
 * Install the process-level handlers.
 *
 * Exported because `bin/lockbox.js` is the entry point that actually runs when
 * the tool is on PATH, and it imports this module rather than running it, so the
 * direct-run block below never fires there. Both call sites share this one
 * configuration instead of repeating it. Calling it twice is harmless:
 * `installCliHandlers` is idempotent.
 *
 * Without it, `lockbox decrypt x | head` prints a node EPIPE stack trace, and
 * Ctrl-C during a long encrypt reports an exception instead of stopping quietly.
 */
export function installHandlers() {
  return installCliHandlers({
    tool: 'lockbox',
    usage: () => USAGE,
    debug: isDebug,
    onInterrupt: (signal) => {
      // A Ctrl-C with a write in flight aborts that write rather than ending the
      // process here. The write then unwinds through its own cleanup, which is
      // what removes the half-written output -- and what makes the message below
      // true. Exiting on the spot skipped that and left the partial file behind
      // while saying it had not.
      if (!currentRun) return false;
      stopSignal = signal;
      currentRun.abort();
      return true; // the write finishes the stop and reports the exit status
    },
  });
}

/** What to say once a signal has stopped a run and its cleanup has finished. */
function stoppedMessage() {
  return 'stopped. No output file was finished, so none was left behind';
}

// Only run when invoked directly, so importing this module in a test is safe.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  installHandlers();

  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(formatError(error, { tool: 'lockbox', usage: () => USAGE, debug: isDebug() }));
      process.exitCode = error instanceof UsageError ? (error.code ?? 2) : 1;
    },
  );
}
