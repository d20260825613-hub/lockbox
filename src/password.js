/**
 * Password input.
 *
 * Three honest options, in order of safety:
 *   1. an environment variable or a file, for scripts (never appears in argv,
 *      where any process on the machine could read it from the process list)
 *   2. an interactive prompt that reads from the terminal directly
 *   3. a plain prompt, with a warning, when there is no terminal at all
 *
 * Reading from /dev/tty rather than stdin is deliberate: it keeps the password
 * out of a pipe, so `cat secret | lockbox encrypt f` still prompts properly.
 */

import fs from 'node:fs';
import process from 'node:process';
import readline from 'node:readline';

const MIN_PASSWORD_LENGTH = 8;

export class PasswordError extends Error {
  /**
   * @param {string} message what went wrong, lower case, no trailing period
   * @param {string|null} [hint] the way out, shown on its own line under the
   *   message. `formatError` reads this field by name, so a hint passed any
   *   other way is silently dropped and the user is left with a puzzle.
   */
  constructor(message, hint = null) {
    super(message);
    this.name = 'PasswordError';
    this.hint = hint;
  }
}

/**
 * Resolve a password.
 *
 * An environment variable or a file is used as given; `confirm` only applies
 * when a human has to type it, because a typo there is unrecoverable.
 *
 * @param {{passwordEnv?: string|null, passwordFile?: string|null}} options
 * @param {{confirm?: boolean}} [behaviour]
 */
export async function readPassword(options = {}, { confirm = false } = {}) {
  if (options.passwordEnv) {
    const value = process.env[options.passwordEnv];
    if (!value) throw new PasswordError(`environment variable ${options.passwordEnv} is empty or not set`);
    return value;
  }
  if (options.passwordFile) {
    const text = await fs.promises.readFile(options.passwordFile, 'utf8');
    const first = text.split(/\r?\n/)[0];
    if (!first) throw new PasswordError(`${options.passwordFile} is empty`);
    return first;
  }
  return confirm ? readPasswordConfirmed() : promptOnce('Password: ');
}

/**
 * Interactive prompt with confirmation, used by `encrypt`.
 *
 * Confirm-on-entry is the only guard against a typo locking a file forever:
 * there is no recovery path, so this check matters more here than it would in a
 * tool that can reset a password.
 */
export async function readPasswordConfirmed() {
  const first = await promptOnce('Password: ');
  if (first.length < MIN_PASSWORD_LENGTH) {
    throw new PasswordError(`use at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  const again = await promptOnce('Repeat password: ');
  if (first !== again) {
    throw new PasswordError('the two passwords do not match');
  }
  return first;
}

/** Prompt without echoing, falling back to a visible prompt and a warning. */
function promptOnce(label) {
  return new Promise((resolve, reject) => {
    const tty = openTty();
    const input = tty ?? process.stdin;
    const output = tty ?? process.stderr;

    // Reading a password needs one of these three states to end the wait, and
    // the failure they all guard against is the same: a promise that never
    // settles. Node reports that as "Detected unsettled top-level await" and
    // exits 13 -- an errno, not one of this tool's exit codes -- so
    // `lockbox encrypt f < /dev/null` looked like a crash instead of "no
    // password was given".
    //
    // Which one fires depends on when the input ends, which is why all three
    // are needed and none is redundant:
    //
    //   'line'  the normal case; the only one that carries a password.
    //   'close' the input ended while this prompt was waiting. Readline emits
    //           `close` with no `line` and no `error`.
    //   'end'   the input ended *before* this prompt started. That is not
    //           hypothetical: `encrypt` asks twice (password, then confirm), so
    //           a here-string with one line leaves the second prompt reading a
    //           stream that is already done. Readline then emits nothing at all
    //           -- the probe that found this showed the second prompt timing out
    //           with every listener still silent -- so a pre-check plus a
    //           listener on the stream itself is the only way to catch it.
    const noPassword = () =>
      new PasswordError(
        'no password was given (the input ended before one was entered)',
        'pass --password-file, --password-env, or run this in a terminal',
      );

    let settled = false;
    let rl = null;
    let onEnd = null;

    function settle(fn, value) {
      if (settled) return;
      settled = true;
      if (onEnd) input.off('end', onEnd);
      if (rl) rl.close();
      if (tty) tty.close();
      fn(value);
    }

    // The stream can already be finished here. Rejecting without creating a
    // readline interface is what turns a hang into a message.
    if (input.readableEnded || input.destroyed) {
      output.write('\n');
      settle(reject, noPassword());
      return;
    }

    if (!tty) {
      output.write('warning: no terminal available, the password will be visible as you type\n');
    }

    rl = readline.createInterface({ input, output, terminal: true });
    let muted = false;
    if (tty && typeof input.setRawMode === 'function') {
      const originalWrite = rl._writeToOutput?.bind(rl);
      rl._writeToOutput = (text) => {
        if (muted) return;
        if (originalWrite) originalWrite(text);
      };
    }

    output.write(label);
    muted = true;

    onEnd = () => {
      output.write('\n');
      settle(reject, noPassword());
    };
    input.once('end', onEnd);

    rl.once('line', (line) => {
      output.write('\n');
      settle(resolve, line);
    });
    rl.once('error', (error) => settle(reject, error));
    rl.once('SIGINT', () => {
      output.write('\n');
      settle(reject, new PasswordError('cancelled'));
    });
    rl.once('close', () => {
      if (settled) return;
      output.write('\n');
      settle(reject, noPassword());
    });
  });
}

/** A readable handle on the controlling terminal, or null when there is none. */
function openTty() {
  if (process.platform === 'win32') return null; // no /dev/tty on Windows
  try {
    const fd = fs.openSync('/dev/tty', 'r+');
    const stream = new fs.ReadStream(null, { fd, autoClose: false });
    stream.write = (chunk, encoding, callback) => {
      fs.writeSync(fd, typeof chunk === 'string' ? chunk : chunk.toString(encoding ?? 'utf8'));
      if (typeof callback === 'function') callback();
      return true;
    };
    stream.close = () => {
      try {
        fs.closeSync(fd);
      } catch {
        /* already closed */
      }
    };
    stream.isTTY = true;
    return stream;
  } catch {
    return null;
  }
}

export { MIN_PASSWORD_LENGTH };
