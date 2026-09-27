/**
 * Shared CLI behaviour for these projects.
 *
 * Copied into each repository's src/ at build time rather than installed as a
 * package, so every project keeps its zero-runtime-dependency promise while the
 * six of them do not drift apart on the boring parts.
 *
 * What lives here:
 *   - "did you mean" suggestions for a mistyped option
 *   - a consistent error format: what went wrong, and what to do about it
 *   - the three signal and pipe cases every CLI gets wrong the first time
 *
 * The pipe case is the one that matters most and is easiest to skip. A CLI whose
 * output is piped into `head` receives EPIPE when the reader closes early, and
 * node turns that into an unhandled error and a stack trace. Every well-behaved
 * Unix tool exits quietly instead.
 */

import process from 'node:process';

/**
 * Levenshtein distance: the number of single-character insertions, deletions or
 * substitutions needed to turn one string into the other.
 *
 * Written as the straightforward two-row dynamic program and checked against
 * hand-computed cases in the tests, because an earlier attempt at a clever
 * version silently returned the wrong answer for `colour` to `color` — the exact
 * case the function exists to serve.
 */
export function editDistance(a, b) {
  const left = String(a);
  const right = String(b);
  if (left === right) return 0;
  if (left.length === 0) return right.length;
  if (right.length === 0) return left.length;

  // previous[j] is the distance between left[0..i-1] and right[0..j-1].
  let previous = Array.from({ length: right.length + 1 }, (_, j) => j);
  for (let i = 1; i <= left.length; i += 1) {
    const current = new Array(right.length + 1);
    current[0] = i;
    for (let j = 1; j <= right.length; j += 1) {
      const substitution = previous[j - 1] + (left[i - 1] === right[j - 1] ? 0 : 1);
      const deletion = previous[j] + 1;
      const insertion = current[j - 1] + 1;
      current[j] = Math.min(substitution, deletion, insertion);
    }
    previous = current;
  }
  return previous[right.length];
}

/** Below this, a single-character difference says nothing about intent. */
const MIN_SUGGESTABLE_LENGTH = 4;

/**
 * The closest known name to what the user typed, or null when nothing is close.
 *
 * Short names are skipped: `a` and `b` are one edit apart and completely
 * unrelated, so at that length there is no such thing as a typo. A confident
 * wrong suggestion is worse than no suggestion.
 *
 * @param {string} input
 * @param {Iterable<string>} candidates
 * @returns {string|null}
 */
export function nearestName(input, candidates) {
  const needle = String(input);
  if (needle.length < MIN_SUGGESTABLE_LENGTH) return null;
  const allowance = needle.length <= 6 ? 2 : 3;
  let best = null;
  let bestDistance = allowance + 1;
  for (const candidate of candidates) {
    const name = String(candidate);
    if (name.length < MIN_SUGGESTABLE_LENGTH) continue;
    const distance = editDistance(needle, name);
    if (distance < bestDistance) {
      bestDistance = distance;
      best = name;
    }
  }
  return best;
}

/**
 * An error the CLI should print as a message rather than a stack trace.
 *
 * `hint` is the part people actually need: the corrected command, or the file to
 * look at. An error without a hint is a puzzle; an error with one is a fix.
 */
export class UsageError extends Error {
  /**
   * @param {string} message what went wrong, lower case, no trailing period
   * @param {{hint?: string, code?: number, showUsage?: boolean}} [options]
   */
  constructor(message, options = {}) {
    super(message);
    this.name = 'UsageError';
    this.hint = options.hint ?? null;
    this.code = options.code ?? 2;
    this.showUsage = options.showUsage ?? false;
  }
}

/** Build the "unknown option" error, with a suggestion when there is one. */
export function unknownOptionError(option, candidates) {
  // Compare the bare name: `--colr` against `--color`, not against `color`.
  // Passing the dashes through made every suggestion fail to match.
  const bare = String(option).replace(/^-+/, '');
  const suggestion = nearestName(bare, candidates);
  return new UsageError(`unknown option ${option}`, {
    hint: suggestion ? `did you mean --${suggestion}?` : 'run with --help to see every option',
  });
}

/**
 * Format an error for stderr.
 *
 * Deliberately not a stack trace. A user who mistyped a flag does not want to
 * read through `node:internal`, and a stack trace also hides the one line that
 * matters by burying it at the top of twenty others.
 *
 * `usage` is a function, not a string: building the whole help text on every
 * error would be wasted work, and a caller that does not have help text should
 * not have to pass one.
 *
 * @param {unknown} error
 * @param {{tool?: string, debug?: boolean, usage?: (() => string)|string|null}} [options]
 */
export function formatError(error, options = {}) {
  const { tool = 'error', debug = false, usage = null } = options;
  const message = error && typeof error === 'object' && 'message' in error ? String(error.message) : String(error);
  const hint = error && typeof error === 'object' && 'hint' in error ? error.hint : null;
  const showUsage = error && typeof error === 'object' && 'showUsage' in error ? error.showUsage : false;

  const lines = [`${tool}: ${message}`];
  if (hint) lines.push(`  ${hint}`);
  if (showUsage) {
    const text = typeof usage === 'function' ? usage() : usage;
    if (typeof text === 'string' && text.trim() !== '') {
      lines.push('');
      lines.push(text.replace(/\s+$/, ''));
    }
  }
  if (debug && error instanceof Error && error.stack) {
    lines.push('');
    lines.push(error.stack);
  }
  return `${lines.join('\n')}\n`;
}

/** True for the codes a CLI should treat as "the reader went away". */
export function isBrokenPipe(error) {
  return Boolean(error) && (error.code === 'EPIPE' || error.code === 'ERR_STREAM_DESTROYED');
}

/**
 * Installs already performed in this process, keyed by the stdio streams they
 * were attached to. Kept so that a second call is a no-op instead of a second
 * set of listeners: the bin entry and the module it imports may both ask for the
 * handlers, and installing twice would double every message and leak a listener
 * per call.
 */
const installed = new WeakMap();

/**
 * Install the handlers every command line tool needs.
 *
 * The three cases, and what a user expects from each:
 *
 *   EPIPE     `tool | head` — exit quietly, status 0. Anything else is noise
 *             written to a pipe nobody is reading, and it also breaks `$?`
 *             checks in a script that pipes into `head`.
 *   SIGINT    Ctrl-C — stop, do not print a stack trace for the interruption.
 *             A tool with cleanup can pass `onInterrupt`; a second Ctrl-C exits
 *             immediately so nobody is ever trapped waiting.
 *   leftovers an uncaught exception or an unhandled rejection used to escape as
 *             a stack trace; they now go through `formatError` like everything
 *             else, unless debug is on.
 *
 * Idempotent per process: calling it again returns the existing remover.
 *
 * @param {object} options
 * @param {string} options.tool name used as the prefix of every message
 * @param {(signal: string) => void} [options.onInterrupt] cleanup hook
 * @param {() => string} [options.usage] help text, shown for a usage error
 * @param {() => boolean} [options.debug] read at throw time, not at install time
 * @returns {() => void} removes every handler again (for tests)
 */
export function installCliHandlers({ tool, onInterrupt = null, usage = null, debug = null } = {}) {
  const stdout = process.stdout;
  const stderr = process.stderr;

  const already = installed.get(stdout);
  if (already) return already;

  // A broken pipe raises an error event on the stream. Without this, node prints
  // "Error: write EPIPE" and exits non-zero, which breaks `tool | head -1` in
  // any script that checks the status.
  const onPipeError = (error) => {
    if (isBrokenPipe(error)) {
      process.exit(0);
    }
    throw error;
  };
  stdout.on('error', onPipeError);
  stderr.on('error', onPipeError);

  let interrupted = false;
  const onSignal = (signal) => {
    if (interrupted) {
      // Asked twice: stop being polite.
      process.exit(signal === 'SIGINT' ? 130 : 143);
    }
    interrupted = true;
    try {
      onInterrupt?.(signal);
    } catch {
      /* cleanup must never mask the exit */
    }
    process.exit(signal === 'SIGINT' ? 130 : 143);
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  const onFatal = (error) => {
    if (isBrokenPipe(error)) process.exit(0);
    process.stderr.write(formatError(error, { tool, usage: usage?.() ?? null, debug: debug?.() ?? false }));
    process.exit(1);
  };
  // A named function, not an inline arrow: `off` needs the same reference that
  // `on` was given, and an anonymous wrapper can never be removed again.
  const onUnhandledRejection = (reason) => onFatal(reason);

  process.on('uncaughtException', onFatal);
  process.on('unhandledRejection', onUnhandledRejection);

  const remove = () => {
    stdout.off('error', onPipeError);
    stderr.off('error', onPipeError);
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    process.off('uncaughtException', onFatal);
    process.off('unhandledRejection', onUnhandledRejection);
    installed.delete(stdout);
  };
  installed.set(stdout, remove);
  return remove;
}

/** Is a stream a terminal that can be written to? Used for progress and colour. */
export function isInteractive(stream = process.stdout) {
  return Boolean(stream && stream.isTTY);
}

/**
 * Print text unless the reader went away.
 *
 * A write can also fail when the stream is already closed, which happens when
 * output is redirected to a file on a full disk. Reporting that as a broken pipe
 * would be wrong, so the two are told apart.
 */
export function writeSafely(stream, text) {
  try {
    stream.write(text);
    return true;
  } catch (error) {
    if (isBrokenPipe(error)) return false;
    throw error;
  }
}
