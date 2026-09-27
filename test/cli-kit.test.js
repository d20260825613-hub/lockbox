/**
 * Test the shared CLI behaviour.
 *
 * These cases are easy to skip and expensive to get wrong: a tool that dumps a
 * stack trace when its output is piped into `head` looks broken, and one that
 * exits 1 on a broken pipe breaks `$?` checks in scripts.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';

import {
  UsageError,
  editDistance,
  formatError,
  installCliHandlers,
  isBrokenPipe,
  isInteractive,
  nearestName,
  unknownOptionError,
  writeSafely,
} from '../src/cli-kit.js';

/** A stand-in for process.stdout that records what was written. */
function fakeStream({ isTTY = false, failWith = null } = {}) {
  const chunks = [];
  return {
    isTTY,
    chunks,
    text: () => chunks.join(''),
    on() {},
    off() {},
    write(chunk) {
      if (failWith) {
        const error = new Error('write failed');
        error.code = failWith;
        throw error;
      }
      chunks.push(String(chunk));
      return true;
    },
  };
}

test('editDistance matches hand-computed and reference values', () => {
  // The classic reference pair, plus the cases this function actually serves.
  assert.equal(editDistance('kitten', 'sitting'), 3);
  assert.equal(editDistance('saturday', 'sunday'), 3);
  assert.equal(editDistance('colour', 'color'), 1, 'one deletion, not two');
  assert.equal(editDistance('color', 'colour'), 1, 'and it is symmetric');
  assert.equal(editDistance('colr', 'color'), 1);
  assert.equal(editDistance('color', 'color'), 0);
  assert.equal(editDistance('', 'abc'), 3);
  assert.equal(editDistance('abc', ''), 3);
  assert.equal(editDistance('a', 'b'), 1);
});

test('editDistance is symmetric and never negative, over a spread of pairs', () => {
  const words = ['color', 'colour', 'colr', 'cache', 'concurrency', '', 'json', 'help'];
  for (const left of words) {
    for (const right of words) {
      const forward = editDistance(left, right);
      assert.equal(forward, editDistance(right, left), `${left} vs ${right} is not symmetric`);
      assert.ok(forward >= 0, `${left} vs ${right} went negative`);
      assert.ok(forward <= Math.max(left.length, right.length), `${left} vs ${right} exceeded the string length`);
    }
  }
});

test('nearestName suggests a close option and stays quiet otherwise', () => {
  const options = ['color', 'cache', 'concurrency', 'help', 'version', 'json'];
  assert.equal(nearestName('colr', options), 'color');
  assert.equal(nearestName('colour', options), 'color');
  assert.equal(nearestName('cach', options), 'cache');
  assert.equal(nearestName('concurency', options), 'concurrency');
  assert.equal(nearestName('completely-different', options), null);
});

test('nearestName is stricter about short names, where a small distance means anything', () => {
  // `a` and `b` are one edit apart and completely unrelated, so at that length
  // there is no such thing as a typo. A confident wrong suggestion is worse than
  // no suggestion at all.
  assert.equal(nearestName('d', ['a', 'b', 'c']), null);
  assert.equal(nearestName('abc', ['a', 'ab']), null, 'short candidates are skipped too');
  assert.equal(nearestName('ab', ['abc', 'xyz']), null);
  assert.equal(nearestName('json', ['version', 'color']), null, 'nothing close means no suggestion');
  assert.equal(nearestName('versoin', ['version', 'color']), 'version', 'a transposition is still a typo');
});

test('an unknown option comes back with a did-you-mean hint', () => {
  const error = unknownOptionError('--colr', ['color', 'cache']);
  assert.ok(error instanceof UsageError);
  assert.equal(error.message, 'unknown option --colr');
  assert.match(error.hint, /did you mean --color\?/);
});

test('an unknown option with nothing close suggests the help flag instead', () => {
  const error = unknownOptionError('--totally-made-up', ['color', 'cache']);
  assert.equal(error.hint, 'run with --help to see every option');
});

test('formatError prints a message and a hint, and not a stack trace', () => {
  const error = new UsageError('unknown option --colr', { hint: 'did you mean --color?' });
  const text = formatError(error, { tool: 'lockbox' });
  assert.match(text, /^lockbox: unknown option --colr\n/);
  assert.match(text, /did you mean --color\?/);
  assert.equal(/at .*\(.*:\d+:\d+\)/.test(text), false, 'no stack frames');
});

test('formatError includes the usage text only when the error asks for it', () => {
  const plain = formatError(new UsageError('bad'), { tool: 'x', usage: () => 'USAGE TEXT' });
  assert.equal(plain.includes('USAGE TEXT'), false);

  const wants = formatError(new UsageError('bad', { showUsage: true }), { tool: 'x', usage: () => 'USAGE TEXT' });
  assert.match(wants, /USAGE TEXT/);
});

test('formatError shows a stack trace only in debug mode', () => {
  const error = new Error('boom');
  assert.equal(/at /.test(formatError(error, { tool: 'x' })), false);
  assert.match(formatError(error, { tool: 'x', debug: true }), /Error: boom/);
});

test('formatError copes with a thrown non-Error', () => {
  assert.match(formatError('just a string', { tool: 'x' }), /x: just a string/);
  assert.match(formatError({ code: 'ENOENT' }, { tool: 'x' }), /x: /);
});

test('isBrokenPipe recognises the codes that mean the reader went away', () => {
  assert.equal(isBrokenPipe({ code: 'EPIPE' }), true);
  assert.equal(isBrokenPipe({ code: 'ERR_STREAM_DESTROYED' }), true);
  assert.equal(isBrokenPipe({ code: 'ENOSPC' }), false, 'a full disk is not a broken pipe');
  assert.equal(isBrokenPipe(null), false);
  assert.equal(isBrokenPipe(new Error('no code')), false);
});

test('writeSafely reports a broken pipe instead of throwing', () => {
  const ok = fakeStream();
  assert.equal(writeSafely(ok, 'hello'), true);
  assert.equal(ok.text(), 'hello');

  const broken = fakeStream({ failWith: 'EPIPE' });
  assert.equal(writeSafely(broken, 'hello'), false);
});

test('writeSafely still throws for a real write failure', () => {
  const full = fakeStream({ failWith: 'ENOSPC' });
  assert.throws(() => writeSafely(full, 'hello'), /write failed/);
});

test('isInteractive follows isTTY', () => {
  assert.equal(isInteractive({ isTTY: true }), true);
  assert.equal(isInteractive({ isTTY: false }), false);
  assert.equal(isInteractive(null), false);
});

test('installCliHandlers registers and removes every handler', () => {
  const before = {
    sigint: process.listenerCount('SIGINT'),
    sigterm: process.listenerCount('SIGTERM'),
    uncaught: process.listenerCount('uncaughtException'),
    unhandled: process.listenerCount('unhandledRejection'),
  };
  const stdoutError = process.stdout.listenerCount('error');

  const remove = installCliHandlers({ tool: 'test' });
  assert.equal(process.listenerCount('SIGINT'), before.sigint + 1);
  assert.equal(process.listenerCount('SIGTERM'), before.sigterm + 1);
  assert.equal(process.listenerCount('uncaughtException'), before.uncaught + 1);
  assert.equal(process.listenerCount('unhandledRejection'), before.unhandled + 1);
  assert.equal(process.stdout.listenerCount('error'), stdoutError + 1);

  remove();
  assert.equal(process.listenerCount('SIGINT'), before.sigint);
  assert.equal(process.listenerCount('SIGTERM'), before.sigterm);
  assert.equal(process.listenerCount('uncaughtException'), before.uncaught);
  assert.equal(process.listenerCount('unhandledRejection'), before.unhandled);
  assert.equal(process.stdout.listenerCount('error'), stdoutError);
});

test('installCliHandlers is idempotent within a process', () => {
  // The bin entry and the module it imports may both ask for the handlers.
  // Installing twice would double every message and leak a listener per call, so
  // a second call adds nothing and returns a remover that is safe to call.
  const first = installCliHandlers({ tool: 'a' });
  const afterFirst = process.listenerCount('SIGINT');
  const second = installCliHandlers({ tool: 'b' });

  assert.equal(process.listenerCount('SIGINT'), afterFirst, 'a second install added listeners');
  assert.equal(typeof second, 'function');
  assert.equal(first(), undefined);
});

test('handlers can be installed again after being removed', () => {
  const baseline = process.listenerCount('SIGINT');
  const first = installCliHandlers({ tool: 'a' });
  first();
  assert.equal(process.listenerCount('SIGINT'), baseline);

  const second = installCliHandlers({ tool: 'b' });
  assert.equal(process.listenerCount('SIGINT'), baseline + 1);
  second();
  assert.equal(process.listenerCount('SIGINT'), baseline);
});

test('the bin entry installs the handlers, which the module alone cannot do', async () => {
  // The bug this pins down: importing `run` makes src/cli.js's direct-run check
  // false, so handlers installed only there never fire for the installed
  // `lockbox` command. A subprocess is the only way to see it: the probe
  // imports `bin/lockbox.js` exactly the way a command on PATH does, then
  // reports what the entry point left behind on `process`. Undo the
  // `installHandlers()` call in the bin and this fails with sigint=0 pipe=0 —
  // which is the state that printed an EPIPE stack trace on `lockbox ... | head`.
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'lockbox-kit-'));
  try {
    const bin = new URL('../bin/lockbox.js', import.meta.url).href;
    const probe = path.join(dir, 'probe.mjs');
    await fs.writeFile(
      probe,
      `await import(${JSON.stringify(bin)});\n` +
        "process.stdout.write(`sigint=${process.listenerCount('SIGINT')} pipe=${process.stdout.listenerCount('error')}\\n`);\n",
    );

    const result = spawnSync(process.execPath, [probe], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /lockbox - encrypt a file with a password/, 'the bin did not run the CLI');
    assert.match(result.stdout, /sigint=1 pipe=1/, 'the bin entry installed no handlers');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
