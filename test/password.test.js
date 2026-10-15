/**
 * Password input from a file.
 *
 * The file path is the one scripts use, so it is also the one where an editor's
 * help is easiest to mistake for part of the password: a UTF-8 BOM or an old Mac
 * line ending made the password something nobody could type again, and a
 * password nobody can type is a password that is lost with the file.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { PasswordError, readPassword } from '../src/password.js';
import { makeTempDir, writeFixture } from './helpers.js';

const PASSWORD = 'a-strong-test-password';

test('a password file is read as its first line, whatever ends the line', async () => {
  const dir = await makeTempDir();
  const cases = [
    ['lf.txt', `${PASSWORD}\nignored second line\n`],
    ['crlf.txt', `${PASSWORD}\r\nignored second line\r\n`],
    ['cr.txt', `${PASSWORD}\rignored second line\r`],
    ['no-newline.txt', PASSWORD],
    ['blank-second-line.txt', `${PASSWORD}\n\n`],
  ];
  for (const [name, content] of cases) {
    const file = await writeFixture(dir, name, content);
    assert.equal(await readPassword({ passwordFile: file }), PASSWORD, name);
  }
});

test('a UTF-8 BOM is the editor talking, not part of the password', async () => {
  const dir = await makeTempDir();
  const file = await writeFixture(dir, 'pw.txt', `\uFEFF${PASSWORD}\n`);
  assert.equal(await readPassword({ passwordFile: file }), PASSWORD);
});

test('an empty password file is refused rather than used as an empty password', async () => {
  const dir = await makeTempDir();
  for (const [name, content] of [
    ['empty.txt', ''],
    ['blank.txt', '\r\n'],
    ['bom-only.txt', '\uFEFF\n'],
  ]) {
    const file = await writeFixture(dir, name, content);
    await assert.rejects(() => readPassword({ passwordFile: file }), PasswordError, name);
  }
});
