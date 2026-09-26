import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { after } from 'node:test';

const cleanups = [];

after(async () => {
  await Promise.all(cleanups.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

/** Isolated temp directory, removed when the test file finishes. */
export async function makeTempDir(prefix = 'lockbox-test-') {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  cleanups.push(dir);
  return dir;
}

/** Deterministic pseudo-random bytes, so failures are reproducible. */
export function bytes(length, seed = 1) {
  const out = Buffer.alloc(length);
  let value = seed >>> 0;
  for (let i = 0; i < length; i += 1) {
    value = (value * 1664525 + 1013904223) >>> 0;
    out[i] = value >>> 24;
  }
  return out;
}

/** Write a file whose contents can be checked after a round trip. */
export async function writeFixture(dir, name, content) {
  const target = path.join(dir, name);
  await fs.writeFile(target, content);
  return target;
}

export async function readAll(file) {
  return fs.readFile(file);
}

export function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}
