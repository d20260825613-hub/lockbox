/**
 * One-off repository setup: topics and the v0.1.0 release.
 * Uses `gh api`, so no new credential is needed.
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf8'));
const repo = 'd20260825613-hub/lockbox';
const tag = `v${pkg.version}`;

const TOPICS = [
  'encryption',
  'file-encryption',
  'aes-256-gcm',
  'scrypt',
  'cli',
  'nodejs',
  'zero-dependencies',
  'cross-platform',
  'security-tools',
  'command-line-tool',
];

function gh(args, { allowFail = false } = {}) {
  const dirs = ['D:\\dsh\\_tools\\git\\cmd', 'D:\\dsh\\_tools\\gh\\bin'].filter((d) => fs.existsSync(d));
  const extra = dirs.filter((d) => !(process.env.PATH ?? '').includes(d));
  const env =
    extra.length > 0
      ? { ...process.env, PATH: `${extra.join(path.delimiter)}${path.delimiter}${process.env.PATH}` }
      : process.env;
  const result =
    process.platform === 'win32'
      ? spawnSync('cmd', ['/c', 'gh', ...args], { cwd: projectRoot, encoding: 'utf8', env })
      : spawnSync('gh', args, { cwd: projectRoot, encoding: 'utf8', env });
  if (!allowFail && result.status !== 0) {
    throw new Error(`gh ${args.join(' ')} failed: ${(result.stderr || result.stdout || '').trim()}`);
  }
  return result;
}

// 1. topics ----------------------------------------------------------------
const topicsPayload = JSON.stringify({ names: TOPICS });
const topicTmp = path.join(projectRoot, '.topics.json');
fs.writeFileSync(topicTmp, topicsPayload);
try {
  const result = gh(['api', '--method', 'PUT', `repos/${repo}/topics`, '--input', topicTmp]);
  const names = JSON.parse(result.stdout).names ?? [];
  console.log(`topics: ${names.length} set`);
} finally {
  fs.rmSync(topicTmp, { force: true });
}

// 2. release notes ---------------------------------------------------------
const changelog = fs.readFileSync(path.join(projectRoot, 'CHANGELOG.md'), 'utf8');
const section = changelog.split(`## [${pkg.version}]`)[1]?.split('\n## [')[0] ?? '';
const body = `# lockbox ${pkg.version}\n\nEncrypt a file with a password. scrypt for the key,\nAES-256-GCM for the data, both from Node's own crypto module.${section}\n\n## Before you rely on this\n\nThere is no password recovery. The container format has not been audited. See\nthe README for the full list of limitations.`;
fs.writeFileSync(path.join(projectRoot, 'RELEASE-NOTES.md'), `${body}\n`);
console.log('wrote RELEASE-NOTES.md');

// 3. release ---------------------------------------------------------------
const existing = gh(['release', 'view', tag, '--repo', repo, '--json', 'url'], { allowFail: true });
if (existing.status === 0) {
  console.log(`release ${tag} already exists`);
} else {
  const created = gh([
    'release',
    'create',
    tag,
    '--repo',
    repo,
    '--title',
    `lockbox ${pkg.version}`,
    '--notes-file',
    path.join(projectRoot, 'RELEASE-NOTES.md'),
    '--target',
    'main',
    '--latest',
  ]);
  console.log(`release: ${created.stdout.trim()}`);
}
