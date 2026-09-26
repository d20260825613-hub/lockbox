/** Small formatting helpers. Pure, so they are trivial to test. */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

/** Compact size, e.g. "1.5 MB". */
export function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '0 B';
  if (n < 1024) return `${n} B`;
  const exp = Math.min(Math.floor(Math.log(n) / Math.log(1024)), UNITS.length - 1);
  const value = n / 1024 ** exp;
  return `${value >= 100 ? Math.round(value) : Math.round(value * 10) / 10} ${UNITS[exp]}`;
}

/** Same number, spelled out with thousands separators, for "what is in this file" lines. */
export function formatBytesLong(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '0 bytes';
  const exact = `${n.toLocaleString('en-US')} ${n === 1 ? 'byte' : 'bytes'}`;
  return n < 1024 ? exact : `${formatBytes(n)} (${exact})`;
}
