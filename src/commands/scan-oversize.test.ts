import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan, formatSizeOverCap } from './core';
import { SOURCE_FILE_CAP_BYTES, CONFIG_FILE_CAP_BYTES } from '../scan';

// The size line under "skipped for size" rounded both figures to one decimal,
// so a 1,052,708-byte source file over the 1,048,576-byte cap printed
// `big.js (1.0 MB, cap 1.0 MB)`: a line that reads as if the file were at the
// cap, not over it. The file has to read as larger than the cap.

function treeWithSourceFile(bytes: number): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-oversize-line-'));
  const head = '// x\n';
  fs.writeFileSync(path.join(dir, 'big.js'), head + 'a'.repeat(bytes - head.length));
  return dir;
}

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

describe('the size line for a file skipped for size', () => {
  let dir: string;
  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('prints a size larger than the cap for a file just over it', async () => {
    dir = treeWithSourceFile(1_052_708);
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(stripAnsi(a.map(String).join(' '))); });

    const code = await runScan(dir);
    const out = lines.join('\n');

    expect(code).toBe(1);
    expect(out).toContain('1 file skipped for size');
    expect(out).toContain('big.js (1,052,708 bytes, cap 1,048,576 bytes)');
    expect(out).not.toContain('1.0 MB, cap 1.0 MB');
  });
});

describe('formatSizeOverCap', () => {
  it('keeps the rounded figures when they already show the file as larger', () => {
    expect(formatSizeOverCap(11 * 1024 * 1024 + 300, CONFIG_FILE_CAP_BYTES)).toBe('11 MB, cap 10 MB');
    expect(formatSizeOverCap(2 * 1024 * 1024, SOURCE_FILE_CAP_BYTES)).toBe('2.0 MB, cap 1.0 MB');
  });

  it('prints exact bytes when rounding would show the size equal to the cap', () => {
    expect(formatSizeOverCap(SOURCE_FILE_CAP_BYTES + 1, SOURCE_FILE_CAP_BYTES)).toBe('1,048,577 bytes, cap 1,048,576 bytes');
    // Whole-MB rounding above 10 MB collides the same way.
    expect(formatSizeOverCap(CONFIG_FILE_CAP_BYTES + 400 * 1024, CONFIG_FILE_CAP_BYTES)).toBe('10,895,360 bytes, cap 10,485,760 bytes');
  });

  it('prints exact bytes when the units differ but the rounded figures are equal', () => {
    // A cap one byte under 1 MB rounds to "1024 KB", which is the same amount
    // as the file's "1.0 MB".
    expect(formatSizeOverCap(1024 * 1024, 1024 * 1024 - 1)).toBe('1,048,576 bytes, cap 1,048,575 bytes');
  });
});
