import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Git treats a file holding a NUL byte as binary, so every change to it shows
 * as "Binary files differ" and review sees no lines. A test or comment that
 * needs a NUL writes the `\u0000` escape or builds the string at run time.
 */

const ROOT = path.resolve(__dirname, '..');

/** Tracked files that are binary by nature and may hold NUL bytes. */
const BINARY_EXTENSIONS = new Set(['.png', '.gif', '.jpg', '.jpeg', '.ico', '.webp']);

describe('tracked text files', () => {
  it('contain no NUL byte', () => {
    const files = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8' })
      .split('\0')
      .filter(f => f !== '' && !BINARY_EXTENSIONS.has(path.extname(f).toLowerCase()));
    expect(files.length).toBeGreaterThan(0);
    const withNul = files.filter(f => {
      const full = path.join(ROOT, f);
      if (!fs.existsSync(full) || !fs.statSync(full).isFile()) return false;
      return fs.readFileSync(full).includes(0);
    });
    expect(withNul, 'write the \\u0000 escape, or build the string at run time, in place of a literal NUL byte').toEqual([]);
  });
});
