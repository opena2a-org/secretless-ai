import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * The fullwidth forms U+FF01 to U+FF5E render as the ASCII character they
 * stand for, so a reviewer sees U+FF21 as `A`. A source file that needs one
 * spells it as an escape (`\uFF21`) or names it (U+FF21), never as the
 * character itself.
 */

const ROOTS = ['src', 'scripts'].map(d => path.resolve(__dirname, '..', d));
const FULLWIDTH = /[\uFF01-\uFF5E]/u;

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(full));
    else if (/\.(ts|js|mjs|cjs)$/.test(entry.name)) out.push(full);
  }
  return out;
}

describe('source text', () => {
  it('carries no fullwidth form of an ASCII character', () => {
    const hits: string[] = [];
    for (const root of ROOTS.filter(r => fs.existsSync(r))) {
      for (const file of sourceFiles(root)) {
        fs.readFileSync(file, 'utf-8').split('\n').forEach((line, i) => {
          const m = FULLWIDTH.exec(line);
          if (m) hits.push(`${path.relative(path.resolve(__dirname, '..'), file)}:${i + 1} U+${m[0].codePointAt(0)!.toString(16).toUpperCase()}`);
        });
      }
    }
    expect(hits).toEqual([]);
  });
});
