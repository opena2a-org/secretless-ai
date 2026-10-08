import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Each CHANGELOG entry opens with a bold summary sentence on its own
 * paragraph. Markdown joins consecutive lines into one paragraph, so an entry
 * written directly under the previous one with no blank line between them is
 * rendered as the tail of that entry: the reader sees one entry where there
 * are two, and the second one's summary is buried mid-paragraph (#245).
 */

const CHANGELOG = path.resolve(__dirname, '..', 'CHANGELOG.md');

describe('CHANGELOG.md layout', () => {
  it('separates every bold-led entry from the line before it with a blank line or heading', () => {
    const lines = fs.readFileSync(CHANGELOG, 'utf-8').split('\n');
    const glued: string[] = [];
    for (let i = 1; i < lines.length; i++) {
      if (!lines[i].startsWith('**')) continue;
      const prev = lines[i - 1];
      if (prev.trim() === '' || prev.startsWith('#')) continue;
      glued.push(`CHANGELOG.md:${i + 1}: ${lines[i]}`);
    }
    expect(glued).toEqual([]);
  });
});
