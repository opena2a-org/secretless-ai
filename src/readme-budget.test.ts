import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * The README is the page a visitor reads before installing, and the budget for
 * a CLI README is under 400 lines: reference detail goes under docs/ with a
 * link from the README. The scan coverage and flag-refusal reference moved to
 * docs/scanning.md when the README reached 417 lines. A move leaves links
 * behind, so every relative link and anchor in the README and docs/ is
 * checked against the file and heading it names.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const README_PATH = path.join(REPO_ROOT, 'README.md');
const README_LINE_BUDGET = 400;

const FENCE = /^\s*(```|~~~)/;

/** Markdown the project publishes to users: the README and everything under docs/. */
function publishedMarkdown(): string[] {
  const files = [README_PATH];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.md')) files.push(full);
    }
  };
  walk(path.join(REPO_ROOT, 'docs'));
  return files;
}

/** Lines outside fenced code blocks, with their 1-based line numbers. */
function proseLines(text: string): Array<[number, string]> {
  const out: Array<[number, string]> = [];
  let inFence = false;
  text.split('\n').forEach((line, i) => {
    if (FENCE.test(line)) { inFence = !inFence; return; }
    if (!inFence) out.push([i + 1, line]);
  });
  return out;
}

/** GitHub's anchor for a heading: lowercase, punctuation dropped, spaces to hyphens. */
function headingAnchor(text: string): string {
  return text.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
}

/** Every anchor GitHub generates for a file's headings, numbering repeats as it does. */
function anchorsOf(file: string): Set<string> {
  const seen = new Map<string, number>();
  const anchors = new Set<string>();
  for (const [, line] of proseLines(fs.readFileSync(file, 'utf-8'))) {
    const h = line.match(/^#{1,6}\s+(.+?)\s*#*\s*$/);
    if (!h) continue;
    const base = headingAnchor(h[1]);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    anchors.add(n === 0 ? base : `${base}-${n}`);
  }
  return anchors;
}

/** Relative link targets on a line; code spans are dropped so `[a](b)` in code is not a link. */
function relativeLinks(line: string): string[] {
  const text = line.replace(/`[^`]*`/g, '');
  const targets: string[] = [];
  for (const m of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(m[1])) continue; // https:, mailto: and other schemes
    targets.push(m[1]);
  }
  return targets;
}

describe('README length budget', () => {
  it(`README.md is under ${README_LINE_BUDGET} lines`, () => {
    // Counted the way `wc -l` counts: newline characters.
    const lines = (fs.readFileSync(README_PATH, 'utf-8').match(/\n/g) ?? []).length;
    expect(
      lines,
      `README.md is ${lines} lines; the budget for a CLI README is under ${README_LINE_BUDGET}. ` +
        'Move reference detail to a page under docs/ and link it from the README.',
    ).toBeLessThan(README_LINE_BUDGET);
  });

  it('the scan coverage reference is under docs/ and the README links to it', () => {
    expect(fs.existsSync(path.join(REPO_ROOT, 'docs', 'scanning.md'))).toBe(true);
    const readme = fs.readFileSync(README_PATH, 'utf-8');
    expect(readme).toContain('](docs/scanning.md)');
    expect(readme).toContain('](docs/scanning.md#what-a-directory-scan-opens)');
  });
});

describe('relative links in published markdown resolve', () => {
  const files = publishedMarkdown();

  it('finds the README and the pages under docs/', () => {
    // Guard against the walk matching nothing, which would make the check below vacuous.
    expect(files).toContain(README_PATH);
    expect(files).toContain(path.join(REPO_ROOT, 'docs', 'scanning.md'));
  });

  it('every relative link names a file that exists and a heading that file has', () => {
    const broken: string[] = [];
    for (const file of files) {
      const where = path.relative(REPO_ROOT, file);
      for (const [n, line] of proseLines(fs.readFileSync(file, 'utf-8'))) {
        for (const target of relativeLinks(line)) {
          const hash = target.indexOf('#');
          const rel = hash === -1 ? target : target.slice(0, hash);
          const anchor = hash === -1 ? '' : decodeURIComponent(target.slice(hash + 1));
          const dest = rel === '' ? file : path.resolve(path.dirname(file), decodeURIComponent(rel));
          if (!fs.existsSync(dest)) {
            broken.push(`${where}:${n}: ${target} — no such file`);
            continue;
          }
          if (anchor && dest.endsWith('.md') && !anchorsOf(dest).has(anchor)) {
            broken.push(`${where}:${n}: ${target} — ${path.relative(REPO_ROOT, dest)} has no heading #${anchor}`);
          }
        }
      }
    }
    expect(broken).toEqual([]);
  });
});
