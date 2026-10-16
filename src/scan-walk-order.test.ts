import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from './commands/core';
import { scan, newScanStats } from './scan';

/**
 * The walk visits each directory's entries in sorted order, whatever order
 * `readdir` hands them back in.
 *
 * The samples of what was not opened, and the `Scan one:` command under each,
 * are the first entries the walk meets. Node documents no order for `readdir`:
 * it returns byte order on macOS and Linux only because its I/O layer sorts,
 * while the filesystems underneath return hash order. A walk that took the
 * order it was given printed whichever entries came first there.
 *
 * The stand-in below returns each listing reversed, a `readdir` whose order
 * differs from sorted order, and the tests pin the sorted result.
 */
const order = vi.hoisted(() => ({ reversed: false }));

vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof import('fs')>('fs');
  const readdirSync = actual.readdirSync as (...args: unknown[]) => unknown[];
  return {
    ...actual,
    readdirSync: (...args: unknown[]) => {
      const entries = readdirSync(...args);
      return order.reversed ? [...entries].reverse() : entries;
    },
  };
});

function tree(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'walk-order-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

const MIXED = {
  'src/app.ts': 'export const x = 1;\n',
  'zeta.txt': 'z\n',
  'alpha.txt': 'a\n',
  'Mike.txt': 'm\n',
  'beta.txt': 'b\n',
  'zeta/.cache/z.ts': 'export {};\n',
  'alpha/.cache/a.ts': 'export {};\n',
};

describe('the walk visits each directory in sorted order', () => {
  afterEach(() => {
    order.reversed = false;
    vi.restoreAllMocks();
  });

  async function json(dir: string, reversed: boolean) {
    order.reversed = reversed;
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    await runScan(dir, { json: true });
    vi.restoreAllMocks();
    return JSON.parse(lines.join('\n'));
  }

  async function human(dir: string, reversed: boolean) {
    order.reversed = reversed;
    // From the directory above the tree a printed path reads `<tree>/<name>`.
    // From anywhere else it is absolute, and under a TMPDIR with a space in it
    // an absolute path prints shell-quoted, which `\S+` below does not match.
    vi.spyOn(process, 'cwd').mockReturnValue(path.dirname(dir));
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await runScan(dir);
    vi.restoreAllMocks();
    // eslint-disable-next-line no-control-regex
    return lines.join('\n').replace(/\x1b\[[0-9;]*m/g, '');
  }

  it('lists the samples in sorted order when readdir returns them unsorted', async () => {
    const dir = tree(MIXED);
    const doc = await json(dir, true);
    expect(doc.skippedUnsupportedFiles.map((f: { path: string }) => f.path))
      .toEqual(['Mike.txt', 'alpha.txt', 'beta.txt', 'zeta.txt']);
    expect(doc.notEnteredDirs.map((d: { path: string }) => d.path))
      .toEqual(['alpha/.cache', 'zeta/.cache']);
  });

  it('keeps the same capped sample: the first twenty in sorted order', async () => {
    const files: Record<string, string> = { 'src/app.ts': 'export const x = 1;\n' };
    const names = Array.from({ length: 25 }, (_, i) => `f${String(i).padStart(2, '0')}.txt`);
    for (const n of names) files[n] = 'x\n';
    const doc = await json(tree(files), true);
    expect(doc.summary.skippedUnsupported).toBe(25);
    expect(doc.skippedUnsupportedFiles.map((f: { path: string }) => f.path)).toEqual(names.slice(0, 20));
  });

  it('prints the same report and `Scan one:` targets under either readdir order', async () => {
    const dir = tree(MIXED);
    const asListed = await human(dir, false);
    const reversed = await human(dir, true);
    expect(reversed).toBe(asListed);

    const targets = [...reversed.matchAll(/Scan one: npx secretless-ai scan (\S+)/g)].map(m => m[1]);
    expect(targets).toHaveLength(2);
    expect(targets[0].replace(/\\/g, '/')).toMatch(/\/alpha\/\.cache$/);
    expect(path.basename(targets[1])).toBe('Mike.txt');
  });

  it('orders names by code point, the byte order of their UTF-8 form', async () => {
    // UTF-16 comparison puts the emoji (a surrogate pair) before U+FF21; byte
    // order, and code point order, put it after.
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      '\u{1F600}.txt': 'x\n',
      '\uFF21.txt': 'x\n',
    });
    const doc = await json(dir, true);
    expect(doc.skippedUnsupportedFiles.map((f: { path: string }) => f.path))
      .toEqual(['\uFF21.txt', '\u{1F600}.txt']);
  });
});

/**
 * The source walk enters dot-directories after every other directory (#397).
 *
 * Before #144 it entered none. Once it did, a dot-directory sorted ahead of
 * `src/`, its files filled the cap first, and a capped scan dropped a finding
 * the previous release reported. The value below is legibly fake, so the
 * scanner holds it back as a placeholder; `showPlaceholders` reports it.
 */
describe('dot-directories reach the file cap last', () => {
  afterEach(() => {
    order.reversed = false;
  });

  const VALUE = ['sk-ant-api03-', 'FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12'].join('');
  const SECRET_LINE = `const k = "${VALUE}";\n`;

  function withDotFiles(dotDir: string, count: number, extra: Record<string, string>): string {
    const files: Record<string, string> = { ...extra };
    for (let i = 0; i < count; i++) files[`${dotDir}/f${i}.js`] = 'export const x = 1;\n';
    return tree(files);
  }

  function capped(dir: string, maxSourceFiles: number) {
    const stats = newScanStats();
    const findings = scan(dir, { scanGlobal: false, showPlaceholders: true, maxSourceFiles }, stats);
    return { files: findings.map((f) => f.file), stats };
  }

  for (const reversed of [false, true]) {
    const label = reversed ? 'readdir returns entries reversed' : 'readdir returns entries as listed';

    it(`reports the finding in zzz/app.ts when .foo/ alone exceeds the cap (${label})`, () => {
      order.reversed = reversed;
      const dir = withDotFiles('.foo', 5, { 'zzz/app.ts': SECRET_LINE });
      const { files, stats } = capped(dir, 3);
      expect(files).toEqual(['zzz/app.ts']);
      // The cap still stopped the walk: two .foo/ files were left unscanned.
      expect(stats.truncated).toBe(true);
      expect(stats.eligibleFiles).toBe(6);
    });

    it(`reads a deeper file outside dot-directories before a shallower dot-directory (${label})`, () => {
      order.reversed = reversed;
      const dir = withDotFiles('.foo', 5, { 'src/a/b/app.ts': SECRET_LINE });
      const { files, stats } = capped(dir, 3);
      expect(files).toEqual(['src/a/b/app.ts']);
      expect(stats.truncated).toBe(true);
      expect(stats.eligibleFiles).toBe(6);
    });

    it(`defers a nested dot-directory and everything under it (${label})`, () => {
      order.reversed = reversed;
      const dir = withDotFiles('pkg/.gen/code', 5, { 'pkg/z/y/app.ts': SECRET_LINE });
      const { files, stats } = capped(dir, 3);
      expect(files).toEqual(['pkg/z/y/app.ts']);
      expect(stats.truncated).toBe(true);
      expect(stats.eligibleFiles).toBe(6);
    });
  }

  it('still reads dot-directories when the cap leaves room', () => {
    const dir = withDotFiles('.foo', 5, {
      '.claude/agent.ts': SECRET_LINE,
      'zzz/app.ts': SECRET_LINE,
    });
    const { files, stats } = capped(dir, 5000);
    expect(files.sort()).toEqual(['.claude/agent.ts', 'zzz/app.ts']);
    expect(stats.truncated).toBe(false);
  });

  it('leaves the dot-directory file unscanned when files outside fill the cap', () => {
    const dir = tree({
      '.claude/agent.ts': SECRET_LINE,
      'src/app.ts': 'export const x = 1;\n',
    });
    const { files, stats } = capped(dir, 1);
    expect(files).toEqual([]);
    expect(stats.truncated).toBe(true);
    expect(stats.eligibleFiles).toBe(2);
  });
});
