import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from './commands/core';
import { ignorePattern } from './commands/ignore';
import { SOURCE_SKIP_REASONS } from './scan';

/**
 * A path the scanned tree's own `.secretlessignore` excluded is a coverage gap
 * (#414). The tree being judged wrote that rule, so a committed
 * `.secretlessignore` holding `*` printed "No hardcoded credentials found."
 * at exit 0 with every path listed only as a declared boundary. A path the
 * default-ignore list excludes stays a declared boundary.
 */

const made: string[] = [];
function tree(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ignore-gap-'));
  made.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

// Run from the directory above the scanned tree, so a printed path reads
// `<tree>/<name>` whatever the temporary directory's own path holds.
async function report(dir: string, options?: Parameters<typeof runScan>[1]) {
  vi.spyOn(process, 'cwd').mockReturnValue(path.dirname(dir));
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  const code = await runScan(dir, options);
  // eslint-disable-next-line no-control-regex
  return { text: lines.join('\n').replace(/\x1b\[[0-9;]*m/g, ''), code };
}

async function scanned(dir: string, options?: Parameters<typeof runScan>[1]) {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  const code = await runScan(dir, { ...options, json: true });
  return { doc: JSON.parse(lines.join('\n')), code };
}

const IGNORE_ALL = { '.secretlessignore': '*\n', 'app.js': 'const a = 1;\n', 'src/index.ts': 'export const b = 2;\n' };

describe('a path the scanned tree\'s own .secretlessignore excluded is a coverage gap (#414)', () => {
  it('a .secretlessignore holding * prints the gap headline, names the file and the count, and exits 1', async () => {
    const dir = tree(IGNORE_ALL);
    const base = path.basename(dir);
    const { text, code } = await report(dir);

    expect(text).toContain('No credentials found in the files scanned.');
    expect(text).not.toContain('No hardcoded credentials found.');
    expect(text).toContain(`  2 paths excluded by ${base}/.secretlessignore, so not known to be clean.`);
    expect(text).toContain(`  Verify: cat -v ${base}/.secretlessignore`);
    expect(text).toContain(`  Fix:    npx secretless-ai scan ${base} --no-ignore`);
    // The paths themselves are still listed with the ignore rule's reason.
    expect(text).toContain(`    ${base}/src: ${SOURCE_SKIP_REASONS.ignoreRule}`);
    expect(text).toContain(`    ${base}/app.js: ${SOURCE_SKIP_REASONS.ignoreRule}`);
    expect(code).toBe(1);
  });

  it('--json carries the count in summary.ignoreFileExcluded and exits 1', async () => {
    const { doc, code } = await scanned(tree(IGNORE_ALL));

    expect(doc.summary.total).toBe(0);
    expect(doc.summary.ignoreFileExcluded).toBe(2);
    expect(code).toBe(1);
  });

  it('the Fix, --no-ignore, reads those paths and the scan reports clean', async () => {
    const dir = tree(IGNORE_ALL);
    const { text, code } = await report(dir, { noIgnore: true });
    expect(text).toContain('No hardcoded credentials found.');
    expect(text).not.toContain('excluded by');
    expect(code).toBe(0);

    vi.restoreAllMocks();
    const json = await scanned(dir, { noIgnore: true });
    expect(json.doc.summary.ignoreFileExcluded).toBe(0);
    expect(json.code).toBe(0);
  });

  it('CONTROL: the same files without the ignore file report clean at exit 0', async () => {
    const { text, code } = await report(tree({ 'app.js': IGNORE_ALL['app.js'], 'src/index.ts': IGNORE_ALL['src/index.ts'] }));
    expect(text).toContain('No hardcoded credentials found.');
    expect(text).not.toContain('excluded by');
    expect(code).toBe(0);
  });

  it('says "1 path" for one excluded path', async () => {
    const dir = tree({ '.secretlessignore': 'skip-me.js\n', 'app.js': 'const a = 1;\n', 'skip-me.js': 'const b = 2;\n' });
    const { text, code } = await report(dir);
    expect(text).toContain(`  1 path excluded by ${path.basename(dir)}/.secretlessignore, so not known to be clean.`);
    expect(code).toBe(1);
  });

  it('a directory the default-ignore list excludes stays a declared boundary at exit 0', async () => {
    const dir = tree({ 'app.js': 'const a = 1;\n', 'examples/demo.js': 'const d = 1;\n' });
    const { text, code } = await report(dir);
    expect(text).toContain(`    ${path.basename(dir)}/examples: ${SOURCE_SKIP_REASONS.ignoreRule}`);
    expect(text).toContain('No hardcoded credentials found.');
    expect(text).not.toContain('excluded by');
    expect(code).toBe(0);

    vi.restoreAllMocks();
    const json = await scanned(dir);
    expect(json.doc.summary.ignoreFileExcluded).toBe(0);
    expect(json.code).toBe(0);
  });

  it('a .secretlessignore line the default-ignore list also holds is not counted', async () => {
    const dir = tree({ '.secretlessignore': 'examples/\n', 'app.js': 'const a = 1;\n', 'examples/demo.js': 'const d = 1;\n' });
    const { doc, code } = await scanned(dir);
    expect(doc.summary.ignoreFileExcluded).toBe(0);
    expect(code).toBe(0);
  });

  it('a .secretlessignore whose rules match no path in the tree is not a gap', async () => {
    const dir = tree({ '.secretlessignore': 'dist/\n', 'app.js': 'const a = 1;\n' });
    const { text, code } = await report(dir);
    expect(text).toContain('No hardcoded credentials found.');
    expect(code).toBe(0);
  });

  it('counts a config file the config walk reads by name, and lists it with the ignore rule\'s reason', async () => {
    const dir = tree({ '.secretlessignore': '.env\n', '.env': 'NODE_ENV=production\n', 'app.js': 'const a = 1;\n' });
    const base = path.basename(dir);
    const { text, code } = await report(dir);
    expect(text).toContain(`  1 path excluded by ${base}/.secretlessignore, so not known to be clean.`);
    expect(text).toContain(`    ${base}/.env: ${SOURCE_SKIP_REASONS.ignoreRule}`);
    expect(text).not.toContain(`${base}/.env: ${SOURCE_SKIP_REASONS.unsupportedType}`);
    expect(code).toBe(1);
  });

  it('CONTROL: without the ignore file that config file is read, so it is not listed', async () => {
    const dir = tree({ '.env': 'NODE_ENV=production\n', 'app.js': 'const a = 1;\n' });
    const { text, code } = await report(dir);
    expect(text).not.toContain(`${path.basename(dir)}/.env:`);
    expect(code).toBe(0);
  });

  it('with --include-tests, a test directory the ignore file names is counted; without it, the test rule skips it first', async () => {
    const dir = tree({ '.secretlessignore': 'test/\n', 'app.js': 'const a = 1;\n', 'test/a.js': 'const t = 1;\n' });

    const withTests = await scanned(dir, { includeTests: true });
    expect(withTests.doc.summary.ignoreFileExcluded).toBe(1);
    expect(withTests.code).toBe(1);

    vi.restoreAllMocks();
    const without = await scanned(dir);
    expect(without.doc.summary.ignoreFileExcluded).toBe(0);
    expect(without.doc.notEnteredDirs).toEqual([{ path: 'test', reason: SOURCE_SKIP_REASONS.testDir }]);
    expect(without.code).toBe(0);
  });
});

describe('the gap names `secretless-ai ignore` when the ignore file starts with the header it writes', () => {
  const WRITER_LINE = '  Its rules come from the tree being scanned (written by secretless-ai ignore), not from this scanner.';
  const PLAIN_LINE = '  Its rules come from the tree being scanned, not from this scanner.';
  // The header `ignore` wrote before it cited https://opena2a.org/secretless.
  const PRIOR_HEADER = [
    '# .secretlessignore',
    '# gitignore-style globs for paths the secret scanner should skip.',
    '# Lines starting with `!` re-include a previously ignored path.',
    '# See https://opena2a.org/secretless-ai for syntax.',
    '',
  ].join('\n');
  const FILES = { 'app.js': 'const a = 1;\n', 'skip-me.js': 'const b = 2;\n' };

  it('a file `ignore` created', async () => {
    const dir = tree(FILES);
    expect(ignorePattern('skip-me.js', { rootDir: dir }).exitCode).toBe(0);

    const { text, code } = await report(dir);

    expect(text).toContain(`  1 path excluded by ${path.basename(dir)}/.secretlessignore, so not known to be clean.`);
    expect(text).toContain(WRITER_LINE);
    expect(text).not.toContain(PLAIN_LINE);
    expect(code).toBe(1);
  });

  it('a file an earlier `ignore` created, under the header it wrote then', async () => {
    const { text, code } = await report(tree({ ...FILES, '.secretlessignore': `${PRIOR_HEADER}skip-me.js\n` }));

    expect(text).toContain(WRITER_LINE);
    expect(code).toBe(1);
  });

  it('a file checked out with CRLF line endings', async () => {
    const dir = tree(FILES);
    expect(ignorePattern('skip-me.js', { rootDir: dir }).exitCode).toBe(0);
    const file = path.join(dir, '.secretlessignore');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf-8').replace(/\n/g, '\r\n'));

    expect((await report(dir)).text).toContain(WRITER_LINE);
  });

  it('CONTROL: a file without the header names no writer', async () => {
    const { text, code } = await report(tree(IGNORE_ALL));

    expect(text).toContain(PLAIN_LINE);
    expect(text).not.toContain('written by');
    expect(code).toBe(1);
  });

  it('CONTROL: the header below a rule is not the header `ignore` writes', async () => {
    const { text, code } = await report(tree({ ...FILES, '.secretlessignore': `skip-me.js\n${PRIOR_HEADER}` }));

    expect(text).toContain(PLAIN_LINE);
    expect(text).not.toContain('written by');
    expect(code).toBe(1);
  });
});
