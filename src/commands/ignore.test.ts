/**
 * Tests for src/commands/ignore.ts — the `secretless-ai ignore <path>`
 * subcommand. Covers idempotence, traversal rejection, file creation,
 * append behaviour, glob normalisation, and symlink rejection.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ignorePattern, runIgnore } from './ignore';
import { runScan } from './core';
import { printCommandHelp } from '../command-help';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-ignore-test-'));
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('ignorePattern (file creation)', () => {
  it('creates .secretlessignore with header when file does not exist', () => {
    const r = ignorePattern('docs/migration-guide.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.created).toBe(true);
    const content = fs.readFileSync(path.join(tmpDir, '.secretlessignore'), 'utf-8');
    expect(content).toContain('# .secretlessignore');
    expect(content).toContain('docs/migration-guide.md');
  });

  it('SLS-07.AC2 header cites https://opena2a.org/secretless, no line names secretless-ai', () => {
    // The old `/secretless-ai` docs path is a 404; the syntax docs live at
    // https://opena2a.org/secretless.
    const r = ignorePattern('docs/migration-guide.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(0);
    const content = fs.readFileSync(path.join(tmpDir, '.secretlessignore'), 'utf-8');
    const lines = content.split('\n');
    expect(lines).toContain('# See https://opena2a.org/secretless for syntax.');
    expect(lines.filter((l) => l.includes('secretless-ai'))).toEqual([]);
  });
});

describe('ignorePattern (append behaviour)', () => {
  it('appends to an existing file (no header rewrite)', () => {
    const filePath = path.join(tmpDir, '.secretlessignore');
    fs.writeFileSync(filePath, '# user header\nfirst.md\n', 'utf-8');
    const r = ignorePattern('second.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.created).toBe(false);
    const content = fs.readFileSync(filePath, 'utf-8');
    expect(content).toBe('# user header\nfirst.md\nsecond.md\n');
  });

  it('appends a trailing newline if the existing file did not end in one', () => {
    const filePath = path.join(tmpDir, '.secretlessignore');
    fs.writeFileSync(filePath, 'first.md', 'utf-8');  // no \n at end
    const r = ignorePattern('second.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(0);
    const content = fs.readFileSync(filePath, 'utf-8');
    expect(content).toBe('first.md\nsecond.md\n');
  });
});

describe('ignorePattern (idempotence)', () => {
  it('is a no-op when the pattern is already present', () => {
    const filePath = path.join(tmpDir, '.secretlessignore');
    fs.writeFileSync(filePath, 'docs/foo.md\n', 'utf-8');
    const before = fs.readFileSync(filePath, 'utf-8');
    const r = ignorePattern('docs/foo.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.alreadyPresent).toBe(true);
    const after = fs.readFileSync(filePath, 'utf-8');
    expect(after).toBe(before);
  });

  it('detects exact-line match (does not double-append on whitespace match)', () => {
    const filePath = path.join(tmpDir, '.secretlessignore');
    fs.writeFileSync(filePath, '   docs/foo.md   \n', 'utf-8');
    const r = ignorePattern('docs/foo.md', { rootDir: tmpDir });
    expect(r.alreadyPresent).toBe(true);
  });
});

describe('ignorePattern (path normalisation)', () => {
  it('strips leading ./', () => {
    const r = ignorePattern('./docs/foo.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.pattern).toBe('docs/foo.md');
  });

  it('converts backslashes to forward slashes', () => {
    const r = ignorePattern('docs\\vhs\\setup.sh', { rootDir: tmpDir });
    expect(r.exitCode).toBe(0);
    expect(r.pattern).toBe('docs/vhs/setup.sh');
  });

  it('treats different normalisation forms as the same pattern (idempotence)', () => {
    ignorePattern('docs/foo.md', { rootDir: tmpDir });
    const second = ignorePattern('./docs/foo.md', { rootDir: tmpDir });
    expect(second.alreadyPresent).toBe(true);
  });
});

describe('ignorePattern (path traversal rejection)', () => {
  it('rejects ../foo (relative parent traversal)', () => {
    const r = ignorePattern('../etc/passwd', { rootDir: tmpDir });
    expect(r.exitCode).toBe(1);
    expect(r.message).toContain('Invalid pattern');
  });

  it('rejects /etc/passwd (absolute Unix path)', () => {
    const r = ignorePattern('/etc/passwd', { rootDir: tmpDir });
    expect(r.exitCode).toBe(1);
  });

  it('rejects C:/Windows/System32 (absolute Windows drive prefix)', () => {
    const r = ignorePattern('C:/Windows/System32', { rootDir: tmpDir });
    expect(r.exitCode).toBe(1);
  });

  it('rejects empty input', () => {
    const r = ignorePattern('   ', { rootDir: tmpDir });
    expect(r.exitCode).toBe(1);
  });

  it('rejects nested .. segment', () => {
    const r = ignorePattern('docs/../../etc/passwd', { rootDir: tmpDir });
    expect(r.exitCode).toBe(1);
  });

  it('rejects path that resolves outside repo root via symlink-style traversal', () => {
    // Even though the pattern is "syntactically valid", it would resolve
    // outside the repo root via a real-FS resolve.
    const r = ignorePattern('../sibling/file', { rootDir: tmpDir });
    expect(r.exitCode).toBe(1);
  });
});

describe('ignorePattern (glob patterns)', () => {
  it('accepts an explicit glob via isExplicitPattern', () => {
    const r = ignorePattern('*.golden.txt', { rootDir: tmpDir, isExplicitPattern: true });
    expect(r.exitCode).toBe(0);
    expect(r.pattern).toBe('*.golden.txt');
  });

  it('accepts ** double-star globs', () => {
    const r = ignorePattern('**/__fixtures__/**', { rootDir: tmpDir, isExplicitPattern: true });
    expect(r.exitCode).toBe(0);
  });

  it('rejects an explicit glob that contains ..', () => {
    const r = ignorePattern('../*.txt', { rootDir: tmpDir, isExplicitPattern: true });
    expect(r.exitCode).toBe(1);
  });
});

describe('ignorePattern (symlink rejection)', () => {
  it('refuses to write through a symlink at .secretlessignore', () => {
    // Create a real target file outside the temp dir, then symlink the
    // .secretlessignore path to it. The runner must refuse rather than
    // overwrite the target.
    const target = path.join(tmpDir, 'real-target.txt');
    fs.writeFileSync(target, 'do not overwrite\n', 'utf-8');
    const linkPath = path.join(tmpDir, '.secretlessignore');
    try {
      fs.symlinkSync(target, linkPath);
    } catch {
      // Symlink creation may fail on systems without privilege; skip.
      return;
    }
    const r = ignorePattern('safe.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(2);
    expect(r.message).toContain('symlink');
    // Target untouched.
    expect(fs.readFileSync(target, 'utf-8')).toBe('do not overwrite\n');
  });
});

describe('ignorePattern (size cap)', () => {
  it('refuses to mutate a .secretlessignore over 1MB', () => {
    const filePath = path.join(tmpDir, '.secretlessignore');
    // 1MB + 1 byte.
    fs.writeFileSync(filePath, 'a'.repeat(1024 * 1024 + 1), 'utf-8');
    const r = ignorePattern('safe.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(2);
    expect(r.message).toContain('1MB');
  });
});

describe('ignorePattern (refuses non-file)', () => {
  it('refuses to write when the path is a directory', () => {
    const dirPath = path.join(tmpDir, '.secretlessignore');
    fs.mkdirSync(dirPath);
    const r = ignorePattern('safe.md', { rootDir: tmpDir });
    expect(r.exitCode).toBe(2);
  });
});

describe('runIgnore says what scan does with the line it wrote', () => {
  // `scan` reports a path the scanned tree's own `.secretlessignore` kept it
  // from reading as excluded, a gap that exits 1 (#414), so ignoring the path
  // a finding is on cannot make a scan pass. `ignore` printed only
  // `Verify: secretless-ai scan`, and the scan after it exited 1 with nothing
  // having said it would.
  let cwd: string;
  let out: string[];
  let err: string[];

  beforeEach(() => {
    cwd = process.cwd();
    process.chdir(tmpDir);
    out = [];
    err = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
  });

  afterEach(() => {
    process.chdir(cwd);
    vi.restoreAllMocks();
  });

  /** The exit code and `summary.ignoreFileExcluded` of `scan --json` over the temporary tree. */
  async function scanned(): Promise<{ code: number; ignoreFileExcluded: number }> {
    out.length = 0;
    const code = await runScan(tmpDir, { json: true });
    return { code, ignoreFileExcluded: JSON.parse(out.join('\n')).summary.ignoreFileExcluded };
  }

  it('a path scan reads: says scan keeps exiting 1 for it, names the command that reads it, and scan does exit 1', async () => {
    fs.mkdirSync(path.join(tmpDir, 'src'));
    fs.writeFileSync(path.join(tmpDir, 'src', 'data.js'), 'module.exports = 1;\n');

    expect(runIgnore(['src/data.js'])).toBe(0);

    expect(out).toEqual([
      '  Created .secretlessignore with "src/data.js".',
      '  Skipped from now on, and listed as excluded: scan keeps exiting 1 for it,',
      '  because an excluded path is not known to be clean.',
      '  Read it anyway: secretless-ai scan --no-ignore',
      '  Verify: secretless-ai scan',
    ]);
    expect(await scanned()).toEqual({ code: 1, ignoreFileExcluded: 1 });
  });

  it('appending to an existing file says the same', () => {
    fs.writeFileSync(path.join(tmpDir, '.secretlessignore'), 'other.js\n');
    fs.writeFileSync(path.join(tmpDir, 'app.js'), 'module.exports = 1;\n');

    expect(runIgnore(['app.js'])).toBe(0);

    expect(out[0]).toBe('  Added "app.js" to .secretlessignore.');
    expect(out).toContain('  Skipped from now on, and listed as excluded: scan keeps exiting 1 for it,');
    expect(out).toContain('  Read it anyway: secretless-ai scan --no-ignore');
  });

  // The two lines docs/commands.md showed: scan opens no `.txt` file and no
  // `.md` file outside its config names, so neither line changes what it reads.
  it.each([
    { args: ['--pattern', '*.golden.txt'], file: 'expected.golden.txt' },
    { args: ['docs/migration.md'], file: 'docs/migration.md' },
  ])('a line that matches no path scan reads ($args) claims no exit 1, and scan exits 1 for none', async ({ args, file }) => {
    fs.mkdirSync(path.dirname(path.join(tmpDir, file)), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, file), 'notes\n');
    fs.writeFileSync(path.join(tmpDir, 'app.js'), 'module.exports = 1;\n');

    expect(runIgnore(args)).toBe(0);

    expect(out).toEqual([
      `  Created .secretlessignore with "${args[args.length - 1]}".`,
      '  No path counts as excluded by this line, so scan does not exit 1 for it.',
      '  Verify: secretless-ai scan',
    ]);
    expect((await scanned()).ignoreFileExcluded).toBe(0);
  });

  it('a line the default-ignore list already covers claims no exit 1', () => {
    fs.mkdirSync(path.join(tmpDir, 'examples'));
    fs.writeFileSync(path.join(tmpDir, 'examples', 'demo.js'), 'module.exports = 1;\n');

    expect(runIgnore(['examples/demo.js'])).toBe(0);

    expect(out).toContain('  No path counts as excluded by this line, so scan does not exit 1 for it.');
    expect(out.join('\n')).not.toContain('exiting 1');
  });

  it('a ! line re-includes what it matches, so it makes neither claim', () => {
    expect(runIgnore(['--pattern', '!docs/vhs/'])).toBe(0);

    expect(out).toEqual([
      '  Created .secretlessignore with "!docs/vhs/".',
      '  Verify: secretless-ai scan',
    ]);
  });

  it('a line already present writes nothing and makes no claim', () => {
    fs.writeFileSync(path.join(tmpDir, '.secretlessignore'), 'app.js\n');
    fs.writeFileSync(path.join(tmpDir, 'app.js'), 'module.exports = 1;\n');

    expect(runIgnore(['app.js'])).toBe(0);

    expect(out).toEqual(['  Pattern "app.js" already in .secretlessignore. No change.']);
  });

  it('the usage text says the scanner reports the path as excluded (exit 1)', () => {
    expect(runIgnore([])).toBe(1);

    expect(err).toEqual([
      '  Usage: secretless-ai ignore <path>',
      '         secretless-ai ignore --pattern <glob>',
      '',
      '  Appends a gitignore-style glob to .secretlessignore so the',
      '  scanner skips that path and reports it as excluded (exit 1).',
    ]);
  });

  it('`ignore --help` says the same in its summary', () => {
    printCommandHelp('ignore');

    expect(out.join('\n').split('\n')).toContain(
      '  Append a path or glob to .secretlessignore, so the scanner skips that path and reports it as excluded (exit 1).',
    );
  });
});
