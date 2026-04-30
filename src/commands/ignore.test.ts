/**
 * Tests for src/commands/ignore.ts — the `secretless-ai ignore <path>`
 * subcommand. Covers idempotence, traversal rejection, file creation,
 * append behaviour, glob normalisation, and symlink rejection.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ignorePattern } from './ignore';

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
