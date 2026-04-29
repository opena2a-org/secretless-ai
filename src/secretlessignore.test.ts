import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  buildMatcher,
  loadSecretlessIgnore,
  DEFAULT_IGNORE_PATTERNS,
} from './secretlessignore';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretlessignore-'));
}

describe('secretlessignore — defaults', () => {
  it('applies the default-ignore list to a fresh project', () => {
    const m = loadSecretlessIgnore(tmpDir());
    // Every default-ignore directory must match a file underneath it.
    expect(m.matches('test/fixtures/api.ts')).toBe(true);
    expect(m.matches('tests/foo.spec.ts')).toBe(true);
    expect(m.matches('__tests__/x.ts')).toBe(true);
    expect(m.matches('__fixtures__/y.ts')).toBe(true);
    expect(m.matches('test-server/agents.js')).toBe(true);
    expect(m.matches('docs/vhs/setup-lab.sh')).toBe(true);
    expect(m.matches('examples/index.ts')).toBe(true);
    expect(m.matches('e2e/login.spec.ts')).toBe(true);
    expect(m.matches('.golden/expected.json')).toBe(true);
    expect(m.matches('node_modules/foo/index.js')).toBe(true);
    expect(m.matches('dist/cli.js')).toBe(true);
    expect(m.matches('build/output.js')).toBe(true);
  });

  it('does not ignore source files outside the default list', () => {
    const m = loadSecretlessIgnore(tmpDir());
    expect(m.matches('src/scan.ts')).toBe(false);
    expect(m.matches('lib/client.ts')).toBe(false);
    expect(m.matches('CHANGELOG.md')).toBe(false);
  });

  it('skipDefaults disables the default-ignore list', () => {
    const m = loadSecretlessIgnore(tmpDir(), { skipDefaults: true });
    expect(m.matches('test/foo.ts')).toBe(false);
    expect(m.matches('docs/vhs/setup-lab.sh')).toBe(false);
    expect(m.patternCount).toBe(0);
  });

  it('exports the documented default-ignore list', () => {
    expect(DEFAULT_IGNORE_PATTERNS).toContain('test/');
    expect(DEFAULT_IGNORE_PATTERNS).toContain('docs/vhs/');
    expect(DEFAULT_IGNORE_PATTERNS.length).toBeGreaterThanOrEqual(10);
  });
});

describe('secretlessignore — user file', () => {
  it('user patterns add to defaults', () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, '.secretlessignore'), 'private-fixtures/\n');
    const m = loadSecretlessIgnore(dir);
    expect(m.matches('private-fixtures/secret.txt')).toBe(true);
    // Defaults still apply.
    expect(m.matches('test/foo.ts')).toBe(true);
  });

  it('user comments and blank lines are skipped', () => {
    const dir = tmpDir();
    fs.writeFileSync(
      path.join(dir, '.secretlessignore'),
      [
        '# A comment',
        '',
        '# Another comment',
        'private/',
      ].join('\n'),
    );
    const m = loadSecretlessIgnore(dir);
    expect(m.matches('private/x.ts')).toBe(true);
    expect(m.matches('src/x.ts')).toBe(false);
  });

  it('negation re-enables default-ignored paths', () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, '.secretlessignore'), '!docs/vhs/\n');
    const m = loadSecretlessIgnore(dir);
    expect(m.matches('docs/vhs/setup-lab.sh')).toBe(false);
  });

  it('falls back silently when the ignore file is unreadable', () => {
    const dir = tmpDir();
    // Write a binary blob exceeding 1MB cap.
    const big = Buffer.alloc(2 * 1024 * 1024, 0);
    fs.writeFileSync(path.join(dir, '.secretlessignore'), big);
    const m = loadSecretlessIgnore(dir);
    // Defaults still apply (the file is ignored — too large).
    expect(m.matches('test/x.ts')).toBe(true);
  });
});

describe('secretlessignore — glob semantics', () => {
  it('* matches within a path segment', () => {
    const m = buildMatcher(['*.tmp']);
    expect(m.matches('foo.tmp')).toBe(true);
    expect(m.matches('a/b/foo.tmp')).toBe(true);
    expect(m.matches('foo.txt')).toBe(false);
  });

  it('** matches across path segments', () => {
    const m = buildMatcher(['fixtures/**/secret.json']);
    expect(m.matches('fixtures/secret.json')).toBe(true);
    expect(m.matches('fixtures/a/secret.json')).toBe(true);
    expect(m.matches('fixtures/a/b/c/secret.json')).toBe(true);
    expect(m.matches('other/secret.json')).toBe(false);
  });

  it('? matches one character', () => {
    const m = buildMatcher(['file?.txt']);
    expect(m.matches('file1.txt')).toBe(true);
    expect(m.matches('file12.txt')).toBe(false);
  });

  it('leading slash anchors to root', () => {
    const m = buildMatcher(['/build/']);
    expect(m.matches('build/x.js')).toBe(true);
    expect(m.matches('a/build/x.js')).toBe(false);
  });

  it('a pattern with internal slash anchors to root by default', () => {
    const m = buildMatcher(['docs/vhs/']);
    expect(m.matches('docs/vhs/x.sh')).toBe(true);
    // gitignore semantics: `docs/vhs/` does NOT match nested `lib/docs/vhs/x`.
    expect(m.matches('lib/docs/vhs/x.sh')).toBe(false);
  });

  it('a pattern without a slash matches at any depth', () => {
    const m = buildMatcher(['__tests__/']);
    expect(m.matches('__tests__/x.ts')).toBe(true);
    expect(m.matches('packages/foo/__tests__/x.ts')).toBe(true);
  });

  it('Windows backslashes normalize to forward slashes', () => {
    const m = buildMatcher(['test/']);
    expect(m.matches('test\\foo.ts')).toBe(true);
  });

  it('rejects path traversal in input', () => {
    const m = buildMatcher(['test/']);
    expect(m.matches('../test/secret.txt')).toBe(false);
  });

  it('rejects path traversal in pattern', () => {
    const m = buildMatcher(['../foo/']);
    // Pattern was discarded; nothing matches.
    expect(m.matches('foo/x.ts')).toBe(false);
    expect(m.patternCount).toBe(0);
  });

  it('handles trailing-slash-only directories correctly', () => {
    const m = buildMatcher(['secrets/']);
    // The directory itself is ignored (anything below).
    expect(m.matches('secrets/api-key')).toBe(true);
    // A file literally named `secrets` (no trailing slash) is NOT ignored.
    expect(m.matches('secrets')).toBe(false);
  });
});
