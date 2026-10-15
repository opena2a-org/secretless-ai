import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  scan,
  emptySkips,
  isEnvFile,
  SOURCE_SKIP_REASONS,
  HIDDEN_CACHE_DIRS,
  WORKTREE_DIRS,
  TEST_DIRS,
  TEST_FILE_GLOBS,
  KEY_FILE_EXTENSIONS,
  type ScanStats,
} from './scan';
import {
  CONFIG_FILES,
  CONFIG_SHAPED_BASENAMES,
  CONFIG_SHAPED_EXTENSIONS,
  SOURCE_FILE_EXTENSIONS,
  SOURCE_SKIP_DIRS,
} from './patterns';
import { printCommandHelp } from './command-help';

/**
 * `scan --help` names what a directory scan does not open, and the reasons it
 * names are the reasons the walk reports.
 *
 * The help named only dependency and build output as unread, while the scan
 * prints one of several reasons beside each path it skipped. The help now
 * lists what the walk opens, every skip reason, and that naming a file scans
 * it. These tests pin it to the walk in
 * both directions: a tree built to trigger every skip produces exactly the
 * reasons in SOURCE_SKIP_REASONS, each list the help prints under a reason is
 * skipped with that reason, and the help names every reason and list entry.
 */

const TOKEN = ['ghp_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');

const made: string[] = [];

function tree(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-help-'));
  made.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

function freshStats(): ScanStats {
  return { placeholdersSuppressed: 0, truncated: false, unreadable: [], outOfRoot: [], oversize: [], skips: emptySkips() };
}

/** Walk `dir` and return each skipped path with the reason the scan gives for it. */
function skipped(dir: string): Record<string, string> {
  const stats = freshStats();
  scan(dir, { scanGlobal: false }, stats);
  const out: Record<string, string> = {};
  for (const s of [...stats.skips!.dirs, ...stats.skips!.files]) out[s.path] = s.reason;
  return out;
}

function helpText(): string {
  const out: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  try {
    printCommandHelp('scan');
  } finally {
    spy.mockRestore();
  }
  return out.join('\n');
}

/** `*.test.*` -> `app.test.ts`, `test_*` -> `test_app.ts`, `*_test.go` -> `app_test.go`. */
function exampleFor(glob: string): string {
  const tail = glob.endsWith('.*') ? 'ts' : 'app.ts';
  return glob.replace(/\*$/, tail).replace(/\*/g, 'app');
}

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

describe('the walk reports exactly the skip reasons scan --help explains', () => {
  // A directory with no permissions is readable to root, so the reason for one
  // this user cannot open is not produced there.
  it.skipIf(process.getuid?.() === 0)('a tree that triggers every skip produces each catalogued reason, and no other', () => {
    const dir = tree({
      'src/app.ts': 'export const ok = 1;\n',
      'notes.txt': 'x\n',
      'notes.toml': 'x = 1\n',
      'app.test.ts': 'export const t = 1;\n',
      'test/a.ts': 'export const t = 1;\n',
      '.secretlessignore': 'ignored/\nskip-me.ts\n',
      'ignored/a.ts': 'export const t = 1;\n',
      'skip-me.ts': 'export const t = 1;\n',
      // Entered, so not listed (#144).
      '.claude/agent.ts': 'export const t = 1;\n',
      '.turbo/a.ts': 'export const t = 1;\n',
      '.worktrees/x/a.ts': 'export const t = 1;\n',
      'node_modules/pkg/index.js': 'module.exports = 1;\n',
      '.git/config': '[core]\n',
    });
    // The two hidden cache directories the key and config walks do not read
    // inside: a link out of the root, and one this user cannot open.
    fs.symlinkSync(tree({ 'settings.json': '{}\n' }), path.join(dir, '.cache'));
    const locked = path.join(dir, '.yarn');
    fs.mkdirSync(locked);
    fs.chmodSync(locked, 0o000);
    let reasons: Record<string, string>;
    try {
      reasons = skipped(dir);
    } finally {
      fs.chmodSync(locked, 0o755);
    }

    expect(reasons).toEqual({
      'notes.txt': SOURCE_SKIP_REASONS.unsupportedType,
      'notes.toml': SOURCE_SKIP_REASONS.configNotListed,
      '.secretlessignore': SOURCE_SKIP_REASONS.unsupportedType,
      'app.test.ts': SOURCE_SKIP_REASONS.testFile,
      'test': SOURCE_SKIP_REASONS.testDir,
      'ignored': SOURCE_SKIP_REASONS.ignoreRule,
      'skip-me.ts': SOURCE_SKIP_REASONS.ignoreRule,
      '.turbo': SOURCE_SKIP_REASONS.hiddenCache,
      '.worktrees': SOURCE_SKIP_REASONS.worktrees,
      '.cache': SOURCE_SKIP_REASONS.hiddenDirOutsideRoot,
      '.yarn': SOURCE_SKIP_REASONS.hiddenDirClosed,
      'node_modules': SOURCE_SKIP_REASONS.buildOutput,
      '.git': SOURCE_SKIP_REASONS.gitMetadata,
    });
    const seen = new Set(Object.values(reasons));
    expect([...seen].sort()).toEqual(Object.values(SOURCE_SKIP_REASONS).sort());
  });

  it.each(['notes.txt', 'README.md', 'report.ipynb', 'package-lock.json'])(
    'the help example %s is skipped as an unsupported file type',
    (name) => {
      const dir = tree({ [name]: 'x\n' });
      expect(skipped(dir)).toEqual({ [name]: SOURCE_SKIP_REASONS.unsupportedType });
    },
  );

  it.each([
    ...[...CONFIG_SHAPED_EXTENSIONS].map((ext) => `app${ext}`),
    ...CONFIG_SHAPED_BASENAMES,
    'Dockerfile.prod',
    'app.Dockerfile',
  ])('the help config-format file %s is skipped as a config file not on the built-in list', (name) => {
    const dir = tree({ [name]: 'x\n' });
    expect(skipped(dir)).toEqual({ [name]: SOURCE_SKIP_REASONS.configNotListed });
  });

  it.each(TEST_FILE_GLOBS.map((g) => [g, exampleFor(g)]))(
    'the help glob %s names a file the walk skips as a test file (%s)',
    (_glob, name) => {
      const dir = tree({ [name]: 'export const t = 1;\n' });
      expect(skipped(dir)).toEqual({ [name]: SOURCE_SKIP_REASONS.testFile });
    },
  );

  it.each([...TEST_DIRS])('the help test directory %s/ is skipped as a test directory', (name) => {
    const dir = tree({ [`${name}/a.ts`]: 'export const t = 1;\n' });
    expect(skipped(dir)).toEqual({ [name]: SOURCE_SKIP_REASONS.testDir });
  });

  it.each([...SOURCE_SKIP_DIRS].filter((d) => d !== '.git'))(
    'the help build directory %s/ is skipped as dependency or build output',
    (name) => {
      const dir = tree({ [`${name}/a.ts`]: 'export const t = 1;\n' });
      expect(skipped(dir)).toEqual({ [name]: SOURCE_SKIP_REASONS.buildOutput });
    },
  );

  it.each([...HIDDEN_CACHE_DIRS])('the help hidden cache directory %s/ is skipped as hidden cache or build output', (name) => {
    const dir = tree({ [`${name}/a.ts`]: 'export const t = 1;\n' });
    expect(skipped(dir)).toEqual({ [name]: SOURCE_SKIP_REASONS.hiddenCache });
  });

  it.each([...WORKTREE_DIRS])('the help worktree directory %s/ is skipped as linked git worktrees', (name) => {
    const dir = tree({ [`${name}/x/a.ts`]: 'export const t = 1;\n' });
    expect(skipped(dir)).toEqual({ [name]: SOURCE_SKIP_REASONS.worktrees });
  });

  it('prunes only dot-directory names there, none of them already in the shared skip set', () => {
    for (const name of [...HIDDEN_CACHE_DIRS, ...WORKTREE_DIRS]) {
      expect(name.startsWith('.'), name).toBe(true);
      expect(SOURCE_SKIP_DIRS.has(name), name).toBe(false);
    }
  });

  it.each(['.claude', '.github', '.vscode', '.cursor', '.husky', '.devcontainer', '.idea'])(
    'enters %s/ and reads a source file in it (#144)',
    (name) => {
      const dir = tree({ [`${name}/a.ts`]: 'export const t = 1;\n' });
      expect(skipped(dir)).toEqual({});
      const found = tree({ [`${name}/a.ts`]: `const t = "${TOKEN}";\n` });
      expect(scan(found, { scanGlobal: false }).map((f) => [f.file, f.severity])).toEqual([[`${name}/a.ts`, 'high']]);
    },
  );
});

describe('scan --help names what a directory scan does not open', () => {
  it('names every skip reason the walk reports, each on its own line', () => {
    const text = helpText();
    for (const reason of Object.values(SOURCE_SKIP_REASONS)) {
      expect(text, `scan --help must explain "${reason}"`).toMatch(new RegExp(`^\\s+${reason.replace(/[()]/g, '\\$&')}$`, 'm'));
    }
  });

  it('lists every file type, config name, test pattern and directory the walk consults', () => {
    const tokens = new Set(helpText().split(/[\s,;]+/));
    const expected = [
      ...SOURCE_FILE_EXTENSIONS,
      ...KEY_FILE_EXTENSIONS,
      '.env',
      '.env.*',
      ...CONFIG_FILES.filter((f) => !isEnvFile(f)),
      ...CONFIG_SHAPED_EXTENSIONS,
      ...CONFIG_SHAPED_BASENAMES,
      'Dockerfile.*',
      '*.Dockerfile',
      ...TEST_FILE_GLOBS,
      ...[...TEST_DIRS].map((d) => `${d}/`),
      ...[...SOURCE_SKIP_DIRS].map((d) => `${d}/`),
      ...[...HIDDEN_CACHE_DIRS, ...WORKTREE_DIRS].map((d) => `${d}/`),
    ];
    const missing = expected.filter((t) => !tokens.has(t));
    expect(missing).toEqual([]);
  });

  it('says that naming a file scans it', () => {
    expect(helpText()).toMatch(/Name a path to scan it\. A named file is opened whatever its type/);
  });

  it('stays inside an 80-column terminal below the options', () => {
    const text = helpText();
    const notes = text.slice(text.indexOf('A directory scan opens'));
    const wide = notes.split('\n').filter((l) => l.length > 80);
    expect(wide).toEqual([]);
  });
});

describe('naming a file the directory scan skipped scans it, as the help says', () => {
  it.each([
    ['an unsupported file type', 'notes.txt', `token = "${TOKEN}"\n`],
    ['a config file not on the built-in list', 'notes.toml', `token = "${TOKEN}"\n`],
    ['a test file', 'app.test.ts', `export const t = "${TOKEN}";\n`],
    ['a file an ignore rule matches', 'skip-me.ts', `export const t = "${TOKEN}";\n`],
  ])('%s: the directory scan finds nothing, the named file is read', (_what, name, content) => {
    const dir = tree({ [name]: content, '.secretlessignore': 'skip-me.ts\n' });
    expect(scan(dir, { scanGlobal: false }, freshStats())).toEqual([]);
    const named = scan(path.join(dir, name), { scanGlobal: false }, freshStats());
    expect(named.map((f) => f.patternId)).toEqual(['github-pat']);
  });
});
