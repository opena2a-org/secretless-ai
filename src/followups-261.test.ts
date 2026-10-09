import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  scan,
  emptySkips,
  withDirsVisitedBudget,
  GLOBAL_CONFIG_LABELS,
  type ScanStats,
} from './scan';
import { printCommandHelp } from './command-help';

/**
 * Follow-ups to #261 (#263): the directory-limit report and both budget stops
 * are pinned by a test, `scan --help` names the home-directory files a
 * directory scan reads, `init` under a file names that file, and `--json`
 * carries the counts the human report sizes its Fix from.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

const TOKEN = ['ghp_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');

const made: string[] = [];
function tmp(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  made.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

function cli(args: string[], opts: { home?: string } = {}) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: os.tmpdir(),
    env: { ...process.env, HOME: opts.home ?? tmp('followups-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

function tree(files: Record<string, string | Buffer>): string {
  const dir = tmp('followups-');
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

/** Twelve levels of two links each reach the deepest directory by far more than MAX_PATHS_PER_DIR routes. */
function linkLattice(): string {
  const dir = tmp('followups-lattice-');
  let prev = dir;
  for (let level = 0; level < 12; level++) {
    const next = path.join(prev, 'd');
    fs.mkdirSync(next, { recursive: true });
    fs.symlinkSync(next, path.join(prev, 'l1'), 'dir');
    fs.symlinkSync(next, path.join(prev, 'l2'), 'dir');
    prev = next;
  }
  fs.writeFileSync(path.join(prev, 'a.js'), 'const x = 1;\n');
  return dir;
}

describe('a scan stopped by its directory limit says so', () => {
  itIfBuilt('names the directory limit and a per-subdirectory Fix, not --max-files', () => {
    const res = cli(['scan', linkLattice()]);

    expect(res.status).toBe(1);
    expect(res.stdout).toContain('Scan incomplete: the walk reached its directory limit, so part of the tree was left unscanned.');
    expect(res.stdout).toContain('Raising --max-files does not lift this limit; scan one subdirectory at a time:');
    expect(res.stdout).toMatch(/^\s*Fix:\s+npx secretless-ai scan \S+\/<subdirectory>$/m);
    expect(res.stdout).not.toMatch(/Fix:.*--max-files/);
  });

  itIfBuilt('--json reports walkBudgetExceeded beside truncated', () => {
    const summary = JSON.parse(cli(['scan', linkLattice(), '--json']).stdout).summary;

    expect(summary.truncated).toBe(true);
    expect(summary.walkBudgetExceeded).toBe(true);
  });
});

describe('a walk stopped by MAX_DIRS_VISITED is a directory-budget stop', () => {
  // Plain directories and no links, so the MAX_PATHS_PER_DIR stop never runs.
  const plainTree = () => tree(Object.fromEntries(
    Array.from({ length: 6 }, (_, i) => [`d${i}/a.js`, 'const x = 1;\n']),
  ));

  it('a tree larger than the budget sets truncated and walkBudgetExceeded', () => {
    const stats = freshStats();

    withDirsVisitedBudget(3, () => scan(plainTree(), { scanGlobal: false }, stats));

    expect(stats.truncated).toBe(true);
    expect(stats.walkBudgetExceeded).toBe(true);
  });

  it('CONTROL: a tree inside the budget sets neither', () => {
    const stats = freshStats();

    withDirsVisitedBudget(100, () => scan(plainTree(), { scanGlobal: false }, stats));

    expect(stats.truncated).toBe(false);
    expect(stats.walkBudgetExceeded).toBe(false);
  });

  it('the real budget is back in force after the call', () => {
    const dir = plainTree();
    withDirsVisitedBudget(3, () => scan(dir, { scanGlobal: false }, freshStats()));

    const stats = freshStats();
    scan(dir, { scanGlobal: false }, stats);

    expect(stats.truncated).toBe(false);
  });
});

describe('scan --help names the home-directory files a directory scan reads', () => {
  function helpText(): string {
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    printCommandHelp('scan');
    return out.join('\n');
  }

  it('every home file the scan reads is named before "It opens nothing else"', () => {
    const text = helpText();
    const opens = text.slice(text.indexOf('A directory scan opens'), text.indexOf('It opens nothing else'));
    const tokens = new Set(opens.split(/\s+/));

    expect(GLOBAL_CONFIG_LABELS.filter((label) => !tokens.has(label))).toEqual([]);
  });

  itIfBuilt('a directory scan does read them: a token in ~/.claude/CLAUDE.md is a finding', () => {
    const home = tree({ '.claude/CLAUDE.md': `token = "${TOKEN}"\n` });

    const res = cli(['scan', tmp('followups-empty-'), '--json'], { home });

    expect(JSON.parse(res.stdout).findings.map((f: { file: string }) => f.file)).toEqual(['~/.claude/CLAUDE.md']);
  });
});

describe('`init` on a path under a file', () => {
  itIfBuilt('names the file, and suggests no `mkdir -p` that would fail on it', () => {
    const parent = tree({ 'notes.txt': 'keep me\n' });
    const file = path.join(parent, 'notes.txt');

    const res = cli(['init', path.join(file, 'sub')]);

    expect(res.status).toBe(1);
    expect(res.stderr).not.toContain('Directory not found');
    expect(res.stderr).not.toContain('mkdir');
    expect(res.stderr).toContain(`Not a directory: ${file}`);
    expect(res.stderr).toMatch(/Verify: ls -ld \S*notes\.txt'?$/m);
    expect(res.stderr).toMatch(/Fix:\s+npx secretless-ai init \S+$/m);
    expect(fs.readFileSync(file, 'utf-8')).toBe('keep me\n');
    expect(fs.readdirSync(parent)).toEqual(['notes.txt']);
  });
});

describe('--json carries the count a --max-files cap needs', () => {
  itIfBuilt('eligibleFiles is the cap that clears the truncation', () => {
    const dir = tree(Object.fromEntries(
      Array.from({ length: 30 }, (_, i) => [`f${i}.js`, `const a${i} = 1;\n`]),
    ));

    const capped = JSON.parse(cli(['scan', dir, '--max-files', '2', '--json']).stdout).summary;
    expect(capped.truncated).toBe(true);
    expect(capped.eligibleFiles).toBe(30);
    expect(capped.walkBudgetExceeded).toBe(false);

    const followed = JSON.parse(cli(['scan', dir, '--max-files', String(capped.eligibleFiles), '--json']).stdout).summary;
    expect(followed.truncated).toBe(false);
    expect(followed.eligibleFiles).toBe(0);
  });
});
