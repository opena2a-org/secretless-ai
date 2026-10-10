import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runInit } from './commands/core';

/**
 * `runInit` on a path that holds `..` after a symbolic link (#274).
 *
 * The check that the directory exists reads `..` after a link as the kernel
 * does: the parent of the directory the link points at. init built every path
 * it writes with `path.join`, which drops `..` with the name before it. So
 * `link/../proj` passed the check on the `proj` beside the link's target, and
 * init then wrote to a `proj` beside the link, making it when none existed.
 * init now sets up the directory the check read.
 *
 * Only API callers reach this. The CLI resolves its argument before the call.
 *
 * HOME points at a scratch directory, so init never touches the real home of
 * whoever runs the suite.
 */

function capture(fn: () => number): { code: number; out: string; err: string } {
  const out: string[] = [];
  const err: string[] = [];
  const plain = (lines: string[]) => lines.join('\n').replace(/\u001b\[[0-9;]*m/g, '');
  const logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { out.push(args.join(' ')); });
  const errSpy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { err.push(args.join(' ')); });
  try {
    const code = fn();
    return { code, out: plain(out), err: plain(err) };
  } finally {
    logSpy.mockRestore();
    errSpy.mockRestore();
  }
}

/** The command the tool told the user to run, exactly as printed. */
function printedLine(text: string, label: 'Verify' | 'Fix'): string {
  const m = text.match(new RegExp(`^\\s*${label}:\\s*(.+)$`, 'm'));
  expect(m, `init printed no ${label}: line`).not.toBeNull();
  return m![1].trim();
}

function runInShell(command: string, cwd: string): number {
  return spawnSync('bash', ['-c', command], { cwd, encoding: 'utf-8' }).status ?? 1;
}

/** Every path under `root`, links not followed. */
function listing(root: string): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      found.push(path.relative(root, full));
      if (entry.isDirectory()) walk(full);
    }
  };
  walk(root);
  return found.sort();
}

// Windows resolves `..` by spelling before the filesystem sees the path, so a
// path there has one reading.
describe.skipIf(process.platform === 'win32')('runInit on a path with `..` after a symbolic link', () => {
  /** The working directory: holds `link`, which points at `elsewhere/d`. */
  let x: string;
  let prevCwd: string;
  let scratchHome: string;
  let prevHome: string | undefined;

  beforeEach(() => {
    prevCwd = process.cwd();
    prevHome = process.env.HOME;
    scratchHome = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-dotdot-home-'));
    process.env.HOME = scratchHome;
    // init names paths under the working directory as the kernel reports it,
    // and the temp directory can itself be reached through a link.
    x = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-dotdot-')));
    fs.mkdirSync(path.join(x, 'elsewhere', 'd'), { recursive: true });
    fs.symlinkSync(path.join(x, 'elsewhere', 'd'), path.join(x, 'link'), 'dir');
    process.chdir(x);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    fs.rmSync(x, { recursive: true, force: true });
    fs.rmSync(scratchHome, { recursive: true, force: true });
  });

  it('sets up link/../proj beside the link\'s target, the directory it checked, and makes no proj beside the link', () => {
    fs.mkdirSync(path.join(x, 'elsewhere', 'proj'));

    const res = capture(() => runInit('link/../proj'));

    expect(res.code).toBe(0);
    expect(fs.existsSync(path.join(x, 'elsewhere', 'proj', '.claude', 'settings.json'))).toBe(true);
    expect(res.out).toContain(`+ ${path.join('elsewhere', 'proj', 'CLAUDE.md')}\n`);
    expect(fs.existsSync(path.join(x, 'proj'))).toBe(false);
    expect(fs.readdirSync(path.join(x, 'elsewhere', 'd'))).toEqual([]);
  });

  it('does the same for the path given absolute', () => {
    fs.mkdirSync(path.join(x, 'elsewhere', 'proj'));

    // Built by hand: path.join would drop the `..`.
    const res = capture(() => runInit(`${x}/link/../proj`));

    expect(res.code).toBe(0);
    expect(fs.existsSync(path.join(x, 'elsewhere', 'proj', '.claude', 'settings.json'))).toBe(true);
    expect(fs.existsSync(path.join(x, 'proj'))).toBe(false);
  });

  it('with a proj beside the link as well, sets up the one it checked and leaves the other as it was', () => {
    fs.mkdirSync(path.join(x, 'elsewhere', 'proj'));
    fs.mkdirSync(path.join(x, 'proj'));

    const res = capture(() => runInit('link/../proj'));

    expect(res.code).toBe(0);
    expect(fs.existsSync(path.join(x, 'elsewhere', 'proj', '.claude', 'settings.json'))).toBe(true);
    expect(fs.readdirSync(path.join(x, 'proj'))).toEqual([]);
  });

  it('names a path it refused in the directory it checked, so the printed Verify finds it', () => {
    const proj = path.join(x, 'elsewhere', 'proj');
    fs.mkdirSync(proj);
    fs.writeFileSync(path.join(proj, 'AGENTS.md'), '# rules\n');
    fs.symlinkSync('AGENTS.md', path.join(proj, '.cursorrules'));

    const res = capture(() => runInit('link/../proj'));

    expect(res.out).toContain(`${path.join('elsewhere', 'proj', '.cursorrules')} is a symbolic link`);
    expect(runInShell(printedLine(res.out, 'Verify'), x)).toBe(0);
    expect(fs.readFileSync(path.join(proj, 'AGENTS.md'), 'utf-8')).toBe('# rules\n');
    expect(fs.existsSync(path.join(x, 'proj'))).toBe(false);
  });

  it('CONTROL: refuses link/../proj when only the link\'s own directory holds proj, and writes nothing', () => {
    fs.mkdirSync(path.join(x, 'proj'));
    const before = listing(x);

    const res = capture(() => runInit('link/../proj'));

    expect(res.code).toBe(1);
    expect(res.err).toContain('Directory not found: link/../proj\n');
    expect(res.err).toContain('Nothing was written.');
    expect(listing(x)).toEqual(before);
  });

  it('CONTROL: `..` after a plain directory sets up the directory it names, under the name given', () => {
    fs.mkdirSync(path.join(x, 'proj'));

    const res = capture(() => runInit('elsewhere/../proj'));

    expect(res.code).toBe(0);
    expect(fs.existsSync(path.join(x, 'proj', '.claude', 'settings.json'))).toBe(true);
    expect(res.out).toContain(`+ ${path.join('proj', 'CLAUDE.md')}\n`);
    expect(fs.readdirSync(path.join(x, 'elsewhere')).sort()).toEqual(['d']);
  });

  it('CONTROL: a path through a link with no `..` sets up the link\'s target', () => {
    const res = capture(() => runInit('link'));

    expect(res.code).toBe(0);
    expect(fs.existsSync(path.join(x, 'elsewhere', 'd', '.claude', 'settings.json'))).toBe(true);
  });

  it('CONTROL: an empty path is refused, not read as the working directory', () => {
    const before = listing(x);

    const res = capture(() => runInit(''));

    expect(res.code).toBe(1);
    expect(res.err).toContain('Directory not found: \n');
    expect(listing(x)).toEqual(before);
  });
});
