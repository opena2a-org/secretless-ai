// `init` and the instruction paths it refuses.
//
// 1. `runInit` names every refused path with its reason and prints a Verify and
//    a Fix line. It used to drop the tool from the Configured line and then say
//    "Already up to date. No files changed." with nothing else.
// 2. The writer does not follow a symbolic link put in place between its path
//    checks and its write. The swap is made from inside `fs.mkdirSync`, which
//    the writer calls after its last path check and right before it writes.
//
// HOME and TMPDIR point at scratch directories, so `init` never touches the
// real home of whoever runs the suite.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';
import { runInit } from './commands/core';

const race = vi.hoisted(() => ({
  /** Directory whose `mkdirSync` call triggers `swap`, once. */
  dir: undefined as string | undefined,
  swap: undefined as (() => void) | undefined,
}));

vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof import('fs')>('fs');
  return {
    ...actual,
    mkdirSync: (p: import('fs').PathLike, opts?: import('fs').MakeDirectoryOptions) => {
      if (race.swap && String(p) === race.dir) {
        const swap = race.swap;
        race.swap = undefined;
        swap();
      }
      return actual.mkdirSync(p, opts);
    },
  };
});

const MARKER = '<!-- secretless:managed -->';

let scratchHome: string;
let prevHome: string | undefined;
let prevTmp: string | undefined;

beforeEach(() => {
  prevHome = process.env.HOME;
  prevTmp = process.env.TMPDIR;
  scratchHome = fs.mkdtempSync(path.join(os.tmpdir(), 'refused-home-'));
  process.env.HOME = scratchHome;
  process.env.TMPDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'refused-tmp-'));
});

afterEach(() => {
  race.dir = undefined;
  race.swap = undefined;
  const tmp = process.env.TMPDIR;
  if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
  if (prevTmp === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = prevTmp;
  fs.rmSync(scratchHome, { recursive: true, force: true });
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

function project(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'refused-project-'));
}

function outsideDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'refused-outside-'));
}

function capture(fn: () => number): { code: number; out: string } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.join(' '));
  });
  try {
    const code = fn();
    return { code, out: lines.join('\n').replace(/\[[0-9;]*m/g, '') };
  } finally {
    spy.mockRestore();
  }
}

/** The text after `label:` on the line that starts with it, exactly as printed. */
function printedLine(out: string, label: 'Verify' | 'Fix'): string {
  const m = out.match(new RegExp(`^\\s*${label}:\\s*(.+)$`, 'm'));
  expect(m, `init printed no ${label}: line`).not.toBeNull();
  return m![1].trim();
}

/** How `init` names a project path: relative to the working directory. */
function shownPath(dir: string, rel: string): string {
  return path.relative(process.cwd(), path.join(dir, rel));
}

describe('runInit reports every instruction path it refused', () => {
  it('a .cursorrules link to AGENTS.md (the only detected tool): names the path and reason, prints Verify and Fix, and does not say "Already up to date"', () => {
    const dir = project();
    fs.writeFileSync(path.join(dir, 'AGENTS.md'), '# rules\n');
    fs.symlinkSync('AGENTS.md', path.join(dir, '.cursorrules'));

    const { out } = capture(() => runInit(dir));
    const shown = shownPath(dir, '.cursorrules');

    expect(out).toMatch(/^\s*Configured: none$/m);
    expect(out).toMatch(/^\s*Not configured: Cursor$/m);
    expect(out).toContain(`    ${shown} is a symbolic link (Cursor)`);
    expect(out).not.toContain('Already up to date');
    expect(fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf-8')).toBe('# rules\n');

    // The Verify command runs as printed and shows the link and where it leads.
    const verify = printedLine(out, 'Verify');
    expect(verify).toMatch(/^ls -ld /);
    const r = spawnSync('bash', ['-c', verify], { encoding: 'utf-8' });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('-> AGENTS.md');

    const fix = printedLine(out, 'Fix');
    expect(fix).toContain('replace the link');
    expect(fix).toContain('then re-run: secretless-ai init');
  });

  it('a .windsurfrules directory: the reason says it is not a regular file, and the Fix says what to put there', () => {
    const dir = project();
    fs.mkdirSync(path.join(dir, '.windsurfrules'));
    fs.writeFileSync(path.join(dir, '.windsurfrules', 'user.md'), '# user rule\n');

    const { out } = capture(() => runInit(dir));

    expect(out).toMatch(/^\s*Not configured: Windsurf$/m);
    expect(out).toContain(`    ${shownPath(dir, '.windsurfrules')} is not a regular file (Windsurf)`);
    expect(printedLine(out, 'Fix')).toContain('replace it with a regular file, then re-run: secretless-ai init');
    expect(out).not.toContain('Already up to date');
  });

  it('control: with nothing refused there is no Not configured block, and a re-run is a no-op', () => {
    const dir = project();
    fs.writeFileSync(path.join(dir, '.cursorrules'), '# rules\n');

    const first = capture(() => runInit(dir));
    expect(first.out).not.toContain('Not configured');
    expect(first.out).toMatch(/^\s*Configured: Cursor \(1 of 1 detected\)$/m);

    const second = capture(() => runInit(dir));
    expect(second.out).not.toContain('Not configured');
    expect(second.out).toContain('Already up to date. No files changed.');
  });
});

type RaceCell = {
  name: string;
  /** Build a Windsurf-only project; returns the outside directory. */
  build: (dir: string, outside: string) => void;
  /** Replace `.windsurfrules` with a link once the path checks have passed. */
  swap: (dir: string, outside: string) => void;
};

const RACE_CELLS: RaceCell[] = [
  {
    name: 'a regular .windsurfrules replaced by a link to an outside file',
    build: (dir, outside) => {
      fs.writeFileSync(path.join(dir, '.windsurfrules'), '# rules\n');
      fs.writeFileSync(path.join(outside, 'victim.md'), 'victim\n');
    },
    swap: (dir, outside) => {
      fs.unlinkSync(path.join(dir, '.windsurfrules'));
      fs.symlinkSync(path.join(outside, 'victim.md'), path.join(dir, '.windsurfrules'));
    },
  },
  {
    name: 'an absent .windsurfrules replaced by a dangling link to an outside path',
    build: dir => {
      fs.mkdirSync(path.join(dir, '.windsurf'));
    },
    swap: (dir, outside) => {
      fs.symlinkSync(path.join(outside, 'missing.md'), path.join(dir, '.windsurfrules'));
    },
  },
];

describe('init does not follow a link put in place after its path checks', () => {
  it.each(RACE_CELLS)('[$name]: the outside target is untouched and Windsurf is refused', ({ build, swap }) => {
    const dir = project();
    const outside = outsideDir();
    build(dir, outside);
    const outsideBefore = fs.readdirSync(outside).map(n => [n, fs.readFileSync(path.join(outside, n), 'utf-8')]);

    race.dir = dir;
    race.swap = () => swap(dir, outside);
    const result = init(dir);

    expect(race.swap, 'the swap never ran, so this cell tested nothing').toBeUndefined();
    const outsideAfter = fs.readdirSync(outside).map(n => [n, fs.readFileSync(path.join(outside, n), 'utf-8')]);
    expect(outsideAfter).toEqual(outsideBefore);
    expect(result.toolsDetected).toEqual(['windsurf']);
    expect(result.toolsConfigured).not.toContain('windsurf');
    expect(result.pathsRefused).toContainEqual({ tool: 'windsurf', path: '.windsurfrules', reason: 'is a symbolic link' });
  });

  it('control: without a swap the same writer creates .windsurfrules and appends once', () => {
    const dir = project();
    fs.mkdirSync(path.join(dir, '.windsurf'));

    const first = init(dir);
    const created = fs.readFileSync(path.join(dir, '.windsurfrules'), 'utf-8');
    expect(first.toolsConfigured).toEqual(['windsurf']);
    expect(created).toContain(MARKER);

    fs.writeFileSync(path.join(dir, '.windsurfrules'), '# mine\n');
    const second = init(dir);
    const appended = fs.readFileSync(path.join(dir, '.windsurfrules'), 'utf-8');
    expect(second.filesModified.some(f => f.endsWith('.windsurfrules'))).toBe(true);
    expect(appended).toBe('# mine\n' + created);

    init(dir);
    expect(fs.readFileSync(path.join(dir, '.windsurfrules'), 'utf-8')).toBe(appended);
  });
});
