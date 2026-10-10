// `init` and the instruction paths it refuses.
//
// 1. `runInit` names every refused path with its reason and prints a Verify and
//    a Fix line. The tool is still left off the Configured line; the run used
//    to say "Already up to date. No files changed." without naming the path.
// 2. The writer never writes the block through a symbolic link put in place
//    between its path checks and its write. A link in place of the rule file
//    itself is refused at the open. A link in place of a directory on the way
//    is followed by the open, which can leave an empty file where it leads,
//    and is refused by the check after the open. The swap is made from inside
//    `fs.mkdirSync`, which the writer calls after its last path check and
//    right before it writes.
// 3. A rule file that cannot be opened for writing and already carries the
//    block is left as it is, and the tools after it are still configured. An
//    open for writing alone made such a file fail `init` with EACCES.
// 4. That read-only fallback opens the file without blocking and runs the
//    same checks as the open for writing. A read-only FIFO swapped in for the
//    rule file does not hang `init`, and a read-only file that carries the
//    block, reached through a directory swapped for a link, does not make
//    `init` report the tool configured.
// 5. A directory on the way replaced by a link to a place `init` cannot write
//    is named as refused, whether or not a file opens read-only there. The
//    read-only checks found the link, but `init` failed with EACCES.
// 6. A rule file with more than one hard link is refused like a symbolic link.
//    Its other names can be outside the project, and `init` appended the block
//    to a `.windsurfrules` hard-linked to a file outside it. The copy command
//    in its Fix line writes to a new file from `mktemp`, never through a link
//    the project has at a name such as `.windsurfrules.tmp`, and removes that
//    file when the copy fails. The Verify and copy commands run as printed for
//    a path that starts with `-` and needs quoting.
//
// HOME and TMPDIR point at scratch directories, so `init` never touches the
// real home of whoever runs the suite.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawn, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';
import { runInit, shellQuote } from './commands/core';

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

/**
 * How a Fix line ends: re-running `init` on the same project, named as its
 * paths are. A bare `init` would set up the working directory instead.
 */
function rerun(dir: string): string {
  return `then re-run: npx secretless-ai init ${shellQuote(path.relative(process.cwd(), dir))}`;
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
    expect(fix.endsWith(rerun(dir)), fix).toBe(true);
  });

  it('a .windsurfrules directory: the reason says it is not a regular file, and the Fix says what to put there', () => {
    const dir = project();
    fs.mkdirSync(path.join(dir, '.windsurfrules'));
    fs.writeFileSync(path.join(dir, '.windsurfrules', 'user.md'), '# user rule\n');

    const { out } = capture(() => runInit(dir));

    expect(out).toMatch(/^\s*Not configured: Windsurf$/m);
    expect(out).toContain(`    ${shownPath(dir, '.windsurfrules')} is not a regular file (Windsurf)`);
    expect(printedLine(out, 'Fix').endsWith(`replace it with a regular file, ${rerun(dir)}`)).toBe(true);
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
  reason: string;
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
    reason: 'is a symbolic link',
  },
  {
    name: 'an absent .windsurfrules replaced by a dangling link to an outside path',
    build: dir => {
      fs.mkdirSync(path.join(dir, '.windsurf'));
    },
    swap: (dir, outside) => {
      fs.symlinkSync(path.join(outside, 'missing.md'), path.join(dir, '.windsurfrules'));
    },
    reason: 'is a symbolic link',
  },
  {
    name: 'a regular .windsurfrules replaced by a hard link to an outside file',
    build: (dir, outside) => {
      fs.writeFileSync(path.join(dir, '.windsurfrules'), '# rules\n');
      fs.writeFileSync(path.join(outside, 'victim.md'), 'victim\n');
    },
    swap: (dir, outside) => {
      fs.unlinkSync(path.join(dir, '.windsurfrules'));
      fs.linkSync(path.join(outside, 'victim.md'), path.join(dir, '.windsurfrules'));
    },
    reason: 'has more than one hard link',
  },
];

describe('init does not follow a link put in place after its path checks', () => {
  it.each(RACE_CELLS)('[$name]: the outside target is untouched and Windsurf is refused', ({ build, swap, reason }) => {
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
    expect(result.pathsRefused).toContainEqual({ tool: 'windsurf', path: '.windsurfrules', reason });
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

type HardLinkCell = {
  name: string;
  tool: 'cursor' | 'cline' | 'windsurf';
  /** The project-relative rule file that is a second name for `victim.md`. */
  rel: string;
  /** Directories the project needs for the tool to be detected and `rel` used. */
  dirs: string[];
};

const HARD_LINK_CELLS: HardLinkCell[] = [
  { name: '.windsurfrules', tool: 'windsurf', rel: '.windsurfrules', dirs: [] },
  { name: '.cursorrules', tool: 'cursor', rel: '.cursorrules', dirs: [] },
  { name: 'owned .cursor/rules/secretless.mdc', tool: 'cursor', rel: '.cursor/rules/secretless.mdc', dirs: ['.cursor/rules'] },
  { name: '.clinerules as a file', tool: 'cline', rel: '.clinerules', dirs: [] },
  { name: 'owned .clinerules/secretless.md', tool: 'cline', rel: '.clinerules/secretless.md', dirs: ['.clinerules'] },
  { name: 'owned .cline/rules/secretless.md', tool: 'cline', rel: '.cline/rules/secretless.md', dirs: ['.cline/rules'] },
];

describe('init and a rule file with more than one hard link', () => {
  it.each(HARD_LINK_CELLS)('[$name] hard-linked to a file outside the project: the outside file is untouched and the tool is refused', ({ tool, rel, dirs }) => {
    const dir = project();
    const outside = outsideDir();
    const victim = path.join(outside, 'victim.md');
    fs.writeFileSync(victim, 'victim\n');
    for (const d of dirs) fs.mkdirSync(path.join(dir, d), { recursive: true });
    fs.linkSync(victim, path.join(dir, rel));

    const result = init(dir);

    expect(fs.readFileSync(victim, 'utf-8')).toBe('victim\n');
    expect(result.toolsDetected).toContain(tool);
    expect(result.toolsConfigured).not.toContain(tool);
    expect(result.pathsRefused).toContainEqual({ tool, path: rel, reason: 'has more than one hard link' });
  });

  it('a .cursorrules hard-linked to AGENTS.md inside the project is refused like a symbolic link to it', () => {
    const dir = project();
    fs.writeFileSync(path.join(dir, 'AGENTS.md'), '# rules\n');
    fs.linkSync(path.join(dir, 'AGENTS.md'), path.join(dir, '.cursorrules'));

    const result = init(dir);

    expect(fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf-8')).toBe('# rules\n');
    expect(result.toolsConfigured).not.toContain('cursor');
    expect(result.pathsRefused).toContainEqual({ tool: 'cursor', path: '.cursorrules', reason: 'has more than one hard link' });
  });

  it('runInit names the path, Verify shows the link count, and the printed Fix makes the next run configure Windsurf without touching the outside file', () => {
    const dir = project();
    const outside = outsideDir();
    const victim = path.join(outside, 'victim.md');
    fs.writeFileSync(victim, 'victim\n');
    fs.linkSync(victim, path.join(dir, '.windsurfrules'));
    fs.mkdirSync(path.join(dir, '.clinerules'));

    const first = capture(() => runInit(dir));
    const shown = shownPath(dir, '.windsurfrules');

    expect(first.out).toMatch(/^\s*Not configured: Windsurf$/m);
    expect(first.out).toContain(`    ${shown} has more than one hard link (Windsurf)`);
    expect(first.out).toMatch(/^\s*Configured: Cline \(1 of 2 detected\)$/m);
    expect(fs.readFileSync(victim, 'utf-8')).toBe('victim\n');

    const verify = spawnSync('bash', ['-c', printedLine(first.out, 'Verify')], { encoding: 'utf-8' });
    expect(verify.status).toBe(0);
    expect(verify.stdout.trim().split(/\s+/)[1]).toBe('2');

    const fix = printedLine(first.out, 'Fix');
    expect(fix.endsWith(rerun(dir)), fix).toBe(true);
    const copy = fix.match(/copy of itself \((.+)\), or remove it/);
    expect(copy, 'the Fix line carries no copy command').not.toBeNull();
    const ran = spawnSync('bash', ['-c', copy![1]], { encoding: 'utf-8' });
    expect(ran.status, ran.stderr).toBe(0);
    expect(fs.statSync(path.join(dir, '.windsurfrules')).nlink).toBe(1);

    const second = capture(() => runInit(dir));
    expect(second.out).not.toContain('Not configured');
    expect(fs.readFileSync(path.join(dir, '.windsurfrules'), 'utf-8')).toContain(MARKER);
    expect(fs.readFileSync(victim, 'utf-8')).toBe('victim\n');
  });

  // A copy to the fixed name `.windsurfrules.tmp` was written through a link
  // the project had there: into the outside file it leads to, or into a new
  // file where a dangling one leads, and the link was then moved into place.
  it.each([
    { name: 'a link to a file outside the project', target: 'victim.md', present: true },
    { name: 'a dangling link to a path outside the project', target: 'missing.md', present: false },
  ])('the printed copy command does not write through a .windsurfrules.tmp that is [$name]', ({ target, present }) => {
    const dir = project();
    const outside = outsideDir();
    const leadsTo = path.join(outside, target);
    if (present) fs.writeFileSync(leadsTo, 'victim\n');
    fs.writeFileSync(path.join(dir, 'AGENTS.md'), '# rules\n');
    fs.linkSync(path.join(dir, 'AGENTS.md'), path.join(dir, '.windsurfrules'));
    fs.symlinkSync(leadsTo, path.join(dir, '.windsurfrules.tmp'));

    const first = capture(() => runInit(dir));
    const copy = printedLine(first.out, 'Fix').match(/copy of itself \((.+)\), or remove it/);
    expect(copy, 'the Fix line carries no copy command').not.toBeNull();
    const ran = spawnSync('bash', ['-c', copy![1]], { encoding: 'utf-8' });
    expect(ran.status, ran.stderr).toBe(0);

    if (present) expect(fs.readFileSync(leadsTo, 'utf-8')).toBe('victim\n');
    else expect(fs.existsSync(leadsTo)).toBe(false);
    expect(fs.readlinkSync(path.join(dir, '.windsurfrules.tmp'))).toBe(leadsTo);
    const copied = fs.lstatSync(path.join(dir, '.windsurfrules'));
    expect(copied.isFile()).toBe(true);
    expect(copied.nlink).toBe(1);
    expect(fs.readdirSync(dir).filter(n => n.startsWith('.windsurfrules')).sort()).toEqual(['.windsurfrules', '.windsurfrules.tmp']);

    const second = capture(() => runInit(dir));
    expect(second.out).not.toContain('Not configured');
    expect(fs.readFileSync(path.join(dir, '.windsurfrules'), 'utf-8')).toMatch(new RegExp(`^# rules\\n[\\s\\S]*${MARKER}`));
    expect(fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf-8')).toBe('# rules\n');
  });

  // The other project paths here never need quoting and never start with `-`.
  // These run the printed commands, from the project's parent, for a path that
  // does both: the project is `-j it's` there, shown as `'-j it'\''s/...'`.
  describe('the printed commands for a path that starts with - and needs quoting', () => {
    let prevCwd: string;
    let dir: string;
    let shown: string;

    beforeEach(() => {
      prevCwd = process.cwd();
      const parent = fs.realpathSync(project());
      process.chdir(parent);
      dir = path.join(parent, "-j it's");
      fs.mkdirSync(dir);
      fs.writeFileSync(path.join(dir, 'AGENTS.md'), '# rules\n');
      fs.chmodSync(path.join(dir, 'AGENTS.md'), 0o644);
      fs.utimesSync(path.join(dir, 'AGENTS.md'), new Date('2020-01-02T03:04:05Z'), new Date('2020-01-02T03:04:05Z'));
      fs.linkSync(path.join(dir, 'AGENTS.md'), path.join(dir, '.windsurfrules'));
      shown = shownPath(dir, '.windsurfrules');
      expect(shown).toBe("-j it's/.windsurfrules");
    });

    afterEach(() => {
      process.chdir(prevCwd);
    });

    function copyCommand(out: string): string {
      const copy = printedLine(out, 'Fix').match(/copy of itself \((.+)\), or remove it/);
      expect(copy, 'the Fix line carries no copy command').not.toBeNull();
      return copy![1];
    }

    function leftover(): string[] {
      return fs.readdirSync(dir).filter(n => n.startsWith('.windsurfrules.'));
    }

    it('Verify runs as printed, and the copy is made beside the rule file and keeps its mode and time', () => {
      const first = capture(() => runInit(dir));
      expect(first.out).toContain(`    ${shown} has more than one hard link (Windsurf)`);

      const verify = spawnSync('bash', ['-c', printedLine(first.out, 'Verify')], { encoding: 'utf-8' });
      expect(verify.status, verify.stderr).toBe(0);
      expect(verify.stdout.trim().split(/\s+/)[1]).toBe('2');

      // An `mv` first on PATH logs its arguments: the copy has to be made
      // beside the rule file, so that `mv` renames it in that directory. A
      // bare `mktemp` makes it in TMPDIR, and macOS falls back to its own
      // temporary directory when TMPDIR does not exist.
      const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'refused-bin-'));
      const log = path.join(bin, 'mv.log');
      const realMv = spawnSync('sh', ['-c', 'command -v mv'], { encoding: 'utf-8' }).stdout.trim();
      fs.writeFileSync(path.join(bin, 'mv'), '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$MV_LOG"\nexec "$REAL_MV" "$@"\n', { mode: 0o755 });
      const ran = spawnSync('bash', ['-c', copyCommand(first.out)], {
        encoding: 'utf-8',
        env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, MV_LOG: log, REAL_MV: realMv },
      });
      expect(ran.status, ran.stderr).toBe(0);
      const moved = fs.readFileSync(log, 'utf-8').split('\n').filter(a => a !== '' && a !== '--');
      expect(moved).toHaveLength(2);
      expect(moved[1]).toBe(shown);
      expect(path.dirname(moved[0])).toBe(path.dirname(shown));
      const copied = fs.lstatSync(path.join(dir, '.windsurfrules'));
      expect(copied.isFile()).toBe(true);
      expect(copied.nlink).toBe(1);
      expect(copied.mode & 0o777).toBe(0o644);
      expect(Math.floor(copied.mtimeMs / 1000)).toBe(Date.parse('2020-01-02T03:04:05Z') / 1000);
      expect(fs.readFileSync(path.join(dir, '.windsurfrules'), 'utf-8')).toBe('# rules\n');
      expect(leftover()).toEqual([]);

      const second = capture(() => runInit(dir));
      expect(second.out).not.toContain('Not configured');
      expect(fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf-8')).toBe('# rules\n');
    });

    // `init` refuses on the link count without reading the file, so the copy
    // command is printed for a file `cp` cannot read. It used to exit 1 and
    // leave the empty file mktemp created beside the rule file.
    it.skipIf(process.getuid?.() === 0)('a copy that fails exits non-zero and leaves no file beside the rule file', () => {
      fs.chmodSync(path.join(dir, 'AGENTS.md'), 0o000);
      const first = capture(() => runInit(dir));

      const ran = spawnSync('bash', ['-c', copyCommand(first.out)], { encoding: 'utf-8' });
      expect(ran.status).not.toBe(0);
      expect(ran.stderr).toContain('Permission denied');
      expect(leftover()).toEqual([]);
      expect(fs.statSync(path.join(dir, '.windsurfrules')).nlink).toBe(2);
    });
  });

  it('control: a rule file with one link gets the block appended', () => {
    const dir = project();
    fs.writeFileSync(path.join(dir, '.windsurfrules'), '# rules\n');
    expect(fs.statSync(path.join(dir, '.windsurfrules')).nlink).toBe(1);

    const result = init(dir);

    expect(result.toolsConfigured).toEqual(['windsurf']);
    expect(result.pathsRefused).toEqual([]);
    expect(fs.readFileSync(path.join(dir, '.windsurfrules'), 'utf-8')).toMatch(new RegExp(`^# rules\\n[\\s\\S]*${MARKER}`));
  });
});

describe('init and a directory on the way replaced by a link after its path checks', () => {
  it('.cursor/rules replaced by a link to an outside directory: the block is not written there and Cursor is refused', () => {
    const dir = project();
    const outside = outsideDir();
    const rulesDir = path.join(dir, '.cursor', 'rules');
    fs.mkdirSync(rulesDir, { recursive: true });

    race.dir = rulesDir;
    race.swap = () => {
      fs.rmdirSync(rulesDir);
      fs.symlinkSync(outside, rulesDir);
    };
    const result = init(dir);

    expect(race.swap, 'the swap never ran, so this cell tested nothing').toBeUndefined();
    // The open follows a link at a directory on the way and can leave an empty
    // file where it leads; the check after the open refuses the path before
    // anything is written to it.
    const reached = path.join(outside, 'secretless.mdc');
    expect(fs.existsSync(reached) ? fs.readFileSync(reached, 'utf-8') : '').not.toContain(MARKER);
    expect(result.toolsDetected).toEqual(['cursor']);
    expect(result.toolsConfigured).not.toContain('cursor');
    expect(result.pathsRefused).toContainEqual({ tool: 'cursor', path: '.cursor/rules', reason: 'is a symbolic link' });
  });
});

// Root opens a read-only file for writing anyway, so these cells would not
// reach the code they test.
const canDenyWrites = (() => {
  if (process.platform === 'win32') return false;
  try {
    return typeof process.getuid === 'function' && process.getuid() !== 0;
  } catch {
    return false;
  }
})();

describe('init and a rule file it cannot write', () => {
  it.skipIf(!canDenyWrites)('a read-only .cursorrules that already carries the block: init exits 0, leaves it as it is, and still configures Cline and Aider', () => {
    const dir = project();
    const rules = path.join(dir, '.cursorrules');
    fs.writeFileSync(rules, `# rules\n${MARKER}\n`);
    fs.chmodSync(rules, 0o444);
    fs.mkdirSync(path.join(dir, '.clinerules'));
    fs.writeFileSync(path.join(dir, '.aiderignore'), 'node_modules\n');

    const { code, out } = capture(() => runInit(dir));

    expect(code).toBe(0);
    expect(out).toMatch(/^\s*Configured: Cursor, Cline, Aider \(3 of 3 detected\)$/m);
    expect(out).not.toContain('Not configured');
    expect(fs.readFileSync(rules, 'utf-8')).toBe(`# rules\n${MARKER}\n`);
    expect(fs.readFileSync(path.join(dir, '.clinerules', 'secretless.md'), 'utf-8')).toContain(MARKER);
    expect(fs.readFileSync(path.join(dir, '.aiderignore'), 'utf-8')).toContain('# Secretless');
  });

  it.skipIf(!canDenyWrites)('control: a read-only .windsurfrules without the block is not reported configured and is left as it is', () => {
    const dir = project();
    const rules = path.join(dir, '.windsurfrules');
    fs.writeFileSync(rules, '# rules\n');
    fs.chmodSync(rules, 0o444);

    // Failing the run because the file cannot be written is not a claim that
    // Windsurf is configured either.
    let configured: string[] = [];
    try {
      configured = init(dir).toolsConfigured;
    } catch (err) {
      expect((err as NodeJS.ErrnoException).code).toBe('EACCES');
    }
    expect(configured).not.toContain('windsurf');
    expect(fs.readFileSync(rules, 'utf-8')).toBe('# rules\n');
  });
});

/** Whatever `init` returns as configured, or nothing when it fails with EACCES. */
function configuredUnlessDenied(dir: string): string[] {
  try {
    return init(dir).toolsConfigured;
  } catch (err) {
    expect((err as NodeJS.ErrnoException).code).toBe('EACCES');
    return [];
  }
}

// How long a FIFO open may block before the watchdog opens it for writing. A
// blocking open never returns on its own, and it blocks the worker's event
// loop, so the test's own timeout cannot end it.
const FIFO_WATCHDOG_SECONDS = 5;

describe('init and a read-only path put in place after its path checks', () => {
  it.skipIf(!canDenyWrites)('a read-only FIFO swapped in for .windsurfrules: init does not block on it, Windsurf is not configured, and the FIFO is left as it is', () => {
    const dir = project();
    fs.mkdirSync(path.join(dir, '.windsurf'));
    const rules = path.join(dir, '.windsurfrules');
    const fired = path.join(dir, '.watchdog-fired');

    race.dir = dir;
    race.swap = () => {
      const r = spawnSync('mkfifo', ['-m', '444', rules], { encoding: 'utf-8' });
      expect(r.status, `mkfifo failed: ${r.stderr}`).toBe(0);
    };
    // A read-only open of a FIFO blocks until a writer opens it. The watchdog
    // is that writer, late, so a regression fails here instead of hanging the
    // suite.
    const watchdog = spawn('sh', ['-c',
      `sleep ${FIFO_WATCHDOG_SECONDS}; [ -p "$F" ] || exit 0; : > "$M"; chmod 644 "$F"; : > "$F"`,
    ], { env: { PATH: process.env.PATH, F: rules, M: fired }, stdio: 'ignore' });
    let configured: string[];
    try {
      configured = configuredUnlessDenied(dir);
    } finally {
      watchdog.kill('SIGKILL');
    }

    expect(race.swap, 'the swap never ran, so this cell tested nothing').toBeUndefined();
    expect(fs.existsSync(fired), 'init blocked on the FIFO until the watchdog opened it').toBe(false);
    expect(configured).not.toContain('windsurf');
    const after = fs.lstatSync(rules);
    expect(after.isFIFO()).toBe(true);
    expect(after.mode & 0o777).toBe(0o444);
  }, (FIFO_WATCHDOG_SECONDS + 15) * 1000);

  it.skipIf(!canDenyWrites)('.cursor/rules replaced by a link to an outside directory holding a read-only secretless.mdc with the block: Cursor is not reported configured and the file is left as it is', () => {
    const dir = project();
    const outside = outsideDir();
    const reached = path.join(outside, 'secretless.mdc');
    const content = `---\nalwaysApply: true\n---\n${MARKER}\n`;
    fs.writeFileSync(reached, content);
    fs.chmodSync(reached, 0o444);
    const rulesDir = path.join(dir, '.cursor', 'rules');
    fs.mkdirSync(rulesDir, { recursive: true });

    race.dir = rulesDir;
    race.swap = () => {
      fs.rmdirSync(rulesDir);
      fs.symlinkSync(outside, rulesDir);
    };
    const configured = configuredUnlessDenied(dir);

    expect(race.swap, 'the swap never ran, so this cell tested nothing').toBeUndefined();
    // The block in the outside file is not the project's: carrying it there
    // is no claim that Cursor is configured for this project.
    expect(configured).not.toContain('cursor');
    expect(fs.readFileSync(reached, 'utf-8')).toBe(content);
  });
});

type ReadOnlyLinkCell = {
  name: string;
  /** Fill the outside directory `.cursor/rules` is swapped to a link to. */
  build: (outside: string) => void;
};

const READ_ONLY_LINK_CELLS: ReadOnlyLinkCell[] = [
  {
    name: 'a read-only secretless.mdc that carries the block',
    build: outside => {
      fs.writeFileSync(path.join(outside, 'secretless.mdc'), `# outside\n${MARKER}\n`);
      fs.chmodSync(path.join(outside, 'secretless.mdc'), 0o444);
    },
  },
  {
    name: 'a read-only secretless.mdc without the block',
    build: outside => {
      fs.writeFileSync(path.join(outside, 'secretless.mdc'), '# outside\n');
      fs.chmodSync(path.join(outside, 'secretless.mdc'), 0o444);
    },
  },
  {
    name: 'no secretless.mdc, in a directory init cannot create it in',
    build: outside => {
      fs.chmodSync(outside, 0o555);
    },
  },
];

describe('init and a directory on the way replaced by a link to a place it cannot write', () => {
  // The open for writing fails with EACCES there, and the read-only re-open
  // (or the path check when nothing opens) finds the link. Init used to throw
  // the EACCES without naming the path.
  it.skipIf(!canDenyWrites).each(READ_ONLY_LINK_CELLS)('[$name]: init names .cursor/rules as a symbolic link instead of failing with EACCES', ({ build }) => {
    const dir = project();
    const outside = outsideDir();
    const rulesDir = path.join(dir, '.cursor', 'rules');
    fs.mkdirSync(rulesDir, { recursive: true });
    build(outside);
    const outsideBefore = fs.readdirSync(outside).map(n => [n, fs.readFileSync(path.join(outside, n), 'utf-8')]);

    race.dir = rulesDir;
    race.swap = () => {
      fs.rmdirSync(rulesDir);
      fs.symlinkSync(outside, rulesDir);
    };
    const result = init(dir);

    expect(race.swap, 'the swap never ran, so this cell tested nothing').toBeUndefined();
    const outsideAfter = fs.readdirSync(outside).map(n => [n, fs.readFileSync(path.join(outside, n), 'utf-8')]);
    expect(outsideAfter).toEqual(outsideBefore);
    expect(result.toolsDetected).toEqual(['cursor']);
    expect(result.toolsConfigured).not.toContain('cursor');
    expect(result.pathsRefused).toContainEqual({ tool: 'cursor', path: '.cursor/rules', reason: 'is a symbolic link' });
  });
});
