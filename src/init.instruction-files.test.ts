// SLS-09: `init` writes the Secretless block where Cursor and Cline document
// their instruction files, and survives the documented Cline rules directory.
//
// Each leaf test name starts with the criterion id it evidences. Every project
// here is a scratch directory; HOME and TMPDIR point at scratch directories
// too, so `status()` (which looks for transcripts under HOME) and `init()`
// never touch the real home of whoever runs the suite.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';
import { status } from './status';

const MARKER = '<!-- secretless:managed -->';
const BLOCK_HEAD = `${MARKER}\n## Secretless Mode`;

let scratchHome: string;
let prevHome: string | undefined;
let prevTmp: string | undefined;

beforeEach(() => {
  prevHome = process.env.HOME;
  prevTmp = process.env.TMPDIR;
  scratchHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sls09-home-'));
  process.env.HOME = scratchHome;
  process.env.TMPDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sls09-tmp-'));
});

afterEach(() => {
  const tmp = process.env.TMPDIR;
  if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
  if (prevTmp === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = prevTmp;
  fs.rmSync(scratchHome, { recursive: true, force: true });
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

function project(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sls09-project-'));
}

function write(dir: string, rel: string, content: string): void {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), content);
}

function read(dir: string, rel: string): string {
  return fs.readFileSync(path.join(dir, rel), 'utf-8');
}

function isFile(dir: string, rel: string): boolean {
  const p = path.join(dir, rel);
  return fs.existsSync(p) && fs.statSync(p).isFile();
}

function isDir(dir: string, rel: string): boolean {
  const p = path.join(dir, rel);
  return fs.existsSync(p) && fs.statSync(p).isDirectory();
}

function exists(dir: string, rel: string): boolean {
  return fs.existsSync(path.join(dir, rel));
}

function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

/** Every path under `dir`, relative, sorted, files and directories alike. */
function listPaths(dir: string): string[] {
  const out: string[] = [];
  const walk = (rel: string): void => {
    for (const entry of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;
      out.push(childRel);
      if (entry.isDirectory()) walk(childRel);
    }
  };
  walk('');
  return out.sort();
}

/** Files (not directories) under `dir` whose content holds the marker. */
function filesHoldingMarker(dir: string): string[] {
  return listPaths(dir).filter(rel => isFile(dir, rel) && read(dir, rel).includes(MARKER));
}

// ---------------------------------------------------------------------------
// Fixtures: the projects AC1, AC2 and AC3 name, each as a builder so AC4, AC5
// and AC6 can rebuild the very same project.
// ---------------------------------------------------------------------------

const USER_MDC = '---\ndescription: user rule\nalwaysApply: false\n---\n# User rule\n';
const USER_CLINE_RULE = '# User rule\n';

type Fixture = { name: string; tool: 'cursor' | 'cline'; build: (dir: string) => void };

const cursorEmptyDir: Fixture = {
  name: 'AC1 cursor: only marker is an empty .cursor/ directory',
  tool: 'cursor',
  build: dir => fs.mkdirSync(path.join(dir, '.cursor')),
};
const cursorUserMdc: Fixture = {
  name: 'AC1 cursor: .cursor/rules/ holds one user .mdc file',
  tool: 'cursor',
  build: dir => write(dir, '.cursor/rules/user.mdc', USER_MDC),
};
const cursorRulesFile: Fixture = {
  name: 'AC1 cursor: only marker is a .cursorrules file',
  tool: 'cursor',
  build: dir => write(dir, '.cursorrules', '# Existing rules\n'),
};
const clineEmptyDir: Fixture = {
  name: 'AC2 cline: only marker is an empty .cline/ directory',
  tool: 'cline',
  build: dir => fs.mkdirSync(path.join(dir, '.cline')),
};
const clineRulesDir: Fixture = {
  name: 'AC2 cline: .cline/rules/ holds one user rule file, no .clinerules',
  tool: 'cline',
  build: dir => write(dir, '.cline/rules/user.md', USER_CLINE_RULE),
};
const clineDirWithAider: Fixture = {
  name: 'AC3 cline: .clinerules/ is a directory with one user file, plus .aider.conf.yml',
  tool: 'cline',
  build: dir => {
    write(dir, '.clinerules/user.md', USER_CLINE_RULE);
    write(dir, '.aider.conf.yml', '');
  },
};
const clineFile: Fixture = {
  name: 'AC3 cline: .clinerules is a regular file',
  tool: 'cline',
  build: dir => write(dir, '.clinerules', '# Existing rules\n'),
};

const ALL_FIXTURES: Fixture[] = [
  cursorEmptyDir, cursorUserMdc, cursorRulesFile,
  clineEmptyDir, clineRulesDir,
  clineDirWithAider, clineFile,
];

function expectCursorMdc(dir: string): void {
  const rel = '.cursor/rules/secretless.mdc';
  expect(isFile(dir, rel)).toBe(true);
  const content = read(dir, rel);
  const lines = content.split('\n');
  expect(lines[0]).toBe('---');
  const close = lines.indexOf('---', 1);
  expect(close).toBeGreaterThan(0);
  const frontmatter = lines.slice(1, close);
  expect(frontmatter).toContain('alwaysApply: true');
  const body = lines.slice(close + 1).join('\n');
  expect(body).toContain(BLOCK_HEAD);
}

// ---------------------------------------------------------------------------
// AC1 — Cursor
// ---------------------------------------------------------------------------

describe('SLS-09.AC1 Cursor writes .cursor/rules/secretless.mdc', () => {
  it('SLS-09.AC1 empty .cursor/ directory: writes the .mdc with alwaysApply frontmatter and no .cursorrules', () => {
    const dir = project();
    cursorEmptyDir.build(dir);

    const result = init(dir);

    expectCursorMdc(dir);
    expect(result.filesCreated.some(f => f.endsWith('secretless.mdc'))).toBe(true);
    expect(exists(dir, '.cursorrules')).toBe(false);
  });

  it('SLS-09.AC1 .cursor/rules/ with a user .mdc: user file byte-identical, .mdc written, no .cursorrules', () => {
    const dir = project();
    cursorUserMdc.build(dir);

    const result = init(dir);

    expectCursorMdc(dir);
    expect(result.filesCreated.some(f => f.endsWith('secretless.mdc'))).toBe(true);
    expect(read(dir, '.cursor/rules/user.mdc')).toBe(USER_MDC);
    expect(exists(dir, '.cursorrules')).toBe(false);
  });

  // Revision 3, the held cell: a project whose rules live in `.cursorrules`
  // and that has no `.mdc` under `.cursor/rules/` gets the block appended to
  // `.cursorrules` only. No `.cursor/rules/secretless.mdc` is created until the
  // host-side load check observes that adding an `.mdc` does not stop Cursor
  // applying `.cursorrules`.
  it('SLS-09.AC1 only .cursorrules: user line byte-identical then the block, nothing under .cursor/rules/, no secretless.mdc created', () => {
    const dir = project();
    cursorRulesFile.build(dir);

    const result = init(dir);

    const rules = read(dir, '.cursorrules');
    expect(rules.startsWith('# Existing rules\n')).toBe(true);
    expect(rules.indexOf(BLOCK_HEAD)).toBeGreaterThan(rules.indexOf('# Existing rules'));
    expect(exists(dir, '.cursor/rules')).toBe(false);
    expect(listPaths(dir).some(p => p.startsWith('.cursor/rules'))).toBe(false);
    expect(result.filesCreated.some(f => f.endsWith('secretless.mdc'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// AC2 — Cline, no `.clinerules` path
// ---------------------------------------------------------------------------

describe('SLS-09.AC2 Cline without a .clinerules path', () => {
  it('SLS-09.AC2 empty .cline/ directory: writes .clinerules/secretless.md, no regular .clinerules file', () => {
    const dir = project();
    clineEmptyDir.build(dir);

    const result = init(dir);

    expect(isFile(dir, '.clinerules/secretless.md')).toBe(true);
    expect(read(dir, '.clinerules/secretless.md')).toContain(MARKER);
    expect(isFile(dir, '.clinerules')).toBe(false);
    expect(result.filesCreated.some(f => f.endsWith('secretless.md'))).toBe(true);
  });

  it('SLS-09.AC2 .cline/rules/ with a user rule: block in .cline/rules/secretless.md, user file byte-identical, no .clinerules', () => {
    const dir = project();
    clineRulesDir.build(dir);

    init(dir);

    expect(isFile(dir, '.cline/rules/secretless.md')).toBe(true);
    expect(read(dir, '.cline/rules/secretless.md')).toContain(MARKER);
    expect(read(dir, '.cline/rules/user.md')).toBe(USER_CLINE_RULE);
    expect(exists(dir, '.clinerules')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// AC3 — Cline, `.clinerules` already exists (directory or file)
// ---------------------------------------------------------------------------

describe('SLS-09.AC3 Cline with an existing .clinerules path', () => {
  it('SLS-09.AC3 .clinerules/ directory plus Aider: no throw, user file byte-identical, block in .clinerules/secretless.md, .aiderignore present', () => {
    const dir = project();
    clineDirWithAider.build(dir);

    expect(() => init(dir)).not.toThrow();

    expect(read(dir, '.clinerules/user.md')).toBe(USER_CLINE_RULE);
    expect(isFile(dir, '.clinerules/secretless.md')).toBe(true);
    expect(read(dir, '.clinerules/secretless.md')).toContain(BLOCK_HEAD);
    expect(isFile(dir, '.aiderignore')).toBe(true);
  });

  it('SLS-09.AC3 .clinerules regular file: block appended after existing content, still a file, no .cline/ created', () => {
    const dir = project();
    clineFile.build(dir);

    init(dir);

    expect(isFile(dir, '.clinerules')).toBe(true);
    const rules = read(dir, '.clinerules');
    expect(rules.startsWith('# Existing rules\n')).toBe(true);
    expect(rules.indexOf(BLOCK_HEAD)).toBeGreaterThan(rules.indexOf('# Existing rules'));
    expect(exists(dir, '.cline')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// AC4 — second run is a no-op: one marker per file, same path set
// ---------------------------------------------------------------------------

describe('SLS-09.AC4 second init is idempotent', () => {
  it.each(ALL_FIXTURES)('SLS-09.AC4 second init on [$name]: one marker per file, same path set', ({ build }) => {
    const dir = project();
    build(dir);

    init(dir);
    const pathsAfterFirst = listPaths(dir);
    const holdersAfterFirst = filesHoldingMarker(dir);
    expect(holdersAfterFirst.length).toBeGreaterThan(0);

    init(dir);
    expect(listPaths(dir)).toEqual(pathsAfterFirst);
    for (const rel of filesHoldingMarker(dir)) {
      expect(count(read(dir, rel), MARKER), rel).toBe(1);
    }
    expect(filesHoldingMarker(dir)).toEqual(holdersAfterFirst);
  });
});

// ---------------------------------------------------------------------------
// AC5 — status lists the tool once init has written its file
// ---------------------------------------------------------------------------

describe('SLS-09.AC5 status.configuredTools follows what init wrote', () => {
  it.each(ALL_FIXTURES)('SLS-09.AC5 after init on [$name]: configuredTools contains $tool', async ({ build, tool }) => {
    const dir = project();
    build(dir);

    init(dir);
    const s = await status(dir);

    expect(s.configuredTools).toContain(tool);
  });

  it('SLS-09.AC5 before init, an empty .cursor/ project lists neither cursor nor cline', async () => {
    const dir = project();
    cursorEmptyDir.build(dir);

    const s = await status(dir);

    expect(s.configuredTools).not.toContain('cursor');
    expect(s.configuredTools).not.toContain('cline');
  });

  it('SLS-09.AC5 before init, an empty .cline/ project lists neither cursor nor cline', async () => {
    const dir = project();
    clineEmptyDir.build(dir);

    const s = await status(dir);

    expect(s.configuredTools).not.toContain('cursor');
    expect(s.configuredTools).not.toContain('cline');
  });
});

// ---------------------------------------------------------------------------
// AC6 — no AGENTS.md; Windsurf and Copilot unchanged
// ---------------------------------------------------------------------------

describe('SLS-09.AC6 no AGENTS.md, Windsurf and Copilot unchanged', () => {
  it.each(ALL_FIXTURES)('SLS-09.AC6 init on [$name] writes no AGENTS.md', ({ build }) => {
    const dir = project();
    build(dir);

    init(dir);

    expect(exists(dir, 'AGENTS.md')).toBe(false);
  });

  it('SLS-09.AC6 Cursor project with an existing AGENTS.md leaves it byte-identical', () => {
    const dir = project();
    cursorEmptyDir.build(dir);
    const agents = '# Agents\n\nSome user content.\n';
    write(dir, 'AGENTS.md', agents);

    init(dir);

    expect(read(dir, 'AGENTS.md')).toBe(agents);
  });

  it('SLS-09.AC6 Windsurf: block in .windsurfrules, .windsurf/ stays empty, no .devin/', () => {
    const dir = project();
    fs.mkdirSync(path.join(dir, '.windsurf'));

    init(dir);

    expect(isFile(dir, '.windsurfrules')).toBe(true);
    expect(read(dir, '.windsurfrules')).toContain(BLOCK_HEAD);
    expect(isDir(dir, '.windsurf')).toBe(true);
    expect(fs.readdirSync(path.join(dir, '.windsurf'))).toEqual([]);
    expect(exists(dir, '.devin')).toBe(false);
  });

  it('SLS-09.AC6 Copilot: block in .github/copilot-instructions.md and no other file under .github/', () => {
    const dir = project();
    write(dir, '.github/copilot-instructions.md', '');

    init(dir);

    expect(read(dir, '.github/copilot-instructions.md')).toContain(BLOCK_HEAD);
    expect(fs.readdirSync(path.join(dir, '.github'))).toEqual(['copilot-instructions.md']);
  });
});

// ---------------------------------------------------------------------------
// AC8 — a symbolic link in the owned path, or a destination outside the
// project, is never written through: the target is untouched, the tool is not
// listed as configured, and the result names the path.
// ---------------------------------------------------------------------------

/** A directory outside any project, as a symlink target. */
function outsideDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sls09-outside-'));
}

/** Listing plus bytes of every file under `dir`, for a before/after compare. */
function snapshot(dir: string): Array<[string, string | null]> {
  return listPaths(dir).map(rel => [rel, isFile(dir, rel) ? read(dir, rel) : null]);
}

type LinkCell = {
  name: string;
  tool: 'cursor' | 'cline' | 'windsurf';
  /** The project-relative path that is the link. */
  linkRel: string;
  /** Build the project with the link in place; returns the link target. */
  build: (dir: string) => string;
  /** The same project without the link (the control), and the file it gets. */
  control: (dir: string) => void;
  controlFile: string;
};

const LINK_CELLS: LinkCell[] = [
  {
    name: 'M2 .cursor/rules linked to an outside directory',
    tool: 'cursor',
    linkRel: '.cursor/rules',
    build: dir => {
      const target = outsideDir();
      fs.mkdirSync(path.join(dir, '.cursor'));
      fs.symlinkSync(target, path.join(dir, '.cursor', 'rules'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.cursor', 'rules'), { recursive: true }),
    controlFile: '.cursor/rules/secretless.mdc',
  },
  {
    name: 'M2b owned .cursor/rules/secretless.mdc linked to an outside file',
    tool: 'cursor',
    linkRel: '.cursor/rules/secretless.mdc',
    build: dir => {
      const target = outsideDir();
      fs.writeFileSync(path.join(target, 'victim.mdc'), 'victim\n'); // 7 bytes
      fs.mkdirSync(path.join(dir, '.cursor', 'rules'), { recursive: true });
      fs.symlinkSync(path.join(target, 'victim.mdc'), path.join(dir, '.cursor', 'rules', 'secretless.mdc'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.cursor', 'rules'), { recursive: true }),
    controlFile: '.cursor/rules/secretless.mdc',
  },
  {
    name: '.cursor linked to an outside directory',
    tool: 'cursor',
    linkRel: '.cursor',
    build: dir => {
      const target = outsideDir();
      fs.symlinkSync(target, path.join(dir, '.cursor'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.cursor')),
    controlFile: '.cursor/rules/secretless.mdc',
  },
  {
    name: 'M2c .clinerules linked to an outside directory',
    tool: 'cline',
    linkRel: '.clinerules',
    build: dir => {
      const target = outsideDir();
      fs.symlinkSync(target, path.join(dir, '.clinerules'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.clinerules')),
    controlFile: '.clinerules/secretless.md',
  },
  {
    name: '.cline linked to an outside directory',
    tool: 'cline',
    linkRel: '.cline',
    build: dir => {
      const target = outsideDir();
      fs.symlinkSync(target, path.join(dir, '.cline'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.cline')),
    controlFile: '.clinerules/secretless.md',
  },
  {
    name: '.cline/rules linked to an outside directory',
    tool: 'cline',
    linkRel: '.cline/rules',
    build: dir => {
      const target = outsideDir();
      fs.mkdirSync(path.join(dir, '.cline'));
      fs.symlinkSync(target, path.join(dir, '.cline', 'rules'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.cline', 'rules'), { recursive: true }),
    controlFile: '.cline/rules/secretless.md',
  },
  {
    name: 'owned .clinerules/secretless.md linked to an outside file',
    tool: 'cline',
    linkRel: '.clinerules/secretless.md',
    build: dir => {
      const target = outsideDir();
      fs.writeFileSync(path.join(target, 'victim.md'), 'victim\n');
      fs.mkdirSync(path.join(dir, '.clinerules'));
      fs.symlinkSync(path.join(target, 'victim.md'), path.join(dir, '.clinerules', 'secretless.md'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.clinerules')),
    controlFile: '.clinerules/secretless.md',
  },
  {
    name: '.windsurfrules linked to an outside file',
    tool: 'windsurf',
    linkRel: '.windsurfrules',
    build: dir => {
      const target = outsideDir();
      fs.writeFileSync(path.join(target, 'victim.md'), 'victim\n');
      fs.symlinkSync(path.join(target, 'victim.md'), path.join(dir, '.windsurfrules'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.windsurf')),
    controlFile: '.windsurfrules',
  },
  {
    name: 'dangling .windsurfrules link to an outside path, with .windsurf/ present',
    tool: 'windsurf',
    linkRel: '.windsurfrules',
    build: dir => {
      const target = outsideDir();
      fs.mkdirSync(path.join(dir, '.windsurf'));
      fs.symlinkSync(path.join(target, 'missing.md'), path.join(dir, '.windsurfrules'));
      return target;
    },
    control: dir => fs.mkdirSync(path.join(dir, '.windsurf')),
    controlFile: '.windsurfrules',
  },
];

describe('SLS-09.AC8 init never writes through a symbolic link or outside the project', () => {
  it.each(LINK_CELLS)('SLS-09.AC8 [$name]: target untouched, tool not configured, result names the path', ({ tool, linkRel, build }) => {
    const dir = project();
    const target = build(dir);
    const targetBefore = snapshot(target);
    const projectBefore = snapshot(dir);

    const result = init(dir);

    expect(snapshot(target)).toEqual(targetBefore);
    expect(snapshot(dir)).toEqual(projectBefore);
    expect(result.toolsDetected).toContain(tool);
    expect(result.toolsConfigured).not.toContain(tool);
    expect(result.pathsRefused.map(r => r.path)).toContain(linkRel);
    expect(result.pathsRefused.find(r => r.path === linkRel)?.tool).toBe(tool);
    expect(result.filesCreated.some(f => f.endsWith('secretless.mdc') || f.endsWith('secretless.md'))).toBe(false);
  });

  it.each(LINK_CELLS)('SLS-09.AC8 control for [$name]: without the link the project gets its file', ({ tool, control, controlFile }) => {
    const dir = project();
    control(dir);

    const result = init(dir);

    expect(isFile(dir, controlFile)).toBe(true);
    expect(fs.lstatSync(path.join(dir, controlFile)).isSymbolicLink()).toBe(false);
    expect(read(dir, controlFile)).toContain(BLOCK_HEAD);
    expect(result.toolsConfigured).toContain(tool);
    expect(result.pathsRefused).toEqual([]);
  });

  it('SLS-09.AC8 a dangling owned-path link with a .cursorrules present: nothing is written for Cursor, not even to .cursorrules', () => {
    const dir = project();
    write(dir, '.cursorrules', '# Existing rules\n');
    write(dir, '.cursor/rules/user.mdc', USER_MDC); // an .mdc exists, so the owned .mdc would be written
    const target = outsideDir();
    fs.symlinkSync(path.join(target, 'missing.mdc'), path.join(dir, '.cursor', 'rules', 'secretless.mdc'));
    const before = snapshot(dir);

    const result = init(dir);

    expect(fs.readdirSync(target)).toEqual([]);
    expect(snapshot(dir)).toEqual(before);
    expect(read(dir, '.cursorrules')).toBe('# Existing rules\n');
    expect(result.toolsConfigured).not.toContain('cursor');
    expect(result.pathsRefused.map(r => r.path)).toContain('.cursor/rules/secretless.mdc');
  });
});

describe('Windsurf with a .windsurfrules entry that is not a regular file', () => {
  it('a .windsurfrules directory: no throw, nothing written into it, Windsurf refused, Cline and Aider after it still configured', () => {
    const dir = project();
    const userRule = '# User rule\n';
    write(dir, '.windsurfrules/user.md', userRule);
    fs.mkdirSync(path.join(dir, '.cline'));
    write(dir, '.aider.conf.yml', '');

    let result: ReturnType<typeof init> | undefined;
    expect(() => { result = init(dir); }).not.toThrow();

    expect(fs.readdirSync(path.join(dir, '.windsurfrules'))).toEqual(['user.md']);
    expect(read(dir, '.windsurfrules/user.md')).toBe(userRule);
    expect(result!.toolsDetected).toContain('windsurf');
    expect(result!.toolsConfigured).not.toContain('windsurf');
    expect(result!.pathsRefused).toContainEqual({
      tool: 'windsurf',
      path: '.windsurfrules',
      reason: 'is not a regular file',
    });
    expect(result!.toolsConfigured).toEqual(expect.arrayContaining(['cline', 'aider']));
    expect(read(dir, '.clinerules/secretless.md')).toContain(BLOCK_HEAD);
    expect(isFile(dir, '.aiderignore')).toBe(true);
  });
});
