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

  it('SLS-09.AC1 existing .cursorrules: existing line still first, block appended there, .mdc also written', () => {
    const dir = project();
    cursorRulesFile.build(dir);

    const result = init(dir);

    expectCursorMdc(dir);
    expect(result.filesCreated.some(f => f.endsWith('secretless.mdc'))).toBe(true);
    const rules = read(dir, '.cursorrules');
    expect(rules.startsWith('# Existing rules\n')).toBe(true);
    expect(rules.indexOf(BLOCK_HEAD)).toBeGreaterThan(rules.indexOf('# Existing rules'));
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
