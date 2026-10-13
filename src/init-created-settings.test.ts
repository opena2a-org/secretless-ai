// `init` names `.claude/settings.json` in exactly one of its two lists.
//
// Created means the path was not there before the run. Modified means it was
// there and the run changed it. A fresh project was told `Modified:` and
// `~ .claude/settings.json (added 99 deny patterns)` about a file that did not
// exist. A reader uses that list to decide what to commit and what a revert
// costs: a created file can be deleted, a modified one held their own content.
//
// 1. The result `init()` returns names a settings file the run created in
//    `filesCreated`, in the order it is written, and one that existed (an
//    empty one included) in `filesModified`.
// 2. `runInit` prints the created row with its count as `(<n> deny patterns)`,
//    the phrase `status` prints for the same number, and no `Modified:`
//    heading with nothing under it. The modified row keeps `(added <n> deny
//    patterns)`.
// 3. The created row reads `pattern` at a count of 1 and carries no
//    parenthesis at 0. No real run creates the file with fewer than two
//    patterns, so those two forms are rendered from a stubbed result.
//
// HOME points at a scratch directory, so `init` never touches the real home
// of whoever runs the suite.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';
import { runInit } from './commands/core';

type Result = ReturnType<typeof init>;

const stub = vi.hoisted(() => ({
  /** When set, the next `init` call returns this instead of running. */
  result: undefined as unknown,
}));

vi.mock('./init', async () => {
  const actual = await vi.importActual<typeof import('./init')>('./init');
  return {
    ...actual,
    init: (dir: string) => (stub.result as Result | undefined) ?? actual.init(dir),
  };
});

const SETTINGS = '.claude/settings.json';

let root: string;
let savedHome: string | undefined;
let projects = 0;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-created-settings-'));
  fs.mkdirSync(path.join(root, 'home'));
  savedHome = process.env.HOME;
  process.env.HOME = path.join(root, 'home');
});

afterEach(() => {
  stub.result = undefined;
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  vi.restoreAllMocks();
  fs.rmSync(root, { recursive: true, force: true });
});

/**
 * A new project directory. `settings` is the content of the settings file it
 * holds before `init` runs; left out, the project has no `.claude/` at all.
 */
function project(settings?: string): string {
  const dir = path.join(root, `project-${projects++}`);
  fs.mkdirSync(dir);
  if (settings !== undefined) {
    fs.mkdirSync(path.join(dir, '.claude'));
    fs.writeFileSync(path.join(dir, SETTINGS), settings);
  }
  return dir;
}

/** The lines `runInit` prints for `dir`, trimmed and without colour codes. */
function report(dir: string): string[] {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
    lines.push(a.map(String).join(' ').replace(/\x1b\[[0-9;]*m/g, '').trim());
  });
  const code = runInit(dir);
  vi.restoreAllMocks();
  expect(code).toBe(0);
  return lines;
}

/** The rows under a heading, up to the blank line that ends its block. */
function block(lines: string[], heading: string): string[] {
  const start = lines.indexOf(heading);
  if (start < 0) return [];
  const end = lines.indexOf('', start);
  return lines.slice(start + 1, end < 0 ? undefined : end);
}

describe('the result init returns', () => {
  it('names a settings file the run created as created, in the order it is written', () => {
    const dir = project();
    expect(fs.existsSync(path.join(dir, SETTINGS))).toBe(false);

    const result = init(dir);

    expect(fs.existsSync(path.join(dir, SETTINGS))).toBe(true);
    expect(result.filesModified).not.toContain(SETTINGS);
    expect(result.filesCreated.filter(f => f === SETTINGS)).toHaveLength(1);
    // After the two hook scripts, before the instruction file.
    expect(result.filesCreated.slice(0, 3)).toEqual([
      '.claude/hooks/secretless-guard.sh',
      '.claude/hooks/secretless-output-check.cjs',
      SETTINGS,
    ]);
    expect(path.basename(result.filesCreated[3])).toBe('CLAUDE.md');
  });

  it.each([
    ['holds the user\'s own keys', JSON.stringify({ model: 'opus' }, null, 2) + '\n'],
    ['is an empty object', '{}\n'],
    ['is empty', ''],
  ])('names a settings file that existed as modified when it %s', (_label, before) => {
    const result = init(project(before));

    expect(result.filesCreated).not.toContain(SETTINGS);
    expect(result.filesModified.filter(f => f === SETTINGS)).toHaveLength(1);
    expect(result.denyRulesAdded).toBeGreaterThan(0);
  });

  it('names the file in neither list on a run that changes nothing in it', () => {
    const dir = project();
    init(dir);

    const again = init(dir);

    expect(again.filesCreated).not.toContain(SETTINGS);
    expect(again.filesModified).not.toContain(SETTINGS);
  });
});

describe('the report init prints', () => {
  it('lists a settings file the run created under Created, with its count, and prints no Modified heading', () => {
    // The count comes from a second run on an identical project, not a literal.
    const { denyRulesAdded } = init(project());
    expect(denyRulesAdded).toBeGreaterThan(1);

    const lines = report(project());

    expect(block(lines, 'Created:')).toContain(`+ ${SETTINGS} (${denyRulesAdded} deny patterns)`);
    expect(lines).not.toContain('Modified:');
    expect(lines.filter(l => l.includes('settings.json'))).toHaveLength(1);
    expect(lines).not.toContain('Already up to date. No files changed.');
  });

  it.each([
    ['holds the user\'s own keys', JSON.stringify({ model: 'opus' }, null, 2) + '\n'],
    ['is empty', ''],
  ])('lists a settings file that existed under Modified when it %s', (_label, before) => {
    const { denyRulesAdded } = init(project(before));
    expect(denyRulesAdded).toBeGreaterThan(1);

    const lines = report(project(before));

    expect(block(lines, 'Modified:')).toEqual([`~ ${SETTINGS} (added ${denyRulesAdded} deny patterns)`]);
    expect(block(lines, 'Created:').some(l => l.includes('settings.json'))).toBe(false);
  });

  it.each([
    [1, `+ ${SETTINGS} (1 deny pattern)`],
    [0, `+ ${SETTINGS}`],
  ])('words the created row for a count of %i', (count, row) => {
    const real = init(project());
    expect(real.filesCreated).toContain(SETTINGS);
    stub.result = { ...real, denyRulesAdded: count };

    expect(block(report(project()), 'Created:')).toContain(row);
  });
});
