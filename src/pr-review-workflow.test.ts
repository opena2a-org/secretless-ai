import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * The automated review in .github/workflows/pr-review.yml, and what it is
 * shown about code the pull request did not change.
 *
 * Why this file exists. The review's request held a full source section for
 * the changed files and the diff, and nothing else. On #275 a changed file
 * called escapePathForDisplay() and hasDisplayHazard(), both imported from
 * src/display-safe.ts, and neither the definitions nor the import were in the
 * request. The definitions were absent because src/display-safe.ts did not
 * change. The import was absent because the full source section, the one
 * place an unchanged import line is shown, held only its own notice that it
 * was "truncated at 0 bytes": CHANGELOG.md, listed before every src/ path,
 * was larger than that section's whole budget. The review raised a CRITICAL
 * saying both functions were "called but not defined or imported". The gate
 * failed on a symbol that resolves in the checkout.
 *
 * Under test: a step that follows the relative imports of a changed file
 * whose keyword and quoted specifier stand on one line (`from '...'`,
 * `import '...'`, `require('...')`, `import('...')`) and lists the export
 * declarations of the module each resolves to, read from the HEAD commit and
 * never from a path outside the repository; the prompt that places those
 * declarations between the full source files and the diff; and the system
 * prompt rule that a finding resting on code the review was not shown is
 * MEDIUM at most, which does not block. The step does not follow a
 * template-literal specifier, or a specifier on the line after its `from` or
 * `require(`. It supplies the definitions only: it does not restore an empty
 * full source section.
 *
 * The same indent-walk reading as src/release-workflow.test.ts: no YAML
 * dependency, comments stripped before any substring assertion. The step
 * scripts are executed as written, with each /tmp/ path redirected into a
 * scratch directory.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const WORKFLOW = fs.readFileSync(path.join(REPO_ROOT, '.github', 'workflows', 'pr-review.yml'), 'utf-8');

const COLLECT_STEP = 'Collect definitions the changed files import';
const GATHER_STEP = 'Gather review context';
const BUILD_STEP = 'Build review prompt';
const DEFS_HEADING = 'DEFINITIONS IMPORTED FROM UNCHANGED FILES';

/** See src/release-workflow.test.ts: a git hook exports these for its own repository. */
const GIT_DISCOVERY_VARS = [
  'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
  'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_PREFIX',
];

function withoutGitDiscovery(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, ...extra };
  for (const name of GIT_DISCOVERY_VARS) delete env[name];
  return env;
}

function git(args: string[], cwd: string) {
  const run = spawnSync('git', args, { cwd, encoding: 'utf-8', env: withoutGitDiscovery() });
  expect(run.status, `git ${args.join(' ')}: ${run.stderr}`).toBe(0);
  return run;
}

/**
 * Actions runs a `run:` body as `bash -e {0}`, and as `bash -eo pipefail {0}`
 * once the step or the workflow names `shell: bash`.
 */
const PIPEFAIL = ['-eo', 'pipefail'];

function bash(script: string, cwd: string, extra: NodeJS.ProcessEnv = {}, flags: string[] = ['-e']) {
  return spawnSync('bash', [...flags, '-c', script], { cwd, encoding: 'utf-8', env: withoutGitDiscovery(extra) });
}

// ---------------------------------------------------------------------------
// Indent-walk helpers
// ---------------------------------------------------------------------------

function stripComments(block: string): string {
  return block
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
}

function jobBlock(workflow: string, jobId: string): string {
  const lines = workflow.split('\n');
  const jobs = lines.findIndex((line) => line === 'jobs:');
  expect(jobs, 'workflow has no top-level "jobs:"').toBeGreaterThanOrEqual(0);
  const start = lines.findIndex((line, i) => i > jobs && line === `  ${jobId}:`);
  expect(start, `workflow has no job "${jobId}"`).toBeGreaterThanOrEqual(0);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || /^ {3,}/.test(lines[end]))) end += 1;
  return stripComments(lines.slice(start, end).join('\n'));
}

/** A job's steps, one block per `- ` item under `steps:`. */
function stepBlocks(job: string): string[] {
  const lines = job.split('\n');
  const start = lines.findIndex((line) => line === '    steps:');
  expect(start, 'job has no steps:').toBeGreaterThanOrEqual(0);
  const steps: string[] = [];
  let current: string[] | null = null;
  for (const line of lines.slice(start + 1)) {
    if (/^ {6}- /.test(line)) {
      if (current !== null) steps.push(current.join('\n'));
      current = [line];
    } else if (current !== null) {
      current.push(line);
    }
  }
  if (current !== null) steps.push(current.join('\n'));
  return steps;
}

const STEPS = stepBlocks(jobBlock(WORKFLOW, 'review'));

function stepIndex(name: string): number {
  return STEPS.findIndex((block) => block.split('\n')[0].trim() === `- name: ${name}`);
}

function step(name: string): string {
  const index = stepIndex(name);
  expect(index, `review job has no step "${name}"`).toBeGreaterThanOrEqual(0);
  return STEPS[index];
}

/** The `run: |` body of a step, dedented, blank lines kept (heredocs need them). */
function runScript(name: string): string {
  const lines = step(name).split('\n');
  const runIndex = lines.findIndex((line) => /^ {8}run: \|$/.test(line));
  expect(runIndex, `step "${name}" is not a run: | block`).toBeGreaterThanOrEqual(0);
  return lines
    .slice(runIndex + 1)
    .map((line) => line.slice(10))
    .join('\n');
}

/** The script with every /tmp/ file redirected into a scratch directory. */
function inScratch(script: string, tmp: string): string {
  return script.split('/tmp/').join(`${tmp}/`);
}

// ---------------------------------------------------------------------------
// Scratch repositories
// ---------------------------------------------------------------------------

interface Scratch {
  root: string;
  repo: string;
  tmp: string;
}

function scratchRepo(files: Record<string, string>): Scratch {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pr-review-defs-')));
  const repo = path.join(root, 'repo');
  const tmp = path.join(root, 'tmp');
  fs.mkdirSync(repo);
  fs.mkdirSync(tmp);
  git(['init', '--quiet'], repo);
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(repo, name)), { recursive: true });
    fs.writeFileSync(path.join(repo, name), content);
  }
  return { root, repo, tmp };
}

function commitAll(repo: string): void {
  git(['add', '--all'], repo);
  git(['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
    'commit', '--quiet', '--no-verify', '-m', 'fixture'], repo);
}

function collect(s: Scratch, changed: string[], flags?: string[]) {
  fs.writeFileSync(path.join(s.tmp, 'changed_files.txt'), changed.map((f) => `${f}\n`).join(''));
  const run = bash(inScratch(runScript(COLLECT_STEP), s.tmp), s.repo, {}, flags);
  const defsFile = path.join(s.tmp, 'imported_defs.txt');
  const defs = fs.existsSync(defsFile) ? fs.readFileSync(defsFile, 'utf-8') : '';
  return { run, defs };
}

/** src/display-safe.ts as it stood at the #275 head, cut to the two exports the review called undefined. */
const DISPLAY_SAFE = [
  "import * as path from 'path';",
  '',
  'const HAZARD = /[\\u0000-\\u001f]/;',
  '',
  'export function hasDisplayHazard(text: string): boolean {',
  '  return HAZARD.test(text);',
  '}',
  '',
  'export function escapePathForDisplay(p: string, sep: string = path.sep): string {',
  '  return p.split(sep).join(sep);',
  '}',
  '',
  'function notExported(): void {}',
  '',
].join('\n');

const CORE = [
  "import { escapePathForDisplay, hasDisplayHazard } from '../display-safe';",
  "import { VERSION } from './utils';",
  '',
  'export function runInit(dir: string): string {',
  '  return hasDisplayHazard(dir) ? escapePathForDisplay(dir) : VERSION;',
  '}',
  '',
].join('\n');

// ---------------------------------------------------------------------------
// #277
// ---------------------------------------------------------------------------

describe('the review is shown the definitions a changed file imports from unchanged files (#277)', () => {
  it('a step between gathering the context and building the prompt collects them, with no workflow expression and no secret in reach', () => {
    const collectAt = stepIndex(COLLECT_STEP);
    expect(collectAt, `review job has no step "${COLLECT_STEP}"`).toBeGreaterThanOrEqual(0);
    expect(collectAt).toBeGreaterThan(stepIndex(GATHER_STEP));
    expect(collectAt).toBeLessThan(stepIndex(BUILD_STEP));

    const block = step(COLLECT_STEP);
    expect(block).not.toContain('${{');
    expect(block).not.toContain('secrets.');
    expect(block).not.toMatch(/^ {8}env:/m);
    expect(block).not.toMatch(/^ {8}continue-on-error:/m);
  });

  it('on the #275 shape it lists hasDisplayHazard and escapePathForDisplay from src/display-safe.ts at their line numbers', () => {
    const s = scratchRepo({
      'src/display-safe.ts': DISPLAY_SAFE,
      'src/commands/core.ts': CORE,
      'src/commands/utils.ts': "export const VERSION = '0.0.0';\n",
    });
    try {
      commitAll(s.repo);
      const { run, defs } = collect(s, ['src/commands/core.ts', 'src/commands/utils.ts']);
      expect(run.status, run.stderr).toBe(0);

      expect(defs).toContain('=== src/display-safe.ts ');
      expect(defs).toMatch(/^ +5\texport function hasDisplayHazard\(text: string\): boolean \{$/m);
      expect(defs).toMatch(/^ +9\texport function escapePathForDisplay\(p: string, sep: string = path\.sep\): string \{$/m);
      // Export declarations only: not the body, not a private helper.
      expect(defs).not.toContain('HAZARD.test');
      expect(defs).not.toContain('notExported');
      // A changed module's full source is already in FULL SOURCE FILES.
      expect(defs).not.toContain('=== src/commands/utils.ts');
    } finally {
      fs.rmSync(s.root, { recursive: true, force: true });
    }
  });

  it('resolves a .js specifier to its .ts source, a directory to its index, require() of a .js module, a type import and a multi-line export list', () => {
    const s = scratchRepo({
      'src/a.ts': [
        "import { helper } from './util.js';",
        "import { fromIndex } from './lib';",
        "import type { Shape } from './types';",
        "import {",
        "  one,",
        "  two,",
        "} from './list';",
        "export * from './reexported';",
        "import { describe } from 'vitest';",
        "const legacy = require('./legacy');",
        '',
      ].join('\n'),
      'src/util.ts': 'export function helper(): number {\n  return 1;\n}\n',
      'src/lib/index.ts': 'export const fromIndex = 1;\n',
      'src/types.ts': 'export interface Shape {\n  side: number;\n}\n',
      'src/list.ts': 'const one = 1;\nconst two = 2;\nexport {\n  one,\n  two,\n};\n',
      'src/reexported.ts': 'export class Reexported {}\n',
      'src/legacy.js': 'function oldOne() {}\nfunction oldTwo() {}\nmodule.exports = {\n  oldOne,\n  oldTwo,\n};\nexports.third = 3;\n',
    });
    try {
      commitAll(s.repo);
      const { run, defs } = collect(s, ['src/a.ts']);
      expect(run.status, run.stderr).toBe(0);

      expect(defs).toMatch(/=== src\/util\.ts [^\n]*\n +1\texport function helper\(\): number \{\n/);
      expect(defs).toMatch(/=== src\/lib\/index\.ts [^\n]*\n +1\texport const fromIndex = 1;\n/);
      expect(defs).toMatch(/=== src\/types\.ts [^\n]*\n +1\texport interface Shape \{\n/);
      expect(defs).toMatch(/=== src\/list\.ts [^\n]*\n +3\texport \{\n +4\t  one,\n +5\t  two,\n +6\t\};\n/);
      expect(defs).toMatch(/=== src\/reexported\.ts [^\n]*\n +1\texport class Reexported \{\}\n/);
      expect(defs).toMatch(/=== src\/legacy\.js [^\n]*\n +3\tmodule\.exports = \{\n +4\t  oldOne,\n +5\t  oldTwo,\n +6\t\};\n +7\texports\.third = 3;\n/);
      // A package import is not a repository file.
      expect(defs).not.toContain('vitest');
    } finally {
      fs.rmSync(s.root, { recursive: true, force: true });
    }
  });

  it('reads nothing outside the HEAD commit: not a path that climbs out of the repository, a tracked symlink, an untracked file or a working-tree edit', () => {
    const s = scratchRepo({
      'src/commands/core.ts': [
        "import { a } from '../../../outside/secret';",
        "import { b } from '../../../../../../../../outside/secret';",
        "import { c } from '../link';",
        "import { d } from '../untracked';",
        "import { e } from '../edited';",
        '',
      ].join('\n'),
      'src/edited.ts': 'export const COMMITTED_MARKER = 1;\n',
    });
    try {
      const outside = path.join(s.root, 'outside');
      fs.mkdirSync(outside);
      fs.writeFileSync(path.join(outside, 'secret.ts'), 'export const OUTSIDE_MARKER = 1;\n');
      fs.symlinkSync(path.join(outside, 'secret.ts'), path.join(s.repo, 'src', 'link.ts'));
      commitAll(s.repo);
      // Neither of these is in the commit the review is about.
      fs.writeFileSync(path.join(s.repo, 'src', 'untracked.ts'), 'export const UNTRACKED_MARKER = 1;\n');
      fs.writeFileSync(path.join(s.repo, 'src', 'edited.ts'), 'export const WORKTREE_MARKER = 1;\n');

      const { run, defs } = collect(s, ['src/commands/core.ts']);
      expect(run.status, run.stderr).toBe(0);

      expect(defs).toContain('COMMITTED_MARKER');
      expect(defs).not.toContain('OUTSIDE_MARKER');
      expect(defs).not.toContain('UNTRACKED_MARKER');
      expect(defs).not.toContain('WORKTREE_MARKER');
      // The symlink's blob is its target's name, which declares nothing.
      expect(defs).not.toContain('src/link.ts');
    } finally {
      fs.rmSync(s.root, { recursive: true, force: true });
    }
  });

  it('drops a path that climbs above the repository root instead of reading the committed module the same path names from the root', () => {
    const s = scratchRepo({
      'src/commands/core.ts': [
        "import { a } from '../../../outside/secret';",
        "import { b } from '../../../../../../../../outside/secret';",
        "import { c } from '../../lib/ok';",
        '',
      ].join('\n'),
      // Where both climbing paths land if a '..' above the root is ignored.
      'outside/secret.ts': 'export const CLAMPED_MARKER = 1;\n',
      'lib/ok.ts': 'export const ROOT_MARKER = 1;\n',
    });
    try {
      commitAll(s.repo);
      const { run, defs } = collect(s, ['src/commands/core.ts']);
      expect(run.status, run.stderr).toBe(0);

      expect(defs).not.toContain('CLAMPED_MARKER');
      expect(defs).not.toContain('outside/secret');
      // Up to the root and down again never leaves the repository.
      expect(defs).toMatch(/=== lib\/ok\.ts [^\n]*\n +1\texport const ROOT_MARKER = 1;\n/);
    } finally {
      fs.rmSync(s.root, { recursive: true, force: true });
    }
  });

  it('skips a deleted file, a file that is not code and a file named "-" without failing, and writes an empty list when nothing resolves', () => {
    const s = scratchRepo({ 'README.md': "import { x } from './display-safe';\n", '-': "import { y } from './z';\n" });
    try {
      commitAll(s.repo);
      const { run, defs } = collect(s, ['gone.ts', 'README.md', '-']);
      expect(run.status, run.stderr).toBe(0);
      expect(defs).toBe('');
      expect(fs.existsSync(path.join(s.tmp, 'imported_defs.txt'))).toBe(true);
    } finally {
      fs.rmSync(s.root, { recursive: true, force: true });
    }
  });

  it('skips a deleted file before reading it, so the step also passes under pipefail and logs no git error for it', () => {
    const s = scratchRepo({
      'src/kept.ts': "import { helper } from './util';\n",
      'src/util.ts': 'export function helper(): number {\n  return 1;\n}\n',
    });
    try {
      commitAll(s.repo);
      // Read without the skip, the deleted path fails `git cat-file blob` at
      // the head of a pipeline. Plain -e does not see that; pipefail ends the
      // step there, before the file listed after it.
      const { run, defs } = collect(s, ['src/gone.ts', 'src/kept.ts'], PIPEFAIL);
      expect(run.status, run.stderr).toBe(0);
      expect(run.stderr).not.toContain('src/gone.ts');
      expect(defs).toMatch(/=== src\/util\.ts \(unchanged; imported by src\/kept\.ts\) ===\n +1\texport function helper\(\): number \{\n/);
    } finally {
      fs.rmSync(s.root, { recursive: true, force: true });
    }
  });

  it('stops at its size budget with a notice instead of growing the request without bound, and lists nothing after the notice', () => {
    const huge = Array.from({ length: 2500 }, (_, i) => `export const generated_${i} = ${i};`).join('\n');
    const s = scratchRepo({
      'src/a.ts': "import { small } from './small';\nimport { generated_0 } from './huge';\nimport { sameFile } from './same-file';\n",
      'src/b.ts': "import { nextFile } from './next-file';\n",
      'src/small.ts': 'export const small = 1;\n',
      'src/huge.ts': `${huge}\n`,
      'src/same-file.ts': 'export const sameFile = 1;\n',
      'src/next-file.ts': 'export const nextFile = 1;\n',
    });
    try {
      commitAll(s.repo);
      const { run, defs } = collect(s, ['src/a.ts', 'src/b.ts']);
      expect(run.status, run.stderr).toBe(0);
      expect(defs).toContain('export const small = 1;');
      expect(defs).not.toContain('generated_');
      // "remaining modules omitted" holds for the changed file that reached
      // the budget and for every changed file after it: one notice, last.
      expect(defs.match(/\[IMPORTED DEFINITIONS TRUNCATED at \d+ bytes — remaining modules omitted\]/g)).toHaveLength(1);
      expect(defs).toMatch(/\n\[IMPORTED DEFINITIONS TRUNCATED at \d+ bytes — remaining modules omitted\]\n$/);
      expect(defs).not.toContain('sameFile');
      expect(defs).not.toContain('nextFile');
    } finally {
      fs.rmSync(s.root, { recursive: true, force: true });
    }
  });

  it('lists a module once when two changed files import it under different spellings, under the first that imports it', () => {
    const s = scratchRepo({
      'src/a.ts': "import { helper } from './util.js';\n",
      'src/sub/b.ts': "import { helper } from '../util';\n",
      'src/util.ts': 'export function helper(): number {\n  return 1;\n}\n',
    });
    try {
      commitAll(s.repo);
      const { run, defs } = collect(s, ['src/a.ts', 'src/sub/b.ts']);
      expect(run.status, run.stderr).toBe(0);
      expect(defs.match(/^=== src\/util\.ts /gm)).toHaveLength(1);
      expect(defs).toContain('=== src/util.ts (unchanged; imported by src/a.ts) ===');
    } finally {
      fs.rmSync(s.root, { recursive: true, force: true });
    }
  });

  it('the prompt places the definitions between the full source files and the diff, and says so when there are none', () => {
    const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pr-review-prompt-')));
    try {
      const write = (name: string, body: string) => fs.writeFileSync(path.join(tmp, name), body);
      write('pr_title.txt', 'A title\n');
      write('pr_body.txt', 'A body');
      write('changed_files.txt', 'src/commands/core.ts\n');
      write('full_files.txt', '\n=== src/commands/core.ts ===\n     1\timport { hasDisplayHazard } from \'../display-safe\';\n');
      write('imported_defs.txt', '\n=== src/display-safe.ts (unchanged; imported by src/commands/core.ts) ===\n     5\texport function hasDisplayHazard(text: string): boolean {\n');
      write('pr_diff.txt', '+hasDisplayHazard(dir)\n');

      const script = inScratch(runScript(BUILD_STEP), tmp);
      const run = bash(script, tmp, { PR_NUMBER: '275' });
      expect(run.status, run.stderr).toBe(0);
      const msg = fs.readFileSync(path.join(tmp, 'user_msg.txt'), 'utf-8');

      const full = msg.indexOf('FULL SOURCE FILES');
      const defs = msg.indexOf(DEFS_HEADING);
      const definition = msg.indexOf('     5\texport function hasDisplayHazard');
      const diff = msg.indexOf('DIFF (changes introduced in this PR)');
      expect(full).toBeGreaterThanOrEqual(0);
      expect(defs).toBeGreaterThan(full);
      expect(definition).toBeGreaterThan(defs);
      expect(diff).toBeGreaterThan(definition);

      write('imported_defs.txt', '');
      expect(bash(script, tmp, { PR_NUMBER: '275' }).status).toBe(0);
      const none = fs.readFileSync(path.join(tmp, 'user_msg.txt'), 'utf-8');
      const at = none.indexOf(DEFS_HEADING);
      expect(at).toBeGreaterThanOrEqual(0);
      expect(none.slice(at, none.indexOf('DIFF (changes introduced in this PR)'))).toContain('(none)');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('the system prompt names the section, refuses "undefined" for a listed symbol and caps at MEDIUM a finding on code it was not shown', () => {
    const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pr-review-prompt-')));
    try {
      for (const name of ['pr_title.txt', 'pr_body.txt', 'changed_files.txt', 'full_files.txt', 'imported_defs.txt', 'pr_diff.txt']) {
        fs.writeFileSync(path.join(tmp, name), '');
      }
      const run = bash(inScratch(runScript(BUILD_STEP), tmp), tmp, { PR_NUMBER: '275' });
      expect(run.status, run.stderr).toBe(0);
      const system = fs.readFileSync(path.join(tmp, 'system_prompt.txt'), 'utf-8');

      expect(system).toContain(`2. ${DEFS_HEADING}`);
      expect(system).toMatch(new RegExp(`- A symbol reported as undefined[^\\n]*${DEFS_HEADING} lists its declaration`));
      expect(system).toContain('Report it as MEDIUM at most');
      expect(system).toContain('Never report CRITICAL or HIGH on code you were not shown.');
      // MEDIUM does not block: the approve rule is unchanged.
      expect(system).toContain('- APPROVE if no CRITICAL or HIGH findings remain after verification');
      // The nonce placeholder is still left for the shared action to fill.
      expect(system.split('\n')).toContain('VERDICT-__NONCE__: APPROVE');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
