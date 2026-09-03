import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * The `gate` check in .github/workflows/ci.yml, and the evidence that it reports
 * on a docs-only change and on a code change alike.
 *
 * Why this file exists. `ci.yml` used to be `paths:`-filtered to `src/**`,
 * `package.json` and `tsconfig.json`, and its only job was the matrix-named
 * `build-and-test`. A docs-only pull request therefore produced no CI run at
 * all, so the context never reported — and a required context that never reports
 * blocks the pull request permanently. The repository could not require its own
 * test suite, which left one automated model review as the only non-gate-file
 * check on main.
 *
 * The fix moves the path filter off the trigger and into the run. That trades
 * one failure mode for a worse one if it is done carelessly: a classifier that
 * misreads a code change as docs turns the required check into a rubber stamp
 * that reports success without ever having built anything. So the assertions
 * below run BOTH directions, and they run them against the real artifact —
 * every classify/verdict case spawns `.github/scripts/ci-gate.mjs`, the same
 * file and the same environment variables the workflow uses, rather than a
 * re-implementation that could only ever prove it agrees with itself.
 */

const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const GATE_SCRIPT = path.join(REPO_ROOT, '.github', 'scripts', 'ci-gate.mjs');
const WORKFLOW_PATH = path.join(REPO_ROOT, '.github', 'workflows', 'ci.yml');
const WORKFLOW = fs.readFileSync(WORKFLOW_PATH, 'utf-8');

/** The check name branch protection is meant to require. */
const GATE_CHECK_NAME = 'gate';

// ---------------------------------------------------------------------------
// Running the committed gate script
// ---------------------------------------------------------------------------

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  outputs: Record<string, string>;
}

function parseStepOutputs(raw: string): Record<string, string> {
  const outputs: Record<string, string> = {};
  for (const line of raw.split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) outputs[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return outputs;
}

/** Run the workflow's `Classify the change` step over a changed-file list. */
function classify(files: string[], options: { unresolvedBase?: boolean } = {}): Run {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-gate-'));
  const listFile = path.join(dir, 'changed-files.txt');
  const outputFile = path.join(dir, 'github-output.txt');
  fs.writeFileSync(listFile, files.length > 0 ? `${files.join('\n')}\n` : '');
  fs.writeFileSync(outputFile, '');

  const run = spawnSync(process.execPath, [GATE_SCRIPT, 'classify'], {
    encoding: 'utf-8',
    env: {
      ...process.env,
      CHANGED_FILES_FILE: listFile,
      UNRESOLVED_BASE: options.unresolvedBase === true ? 'true' : 'false',
      // Always pinned to the temp file. This suite itself runs inside the gate
      // job, where GITHUB_OUTPUT is set to the real step-output file.
      GITHUB_OUTPUT: outputFile,
    },
  });

  return {
    status: run.status,
    stdout: run.stdout ?? '',
    stderr: run.stderr ?? '',
    outputs: parseStepOutputs(fs.readFileSync(outputFile, 'utf-8')),
  };
}

/** Run the workflow's `Gate verdict` step. Exit 0 is a green `gate` check. */
function verdict(state: { code?: string; npmCi?: string; build?: string; test?: string }): Run {
  const run = spawnSync(process.execPath, [GATE_SCRIPT, 'verdict'], {
    encoding: 'utf-8',
    env: {
      ...process.env,
      GATE_CODE: state.code ?? '',
      GATE_NPM_CI_OUTCOME: state.npmCi ?? '',
      GATE_BUILD_OUTCOME: state.build ?? '',
      GATE_TEST_OUTCOME: state.test ?? '',
    },
  });
  return { status: run.status, stdout: run.stdout ?? '', stderr: run.stderr ?? '', outputs: {} };
}

/** What the three suite steps report when the `if:` on them does not match. */
const SUITE_SKIPPED = { npmCi: 'skipped', build: 'skipped', test: 'skipped' };
const SUITE_PASSED = { npmCi: 'success', build: 'success', test: 'success' };

// ---------------------------------------------------------------------------
// Reading ci.yml
//
// No YAML parser is available (adding a dependency to assert on CI config is a
// worse trade than an indent walk), so these read the file by block. Comment
// lines are stripped first: this workflow documents the filter it removed, and
// a naive substring search would find `paths:` in the prose explaining why there
// is no longer a `paths:`.
// ---------------------------------------------------------------------------

function stripComments(block: string): string {
  return block
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
}

/** The `on:` / `jobs:` block: the key line plus everything indented under it. */
function topLevelBlock(key: string): string {
  const lines = WORKFLOW.split('\n');
  const start = lines.findIndex((line) => line === `${key}:` || line.startsWith(`${key}:`));
  expect(start, `ci.yml has no top-level "${key}:"`).toBeGreaterThanOrEqual(0);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || /^\s/.test(lines[end]))) end += 1;
  return lines.slice(start, end).join('\n');
}

/** One job's block, keyed by its id under `jobs:`. */
function jobBlock(jobId: string): string {
  const lines = topLevelBlock('jobs').split('\n');
  const start = lines.findIndex((line) => line === `  ${jobId}:`);
  expect(start, `ci.yml has no job "${jobId}"`).toBeGreaterThanOrEqual(0);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || /^ {3,}/.test(lines[end]))) end += 1;
  return lines.slice(start, end).join('\n');
}

/** Job-level keys sit at four spaces; step-level keys sit deeper. */
function jobLevelKeys(block: string): string[] {
  return block
    .split('\n')
    .map((line) => /^ {4}([A-Za-z][A-Za-z0-9_-]*):/.exec(line))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => m[1]);
}

// ---------------------------------------------------------------------------

describe('the CI gate reports on every change to main', () => {
  it('SLS-01.AC1 ci.yml triggers on every push to main and every pull_request to main with no paths filter', () => {
    const on = stripComments(topLevelBlock('on'));

    expect(on).toContain('push:');
    expect(on).toContain('pull_request:');
    // Both triggers stay scoped to main, and to main only.
    expect(on.match(/^ {4}branches: \[main\]$/gm)).toHaveLength(2);

    // The defect being closed: a filter on the trigger decides whether the check
    // EXISTS, and a check that does not exist can never be required.
    expect(on).not.toMatch(/^\s*paths:/m);
    expect(on).not.toMatch(/^\s*paths-ignore:/m);
  });

  it('SLS-01.AC1 the gate job reports a fixed check name that no matrix can interpolate', () => {
    const gate = jobBlock(GATE_CHECK_NAME);

    expect(gate).toMatch(new RegExp(`^ {4}name: ${GATE_CHECK_NAME}$`, 'm'));
    // `name: Node ${{ matrix.node-version }}` is a different context string per
    // leg and changes whenever the matrix does, so it cannot be a required
    // context. The gate's name is a literal.
    expect(gate).not.toContain('${{ matrix.');
    expect(jobLevelKeys(gate)).not.toContain('strategy');

    // No job-level `if:`: a condition here would make the job SKIP on some
    // changes, and a skipped required context never reports a conclusion —
    // which is the same wedge as the paths filter, one level down.
    expect(jobLevelKeys(gate)).not.toContain('if');
  });

  it('SLS-01.AC1 the gate job classifies the change in-run and runs the full suite on a code change', () => {
    const gate = jobBlock(GATE_CHECK_NAME);

    // Classification happens inside the run, from committed logic.
    expect(gate).toContain('run: node .github/scripts/ci-gate.mjs classify');
    expect(gate).toContain('run: node .github/scripts/ci-gate.mjs verdict');

    // The full suite, in the gate job itself, conditioned on the classification:
    // setup-node plus the three suite steps.
    for (const step of ['run: npm ci', 'run: npm run build', 'run: npm test']) {
      expect(gate).toContain(step);
    }
    expect(gate.match(/^ {8}if: steps\.classify\.outputs\.code == 'true'$/gm)).toHaveLength(4);
  });

  it('SLS-01.AC1 a code change whose suite passes is a pass and one whose suite fails is a fail', () => {
    expect(verdict({ code: 'true', ...SUITE_PASSED }).status).toBe(0);

    const failed = verdict({ code: 'true', npmCi: 'success', build: 'success', test: 'failure' });
    expect(failed.status).toBe(1);
    expect(failed.stdout).toContain('reason=suite-did-not-pass');
  });

  it('SLS-01.AC1 a non-code change is a deterministic pass without the suite', () => {
    const docs = verdict({ code: 'false', ...SUITE_SKIPPED });
    expect(docs.status).toBe(0);
    expect(docs.stdout).toContain('reason=non-code-change');

    // Deterministic: the same inputs give the same answer, and no suite outcome
    // is consulted on a non-code change.
    expect(verdict({ code: 'false' }).status).toBe(0);
    expect(verdict({ code: 'false', npmCi: 'failure', build: 'failure', test: 'failure' }).status).toBe(0);
  });
});

describe('the gate cannot silently skip the suite on a code change', () => {
  it('SLS-01.AC2 a change set touching only docs is classified non-code', () => {
    const run = classify(['README.md', 'CHANGELOG.md', 'docs/USE-CASES.md', 'STATUS.md']);
    expect(run.status).toBe(0);
    expect(run.outputs.code).toBe('false');
    expect(run.outputs.reason).toBe('no-code-paths-changed');
  });

  it('SLS-01.AC2 a change set touching src/** is classified code', () => {
    const run = classify(['README.md', 'src/cli.ts']);
    expect(run.status).toBe(0);
    expect(run.outputs.code).toBe('true');

    // Nested, too — `src/**` crosses directory separators.
    expect(classify(['src/broker/policy.ts']).outputs.code).toBe('true');
  });

  it('SLS-01.AC2 a change set touching package.json is classified code', () => {
    const run = classify(['package.json']);
    expect(run.status).toBe(0);
    expect(run.outputs.code).toBe('true');
    expect(run.outputs.reason).toBe('code-paths-changed');
  });

  it('SLS-01.AC2 the classifier covers every glob the removed trigger filter used, plus the gate itself', () => {
    const cases: Array<[string, string]> = [
      ['src/index.ts', 'the old src/** glob'],
      ['package.json', 'the old package.json glob'],
      ['tsconfig.json', 'the old tsconfig.json glob'],
      ['.github/workflows/ci.yml', 'the workflow that defines the gate'],
      ['.github/scripts/ci-gate.mjs', 'the classifier the gate runs'],
    ];
    for (const [file, why] of cases) {
      expect(classify([file]).outputs.code, `${file} (${why}) must classify as code`).toBe('true');
    }

    // A single `*` does not cross a separator: `package.json` must not drag in
    // an unrelated path that merely ends the same way.
    expect(classify(['docs/package.json']).outputs.code).toBe('false');
    expect(classify(['other/src/app.ts']).outputs.code).toBe('false');
  });

  it('SLS-01.AC2 a code-classified run in which the suite did not execute is a failure, never a pass', () => {
    // The exact shape of the hole: the classifier said "code", and the suite
    // steps were skipped anyway (a mistyped `if:`, a condition that stopped
    // matching). `skipped` is not `success`.
    const skipped = verdict({ code: 'true', ...SUITE_SKIPPED });
    expect(skipped.status).toBe(1);
    expect(skipped.stdout).toContain('reason=suite-did-not-pass');
    expect(skipped.stderr).toContain('npm ci, npm run build, npm test');

    // Each step individually, so a partial suite cannot pass either.
    expect(verdict({ code: 'true', npmCi: 'skipped', build: 'success', test: 'success' }).status).toBe(1);
    expect(verdict({ code: 'true', npmCi: 'success', build: 'skipped', test: 'success' }).status).toBe(1);
    expect(verdict({ code: 'true', npmCi: 'success', build: 'success', test: 'skipped' }).status).toBe(1);
    expect(verdict({ code: 'true', npmCi: 'success', build: 'success', test: 'cancelled' }).status).toBe(1);
  });

  it('SLS-01.AC2 a classification the gate cannot read fails the gate rather than reading as non-code', () => {
    // The classify step crashed or was skipped, so `code` is empty. Absent is
    // not false.
    const unset = verdict({ ...SUITE_SKIPPED });
    expect(unset.status).toBe(1);
    expect(unset.stdout).toContain('reason=unknown-classification');

    expect(verdict({ code: 'FALSE', ...SUITE_SKIPPED }).status).toBe(1);
    expect(verdict({ code: '0', ...SUITE_SKIPPED }).status).toBe(1);
  });

  it('SLS-01.AC2 an unresolvable base classifies as code instead of as an empty change', () => {
    // A branch's first push reports an all-zero `before`, and a force-push can
    // orphan the previous tip. Either way the file list is unknown, not empty.
    const run = classify([], { unresolvedBase: true });
    expect(run.outputs.code).toBe('true');
    expect(run.outputs.reason).toBe('unresolved-base');

    // And an UNRESOLVED_BASE the script does not recognise fails the step, which
    // leaves `code` unset, which fails the verdict.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-gate-'));
    const listFile = path.join(dir, 'changed-files.txt');
    fs.writeFileSync(listFile, 'README.md\n');
    const bad = spawnSync(process.execPath, [GATE_SCRIPT, 'classify'], {
      encoding: 'utf-8',
      env: { ...process.env, CHANGED_FILES_FILE: listFile, UNRESOLVED_BASE: 'maybe', GITHUB_OUTPUT: '' },
    });
    expect(bad.status).toBe(2);
  });

  it('SLS-01.AC2 the build-and-test matrix job keeps its id, its check names and its steps', () => {
    const matrix = jobBlock('build-and-test');

    // Not deleted, not renamed: same job id, same interpolated name, same two
    // Node versions, same three commands.
    expect(matrix).toMatch(/^ {4}name: Node \$\{\{ matrix\.node-version \}\}$/m);
    expect(matrix).toMatch(/^ {8}node-version: \[20, 22\]$/m);
    expect(matrix).toContain('uses: actions/checkout@v4');
    expect(matrix).toContain('uses: actions/setup-node@v4');
    expect(matrix).toContain('- run: npm ci');
    expect(matrix).toContain('- run: npm run build');
    expect(matrix).toContain('- run: npm test');

    // Its run set is unchanged too. The workflow-level `paths:` filter that used
    // to keep it off non-code changes is gone, so the same classification now
    // gates it here — without this the whole matrix would run on every README
    // commit.
    expect(matrix).toMatch(/^ {4}needs: gate$/m);
    expect(matrix).toMatch(/^ {4}if: needs\.gate\.outputs\.code == 'true'$/m);
  });
});

describe('the same gate check reports on a docs-only change and on a src change', () => {
  it('SLS-01.AC3 one job named gate, with nothing that can stop it reporting on either shape', () => {
    const jobs = stripComments(topLevelBlock('jobs'));
    const jobIds = jobs
      .split('\n')
      .map((line) => /^ {2}([A-Za-z][A-Za-z0-9_-]*):/.exec(line))
      .filter((m): m is RegExpExecArray => m !== null)
      .map((m) => m[1]);
    expect(jobIds).toContain(GATE_CHECK_NAME);

    // Exactly one job carries this name, so "the gate" is one context and not a
    // family of them.
    const named = WORKFLOW.match(new RegExp(`^ {4}name: ${GATE_CHECK_NAME}$`, 'gm'));
    expect(named).toHaveLength(1);

    // Nothing between the change and the run: no trigger filter, no job-level
    // condition, no matrix. Whatever the change is, this job starts and reports.
    const gate = jobBlock(GATE_CHECK_NAME);
    expect(stripComments(topLevelBlock('on'))).not.toMatch(/^\s*paths(-ignore)?:/m);
    expect(jobLevelKeys(gate)).not.toContain('if');
    expect(jobLevelKeys(gate)).not.toContain('strategy');
  });

  it('SLS-01.AC3 the docs-only case and the src case both end in a green gate, by the two paths they should', () => {
    // Case 1 — a docs-only change. Under the old trigger filter this produced no
    // run and therefore no context at all.
    const docs = classify(['README.md', 'docs/use-cases/run-broker.md']);
    expect(docs.outputs.code).toBe('false');
    const docsVerdict = verdict({ code: docs.outputs.code, ...SUITE_SKIPPED });
    expect(docsVerdict.status).toBe(0);
    expect(docsVerdict.stdout).toContain('reason=non-code-change');

    // Case 2 — a src change, same job, same check name, suite actually run.
    const code = classify(['src/scan.ts', 'src/scan.test.ts']);
    expect(code.outputs.code).toBe('true');
    const codeVerdict = verdict({ code: code.outputs.code, ...SUITE_PASSED });
    expect(codeVerdict.status).toBe(0);
    expect(codeVerdict.stdout).toContain('reason=suite-passed');

    // The reported context is the same string in both cases — that is the
    // property branch protection needs, and the reason the two runs differ only
    // in what they did, never in what they are called.
    expect(jobBlock(GATE_CHECK_NAME)).toMatch(new RegExp(`^ {4}name: ${GATE_CHECK_NAME}$`, 'm'));
  });

  it('SLS-01.AC4 the gate classifies before npm ci, so its script imports only node: builtins', () => {
    // The classify step runs before setup-node and before `npm ci` — it has to,
    // since a docs-only change must reach a conclusion without installing
    // anything. A single third-party import here would make every docs-only run
    // fail on a module it cannot resolve.
    const script = fs.readFileSync(GATE_SCRIPT, 'utf-8');
    const imports = [...script.matchAll(/^import .* from '([^']+)';$/gm)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const specifier of imports) {
      expect(specifier, `${specifier} is not a node: builtin`).toMatch(/^node:/);
    }
  });
});
