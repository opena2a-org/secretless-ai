import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { pathToFileURL } from 'url';

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
 *
 * The matrix legs `Node 20` and `Node 22` are in the required set the ci.yml
 * header names, so they report on every change too: `build-and-test` carries no
 * job-level `if:`, runs its suite steps on a code change and ends in the same
 * verdict step as `gate`. And every change that changes a file is code. The documentation list
 * in the script is empty, because the suite reads Markdown: a docs-only change
 * that skipped the suite could break it and still merge with every check green.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
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
function topLevelBlock(key: string, workflow: string = WORKFLOW): string {
  const lines = workflow.split('\n');
  const start = lines.findIndex((line) => line === `${key}:` || line.startsWith(`${key}:`));
  expect(start, `ci.yml has no top-level "${key}:"`).toBeGreaterThanOrEqual(0);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || /^\s/.test(lines[end]))) end += 1;
  return lines.slice(start, end).join('\n');
}

/** One job's block, keyed by its id under `jobs:`. */
function jobBlock(jobId: string, workflow: string = WORKFLOW): string {
  const lines = topLevelBlock('jobs', workflow).split('\n');
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
  it('a change set touching only documentation is classified code', () => {
    const run = classify(['README.md', 'CHANGELOG.md', 'docs/USE-CASES.md', 'STATUS.md']);
    expect(run.status).toBe(0);
    expect(run.outputs.code).toBe('true');
    expect(run.outputs.reason).toBe('code-paths-changed');
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

    // Paths the old globs never named are code too, because the documentation
    // list is empty.
    expect(classify(['docs/package.json']).outputs.code).toBe('true');
    expect(classify(['other/src/app.ts']).outputs.code).toBe('true');
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

    // It reports on every change: there is no job-level `if:`, so neither leg
    // is skipped before it reports. Its suite steps carry the condition
    // instead, and the shape of those steps is pinned further down.
    expect(matrix).toMatch(/^ {4}needs: gate$/m);
    expect(jobLevelKeys(stripComments(matrix))).not.toContain('if');
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

  it('SLS-01.AC3 a docs-only change and a src change both classify as code under the same gate check, and a non-code verdict passes without the suite', () => {
    // Case 1: a docs-only change. Under the old trigger filter this produced no
    // run and therefore no context at all. Now it is code, and the suite runs.
    const docs = classify(['README.md', 'docs/use-cases/run-broker.md']);
    expect(docs.outputs.code).toBe('true');
    // The non-code verdict, read directly as the deterministic-pass case does.
    const nonCodeVerdict = verdict({ code: 'false', ...SUITE_SKIPPED });
    expect(nonCodeVerdict.status).toBe(0);
    expect(nonCodeVerdict.stdout).toContain('reason=non-code-change');

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

// ---------------------------------------------------------------------------
// Every change that changes a file is code
// ---------------------------------------------------------------------------

/**
 * The committed script's exports, read by importing it in a separate node
 * process, the same way the classify and verdict cases run it.
 */
function gateExports(): { docPathGlobs: unknown; names: string[] } {
  const program = [
    `import(${JSON.stringify(pathToFileURL(GATE_SCRIPT).href)}).then((m) => {`,
    '  const docPathGlobs = m.DOC_PATH_GLOBS === undefined ? null : m.DOC_PATH_GLOBS;',
    '  process.stdout.write(JSON.stringify({ docPathGlobs, names: Object.keys(m) }));',
    '});',
  ].join('\n');
  const run = spawnSync(process.execPath, ['-e', program], { encoding: 'utf-8' });
  expect(run.status, run.stderr).toBe(0);
  return JSON.parse(run.stdout);
}

/** The changed-file command the gate job must run, verbatim. */
const RENAME_SAFE_DIFF =
  'git -c core.quotePath=false diff --no-renames --name-only "${base}...${head}" > "$CHANGED_FILES_FILE"';

/**
 * The environment for a scratch git repository. A git hook can run this suite
 * with GIT_DIR and its siblings exported for the repository under test, and git
 * honours them over the working directory, so every GIT_ variable is dropped.
 * The system and user git config are left out as well, so a diff setting on
 * the machine running the suite cannot change what the command lists.
 */
function scratchGitEnv(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (!name.startsWith('GIT_')) env[name] = value;
  }
  return {
    ...env,
    HOME: home,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: os.devNull,
    GIT_AUTHOR_NAME: 'ci-gate test',
    GIT_AUTHOR_EMAIL: 'ci-gate-test@example.invalid',
    GIT_COMMITTER_NAME: 'ci-gate test',
    GIT_COMMITTER_EMAIL: 'ci-gate-test@example.invalid',
  };
}

function scratchGit(repo: string, env: NodeJS.ProcessEnv, args: string[]): string {
  const run = spawnSync('git', ['-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main', ...args], {
    cwd: repo,
    env,
    encoding: 'utf-8',
  });
  expect(run.status, `git ${args.join(' ')}: ${run.stderr}`).toBe(0);
  return run.stdout;
}

describe('every change that changes a file is code', () => {
  it('the documentation list is empty and the script exports no list of code paths', () => {
    const { docPathGlobs, names } = gateExports();
    expect(docPathGlobs).toEqual([]);
    expect(names).toContain('DOC_PATH_GLOBS');
    expect(names).not.toContain('CODE_PATH_GLOBS');
  });

  const singlePaths = [
    'package-lock.json',
    'vitest.config.ts',
    'scripts/release-artifact-review.mjs',
    '.gitignore',
    'brand-new-dir/new-file.txt',
    'README.md',
    'docs/x.md',
    'CHANGELOG.md',
    'SECURITY.md',
    'STATUS.md',
    'LICENSE',
    '.github/workflows/gate-file-approval.yml',
  ];
  for (const file of singlePaths) {
    it(`${file} alone classifies as code`, () => {
      const run = classify([file]);
      expect(run.status).toBe(0);
      expect(run.outputs.code).toBe('true');
      expect(run.outputs.reason).toBe('code-paths-changed');
    });
  }

  it('README.md with package-lock.json classifies as code', () => {
    const run = classify(['README.md', 'package-lock.json']);
    expect(run.status).toBe(0);
    expect(run.outputs.code).toBe('true');
  });

  it('an empty change list with a resolved base stays non-code', () => {
    // An empty three-dot diff changes no file, so it is the one change the
    // suite has nothing to say about.
    const run = classify([]);
    expect(run.status).toBe(0);
    expect(run.outputs.code).toBe('false');
    expect(run.outputs.reason).toBe('no-files-changed');
  });

  it('a rename of src/policy.ts to STATUS.md, run through the workflow diff command, lists both paths and classifies as code', () => {
    const commands = stripComments(WORKFLOW)
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.includes('git -c core.quotePath=false diff') && line.includes('--name-only'));
    expect(commands).toHaveLength(1);
    const command = commands[0];
    expect(command).toBe(RENAME_SAFE_DIFF);

    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-gate-rename-'));
    try {
      const repo = path.join(scratch, 'repo');
      fs.mkdirSync(path.join(repo, 'src'), { recursive: true });
      const env = scratchGitEnv(scratch);
      scratchGit(repo, env, ['init', '-q']);
      fs.writeFileSync(path.join(repo, 'src', 'policy.ts'), 'export const policy = 1;\n');
      scratchGit(repo, env, ['add', 'src/policy.ts']);
      scratchGit(repo, env, ['commit', '-q', '-m', 'base']);
      scratchGit(repo, env, ['mv', 'src/policy.ts', 'STATUS.md']);
      scratchGit(repo, env, ['commit', '-q', '-m', 'rename']);
      const base = scratchGit(repo, env, ['rev-parse', 'HEAD~1']).trim();
      const head = scratchGit(repo, env, ['rev-parse', 'HEAD']).trim();

      const listedBy = (line: string): string[] => {
        const listFile = path.join(scratch, 'changed-files.txt');
        const run = spawnSync('bash', ['-c', line], {
          cwd: repo,
          env: { ...env, base, head, CHANGED_FILES_FILE: listFile },
          encoding: 'utf-8',
        });
        expect(run.status, run.stderr).toBe(0);
        return fs
          .readFileSync(listFile, 'utf-8')
          .split('\n')
          .filter((entry) => entry !== '')
          .sort();
      };

      const listed = listedBy(command);
      expect(listed).toEqual(['STATUS.md', 'src/policy.ts']);
      expect(classify(listed).outputs.code).toBe('true');

      // The control: without --no-renames git reports the rename by its
      // destination alone, and the path it left would never reach the classifier.
      expect(listedBy(command.replace(' --no-renames', ''))).toEqual(['STATUS.md']);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// The matrix legs report on every change
// ---------------------------------------------------------------------------

/** The four `env:` lines of the leg verdict step, leading spaces removed. */
const LEG_VERDICT_ENV = [
  'GATE_CODE: ${{ needs.gate.outputs.code }}',
  'GATE_NPM_CI_OUTCOME: ${{ steps.npm_ci.outcome }}',
  'GATE_BUILD_OUTCOME: ${{ steps.build.outcome }}',
  'GATE_TEST_OUTCOME: ${{ steps.test.outcome }}',
];

/** Each job's `run:` lines in order, leading spaces removed, compared whole. */
const LEG_RUN_LINES = [
  'run: |',
  '- run: npm ci',
  '- run: npm run build',
  '- run: npm test',
  'run: node .github/scripts/ci-gate.mjs verdict',
];
const GATE_RUN_LINES = [
  'run: |',
  'run: |',
  'run: node .github/scripts/ci-gate.mjs classify',
  'run: npm ci',
  'run: npm run build',
  'run: npm test',
  'run: node .github/scripts/ci-gate.mjs verdict',
];

function dedent(line: string): string {
  return line.replace(/^ +/, '');
}

function runLines(block: string): string[] {
  return block
    .split('\n')
    .map(dedent)
    .filter((line) => line.startsWith('run:') || line.startsWith('- run:'));
}

/**
 * What is wrong with the shape of `build-and-test`, and with the suite and
 * verdict lines of `gate`, in a ci.yml text: empty when nothing is. It is a
 * function over text so that a regression can be planted in a string built
 * inside a test, never in the workflow.
 */
function legShapeViolations(workflow: string): string[] {
  const violations: string[] = [];
  const legs = stripComments(jobBlock('build-and-test', workflow));
  const gate = stripComments(jobBlock(GATE_CHECK_NAME, workflow));
  const legLines = legs.split('\n');

  const keys = jobLevelKeys(legs).join(', ');
  if (keys !== 'name, needs, runs-on, strategy, steps') {
    violations.push(`build-and-test job-level keys are "${keys}"`);
  }
  if (!/^ {4}needs: gate$/m.test(legs)) {
    violations.push('build-and-test does not need gate');
  }

  const suiteConditions = legs.match(/^ {8}if: needs\.gate\.outputs\.code == 'true'$/gm) ?? [];
  if (suiteConditions.length !== 4) {
    violations.push(`build-and-test has ${suiteConditions.length} suite conditions, not 4`);
  }

  const always = legLines.flatMap((line, index) => (/^ {8}if: always\(\)$/.test(line) ? [index] : []));
  const testStep = legLines.findIndex((line) => dedent(line) === '- run: npm test');
  if (always.length !== 1) {
    violations.push(`build-and-test has ${always.length} if: always() lines, not 1`);
  } else if (testStep === -1 || always[0] < testStep) {
    violations.push('the if: always() step of build-and-test does not follow its npm test step');
  }

  for (const env of LEG_VERDICT_ENV) {
    const count = legLines.filter((line) => dedent(line) === env).length;
    if (count !== 1) violations.push(`build-and-test carries "${env}" ${count} times, not once`);
  }

  for (const [jobId, block, expected] of [
    ['build-and-test', legs, LEG_RUN_LINES],
    [GATE_CHECK_NAME, gate, GATE_RUN_LINES],
  ] as const) {
    const actual = runLines(block);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      violations.push(`${jobId} run lines are ${JSON.stringify(actual)}`);
    }
    for (const line of block.split('\n')) {
      if (/^\s*(- )?(continue-on-error|shell|working-directory|defaults):/.test(line)) {
        violations.push(`${jobId} carries "${line.trim()}"`);
      }
    }
  }
  return violations;
}

/** ci.yml with the first `from` inside job `jobId` replaced by `to`. */
function plantInJob(jobId: string, from: string, to: string): string {
  const lines = WORKFLOW.split('\n');
  const start = lines.indexOf(`  ${jobId}:`);
  expect(start, `ci.yml has no job "${jobId}"`).toBeGreaterThanOrEqual(0);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || /^ {3,}/.test(lines[end]))) end += 1;
  const job = lines.slice(start, end).join('\n');
  const at = job.indexOf(from);
  expect(at, `"${from.trim()}" is not in job ${jobId}`).toBeGreaterThanOrEqual(0);
  const planted = job.slice(0, at) + to + job.slice(at + from.length);
  return [...lines.slice(0, start), planted, ...lines.slice(end)].join('\n');
}

/**
 * ci.yml with every blank line and every line whose first non-space character
 * is `#` removed. Any change to what the workflow runs changes this list.
 */
const CI_EXECUTABLE_LINES = [
  "name: CI",
  "on:",
  "  push:",
  "    branches: [main]",
  "  pull_request:",
  "    branches: [main]",
  "concurrency:",
  "  group: ci-${{ github.ref }}",
  "  cancel-in-progress: true",
  "permissions:",
  "  contents: read",
  "jobs:",
  "  gate:",
  "    name: gate",
  "    runs-on: ubuntu-latest",
  "    outputs:",
  "      code: ${{ steps.classify.outputs.code }}",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "        with:",
  "          fetch-depth: 0",
  "          persist-credentials: false",
  "      - name: Guard against tracked install-config files",
  "        run: |",
  "          if git ls-files | grep -E '(^|/)(\\.npmrc|\\.yarnrc(\\.yml)?|\\.pnpmfile\\.cjs|\\.envrc)$'; then",
  "            echo \"::error::A tracked install-config file can redirect or preload the install\"",
  "            exit 1",
  "          fi",
  "      - name: Collect the changed files",
  "        id: changed",
  "        env:",
  "          EVENT_NAME: ${{ github.event_name }}",
  "          PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}",
  "          PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
  "          PUSH_BEFORE_SHA: ${{ github.event.before }}",
  "          PUSH_AFTER_SHA: ${{ github.sha }}",
  "          CHANGED_FILES_FILE: ${{ runner.temp }}/changed-files.txt",
  "        run: |",
  "          set -euo pipefail",
  "          : > \"$CHANGED_FILES_FILE\"",
  "          unresolved=false",
  "          if [ \"$EVENT_NAME\" = \"pull_request\" ]; then",
  "            base=\"$PR_BASE_SHA\"",
  "            head=\"$PR_HEAD_SHA\"",
  "          else",
  "            base=\"$PUSH_BEFORE_SHA\"",
  "            head=\"$PUSH_AFTER_SHA\"",
  "          fi",
  "          if [ -z \"$base\" ] || [ -z \"$head\" ] \\",
  "            || ! git cat-file -e \"${base}^{commit}\" 2>/dev/null \\",
  "            || ! git cat-file -e \"${head}^{commit}\" 2>/dev/null; then",
  "            unresolved=true",
  "            echo \"Base '${base:-<empty>}' or head '${head:-<empty>}' could not be resolved; the change will be treated as code.\"",
  "          else",
  "            git -c core.quotePath=false diff --no-renames --name-only \"${base}...${head}\" > \"$CHANGED_FILES_FILE\"",
  "          fi",
  "          echo \"unresolved-base=$unresolved\" >> \"$GITHUB_OUTPUT\"",
  "          echo \"Changed files:\"",
  "          cat \"$CHANGED_FILES_FILE\"",
  "      - name: Classify the change",
  "        id: classify",
  "        env:",
  "          CHANGED_FILES_FILE: ${{ runner.temp }}/changed-files.txt",
  "          UNRESOLVED_BASE: ${{ steps.changed.outputs.unresolved-base }}",
  "        run: node .github/scripts/ci-gate.mjs classify",
  "      - uses: actions/setup-node@v4",
  "        if: steps.classify.outputs.code == 'true'",
  "        with:",
  "          node-version: 20",
  "          cache: npm",
  "      - id: npm_ci",
  "        if: steps.classify.outputs.code == 'true'",
  "        run: npm ci",
  "      - id: build",
  "        if: steps.classify.outputs.code == 'true'",
  "        run: npm run build",
  "      - id: test",
  "        if: steps.classify.outputs.code == 'true'",
  "        run: npm test",
  "      - name: Gate verdict",
  "        if: always()",
  "        env:",
  "          GATE_CODE: ${{ steps.classify.outputs.code }}",
  "          GATE_NPM_CI_OUTCOME: ${{ steps.npm_ci.outcome }}",
  "          GATE_BUILD_OUTCOME: ${{ steps.build.outcome }}",
  "          GATE_TEST_OUTCOME: ${{ steps.test.outcome }}",
  "        run: node .github/scripts/ci-gate.mjs verdict",
  "  build-and-test:",
  "    name: Node ${{ matrix.node-version }}",
  "    needs: gate",
  "    runs-on: ubuntu-latest",
  "    strategy:",
  "      matrix:",
  "        node-version: [20, 22]",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - name: Guard against tracked install-config files",
  "        run: |",
  "          if git ls-files | grep -E '(^|/)(\\.npmrc|\\.yarnrc(\\.yml)?|\\.pnpmfile\\.cjs|\\.envrc)$'; then",
  "            echo \"::error::A tracked install-config file can redirect or preload the install\"",
  "            exit 1",
  "          fi",
  "      - uses: actions/setup-node@v4",
  "        if: needs.gate.outputs.code == 'true'",
  "        with:",
  "          node-version: ${{ matrix.node-version }}",
  "          cache: npm",
  "      - run: npm ci",
  "        id: npm_ci",
  "        if: needs.gate.outputs.code == 'true'",
  "      - run: npm run build",
  "        id: build",
  "        if: needs.gate.outputs.code == 'true'",
  "      - run: npm test",
  "        id: test",
  "        if: needs.gate.outputs.code == 'true'",
  "      - name: Gate verdict",
  "        if: always()",
  "        env:",
  "          GATE_CODE: ${{ needs.gate.outputs.code }}",
  "          GATE_NPM_CI_OUTCOME: ${{ steps.npm_ci.outcome }}",
  "          GATE_BUILD_OUTCOME: ${{ steps.build.outcome }}",
  "          GATE_TEST_OUTCOME: ${{ steps.test.outcome }}",
  "        run: node .github/scripts/ci-gate.mjs verdict",
];

describe('the matrix legs report on every change', () => {
  it('build-and-test has no job-level if:, runs its suite on a code change and ends in the gate verdict', () => {
    expect(legShapeViolations(WORKFLOW)).toEqual([]);
  });

  it('the leg shape check refuses each planted regression of a suite or verdict line', () => {
    const verdictRun = 'run: node .github/scripts/ci-gate.mjs verdict';
    const regressions: Array<[string, string]> = [
      ['the leg npm test step ends in || true', plantInJob('build-and-test', '- run: npm test\n', '- run: npm test || true\n')],
      [
        'the leg npm test step selects no test',
        plantInJob('build-and-test', '- run: npm test\n', '- run: npm test -- --passWithNoTests -t zz-none\n'),
      ],
      ['the leg verdict ends in || true', plantInJob('build-and-test', verdictRun, `${verdictRun} || true`)],
      [
        'the leg verdict step continues on error',
        plantInJob('build-and-test', '        if: always()\n', '        if: always()\n        continue-on-error: true\n'),
      ],
      [
        'build-and-test continues on error at job level',
        plantInJob('build-and-test', '    needs: gate\n', '    needs: gate\n    continue-on-error: true\n'),
      ],
      ['the gate npm test step ends in || true', plantInJob(GATE_CHECK_NAME, 'run: npm test\n', 'run: npm test || true\n')],
      ['the gate verdict ends in || true', plantInJob(GATE_CHECK_NAME, verdictRun, `${verdictRun} || true`)],
    ];
    expect(regressions).toHaveLength(7);
    for (const [what, planted] of regressions) {
      expect(planted, `${what}: nothing was planted`).not.toBe(WORKFLOW);
      expect(legShapeViolations(planted), what).not.toEqual([]);
    }
  });

  it('the executable text of ci.yml is pinned line for line', () => {
    const executable = WORKFLOW.split('\n').filter((line) => line.trim() !== '' && !/^\s*#/.test(line));
    expect(executable).toEqual(CI_EXECUTABLE_LINES);
  });

  it('the ci.yml header names the five required contexts, and no line nominates gate alone', () => {
    const lines = WORKFLOW.split('\n');
    const onLine = lines.findIndex((line) => line === 'on:');
    expect(onLine, 'ci.yml has no top-level "on:" line').toBeGreaterThan(0);
    const header = lines.slice(0, onLine).join('\n');
    for (const text of [
      'gate',
      'Node 20',
      'Node 22',
      'Gate file approval',
      'Automated code review',
      'never takes this list as its input',
    ]) {
      expect(header, `the header does not carry "${text}"`).toContain(text);
    }
    for (const retired of [
      /is the context to require/,
      /without the `if:` below/,
      /the trigger filter used/,
      /This is the required context/,
      /Unchanged: same job id/,
      /ran on before/,
    ]) {
      expect(WORKFLOW).not.toMatch(retired);
    }
  });
});
