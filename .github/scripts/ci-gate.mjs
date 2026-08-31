#!/usr/bin/env node
/**
 * The CI gate's decision logic — one committed copy, used twice.
 *
 * `.github/workflows/ci.yml` shells out to this file, and `src/ci-gate.test.ts`
 * runs the same two entry points as child processes with the same environment
 * variables. That is deliberate: the alternative — a classifier written inline
 * in the workflow's `run:` blocks and a test that re-implements it — can only
 * ever prove that the copy in the test agrees with itself. Here the tested
 * artifact IS the executed artifact, so the two cannot drift.
 *
 * Two modes, both driven entirely by the environment (never by `${{ }}`
 * substituted into a shell script, which would put workflow-expression text
 * into the script source before bash ever parses it):
 *
 *   classify  reads CHANGED_FILES_FILE (one path per line) and UNRESOLVED_BASE,
 *             writes `code=true|false` to $GITHUB_OUTPUT.
 *   verdict   reads GATE_CODE plus the three suite-step outcomes and exits
 *             non-zero unless the run is entitled to pass.
 *
 * Every ambiguity resolves toward RUNNING the suite or FAILING the gate. A gate
 * that reports on every change is only worth requiring if it cannot be talked
 * into a green check by a state nobody anticipated, so:
 *   - a base commit that cannot be resolved classifies as code (run the suite);
 *   - a classification that is neither "true" nor "false" fails the gate;
 *   - a code-classified run whose suite steps did not all report `success`
 *     fails the gate, and `skipped` is not `success`.
 * There is no branch in this file that turns an unknown into a pass.
 */

import * as fs from 'node:fs';
import { pathToFileURL } from 'node:url';

/**
 * The paths that make a change a code change.
 *
 * The first three are exactly the globs that used to sit in this workflow's
 * `on: paths:` filter, moved from the trigger (where they decided whether the
 * check reported AT ALL) into the run (where they decide what the check does).
 * Moving them is the whole point of the change: a required context that never
 * reports on a docs-only pull request wedges that pull request forever.
 *
 * The last two are new and are self-protection: a pull request that edits the
 * workflow or this classifier is a change to the gate itself, and the gate must
 * not be able to wave through its own rewrite without running the suite.
 */
export const CODE_PATH_GLOBS = [
  'src/**',
  'package.json',
  'tsconfig.json',
  '.github/workflows/ci.yml',
  '.github/scripts/ci-gate.mjs',
];

/** The suite the gate runs on a code change, in order. */
export const SUITE_STEPS = ['npm ci', 'npm run build', 'npm test'];

const REGEXP_METACHARACTERS = /[.+^${}()|[\]\\]/g;

/**
 * Translate one `on: paths:`-style glob into an anchored regular expression,
 * with GitHub's separator rules: `*` never crosses a `/`, `**` does, and a
 * trailing `/` after `**` is optional so `a/**` also matches `a` itself.
 */
export function globToRegExp(glob) {
  let source = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i += 1;
        if (glob[i + 1] === '/') {
          i += 1;
          source += '(?:.*/)?';
        } else {
          source += '.*';
        }
      } else {
        source += '[^/]*';
      }
    } else if (ch === '?') {
      source += '[^/]';
    } else {
      source += ch.replace(REGEXP_METACHARACTERS, '\\$&');
    }
  }
  return new RegExp(`^${source}$`);
}

const CODE_PATH_MATCHERS = CODE_PATH_GLOBS.map(globToRegExp);

/**
 * Decide whether a changed-file list is a code change.
 *
 * @param {readonly string[]} files changed paths, repository-relative
 * @param {{ unresolvedBase?: boolean }} [options]
 * @returns {{ code: boolean, matched: string[], reason: string }}
 */
export function classifyChangedFiles(files, options = {}) {
  const paths = (files ?? [])
    .map((entry) => String(entry).trim())
    .filter((entry) => entry.length > 0);
  const matched = paths.filter((entry) => CODE_PATH_MATCHERS.some((re) => re.test(entry)));

  // An unresolvable base (first push to a branch, a force-push that orphaned
  // the previous tip, a shallow clone) means the file list below is not a
  // statement about the change — it is the absence of one. Absence of evidence
  // runs the suite; it must never read as "nothing to build".
  if (options.unresolvedBase === true) {
    return { code: true, matched, reason: 'unresolved-base' };
  }
  if (matched.length > 0) {
    return { code: true, matched, reason: 'code-paths-changed' };
  }
  return {
    code: false,
    matched,
    reason: paths.length === 0 ? 'no-files-changed' : 'no-code-paths-changed',
  };
}

/**
 * The gate's conclusion.
 *
 * @param {{ code?: unknown, outcomes?: Record<string, string> }} input
 *   `outcomes` is keyed by the SUITE_STEPS labels and holds the Actions step
 *   outcome — `success`, `failure`, `cancelled` or `skipped`.
 * @returns {{ pass: boolean, reason: string, notRun: string[] }}
 */
export function gateVerdict(input) {
  const { code, outcomes = {} } = input ?? {};

  // Neither true nor false: the classify step did not reach a decision (it
  // crashed, or it was skipped). That is not a non-code change.
  if (code !== true && code !== false) {
    return { pass: false, reason: 'unknown-classification', notRun: [...SUITE_STEPS] };
  }

  // The deterministic pass. A docs-only change gets a green `gate` without the
  // suite having run — that is the point of the job, not a loophole in it.
  if (code === false) {
    return { pass: true, reason: 'non-code-change', notRun: [...SUITE_STEPS] };
  }

  // A code change is entitled to a pass only if all three suite steps reported
  // `success`. `skipped` fails here, which is what closes the silent-skip hole:
  // a future `if:` that accidentally stops the suite from running on a code
  // change turns the gate red instead of green.
  const notRun = SUITE_STEPS.filter((step) => outcomes[step] !== 'success');
  if (notRun.length > 0) {
    return { pass: false, reason: 'suite-did-not-pass', notRun };
  }
  return { pass: true, reason: 'suite-passed', notRun: [] };
}

function appendStepOutput(lines) {
  const target = process.env.GITHUB_OUTPUT;
  if (!target) return;
  fs.appendFileSync(target, lines.map((line) => `${line}\n`).join(''));
}

function runClassify() {
  const listFile = process.env.CHANGED_FILES_FILE;
  if (!listFile) {
    console.error('::error::ci-gate classify: CHANGED_FILES_FILE is not set');
    return 2;
  }
  if (!fs.existsSync(listFile)) {
    console.error(`::error::ci-gate classify: no changed-file list at ${listFile}`);
    return 2;
  }

  // Explicit three-way read, no defaulting: an UNRESOLVED_BASE this file does
  // not recognise means the collecting step changed shape, and guessing which
  // way it meant is exactly the silent-skip risk this gate exists to remove.
  // Exiting non-zero leaves `code` unset, and an unset `code` fails the verdict.
  const unresolved = process.env.UNRESOLVED_BASE ?? '';
  if (unresolved !== 'true' && unresolved !== 'false') {
    console.error(`::error::ci-gate classify: UNRESOLVED_BASE must be "true" or "false", got "${unresolved}"`);
    return 2;
  }

  const files = fs.readFileSync(listFile, 'utf8').split('\n');
  const result = classifyChangedFiles(files, { unresolvedBase: unresolved === 'true' });

  appendStepOutput([`code=${result.code}`, `reason=${result.reason}`]);
  console.log(`code=${result.code}`);
  console.log(`reason=${result.reason}`);
  console.log(`matched=${result.matched.length > 0 ? result.matched.join(' ') : '(none)'}`);
  return 0;
}

function runVerdict() {
  const raw = process.env.GATE_CODE ?? '';
  const code = raw === 'true' ? true : raw === 'false' ? false : undefined;
  const outcomes = {
    'npm ci': process.env.GATE_NPM_CI_OUTCOME ?? '',
    'npm run build': process.env.GATE_BUILD_OUTCOME ?? '',
    'npm test': process.env.GATE_TEST_OUTCOME ?? '',
  };
  const verdict = gateVerdict({ code, outcomes });

  console.log(`classification=${raw === '' ? '(empty)' : raw}`);
  for (const step of SUITE_STEPS) {
    console.log(`outcome[${step}]=${outcomes[step] === '' ? '(none)' : outcomes[step]}`);
  }
  console.log(`verdict=${verdict.pass ? 'pass' : 'fail'}`);
  console.log(`reason=${verdict.reason}`);

  if (!verdict.pass) {
    const detail = verdict.notRun.length > 0 ? ` (did not succeed: ${verdict.notRun.join(', ')})` : '';
    console.error(`::error::gate: ${verdict.reason}${detail}`);
    return 1;
  }
  return 0;
}

export function main(argv) {
  const mode = argv[0];
  if (mode === 'classify') return runClassify();
  if (mode === 'verdict') return runVerdict();
  console.error(`::error::ci-gate: expected "classify" or "verdict", got "${mode ?? ''}"`);
  return 2;
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  process.exitCode = main(process.argv.slice(2));
}
