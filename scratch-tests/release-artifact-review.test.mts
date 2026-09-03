import { afterAll, describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * scripts/release-artifact-review.mjs, exercised as the release `review` job
 * runs it: spawned on a tarball, judged by its exit code and its census.
 *
 * Red first, per check: each blocking class gets a poisoned tarball built in a
 * temp directory, and the assertion is that the script exits non-zero naming
 * exactly that class — one `=fail` in the census, the right one. Then green:
 * the tarball packed from this delivered tree must pass every check that can
 * run, with anything that cannot run visible as a precondition, never as pass.
 *
 * The credential scanner is a stub `hackmyagent` placed on PATH by these
 * tests. It detects one token shape — ghp_ + 36 — which the real dist/ cannot
 * contain (full GitHub-token literals exist only in *.test.ts, which tsconfig
 * excludes from the build), while the control the script plants always does.
 * What is under test is the script's handling of the scan: control found,
 * zero findings elsewhere, precondition when no scanner resolves.
 */

const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'release-artifact-review.mjs');

const CHECKS = [
  'entry-allowlist',
  'dot-entries',
  'test-path-entries',
  'install-scripts',
  'opena2a-pinned',
  'npm-audit',
  'bin-smoke',
  'credential-scan',
  'own-package-census',
];

// ---------------------------------------------------------------------------
// Fixtures: tarballs built file-by-file, and a stub scanner on PATH
// ---------------------------------------------------------------------------

// Everything below executes files it just wrote — stub scanners, installed
// bins — so the scratch space must live on an exec-mounted filesystem. /tmp
// is noexec in some sandboxes; node_modules/.cache (gitignored, guaranteed
// present once vitest itself is installed) is not. The script's own work dir
// follows via TMPDIR.
const scratchBase = path.join(REPO_ROOT, 'node_modules', '.cache', 'release-review-tests');
fs.mkdirSync(scratchBase, { recursive: true });
const tmpRoot = fs.mkdtempSync(path.join(scratchBase, 'run-'));
afterAll(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));

const FIXTURE_CLI = [
  '#!/usr/bin/env node',
  "if (process.argv[2] === '--version') { console.log('0.0.0-fixture'); process.exit(0); }",
  "console.log('usage: fixture'); process.exit(0);",
  '',
].join('\n');

const BROKEN_CLI = [
  '#!/usr/bin/env node',
  "if (process.argv[2] === '--version') { process.exit(1); }",
  "console.log('usage: fixture'); process.exit(0);",
  '',
].join('\n');

function fixturePackageJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify(
    {
      name: 'secretless-ai',
      version: '0.0.0-fixture',
      license: 'Apache-2.0',
      bin: { 'secretless-ai': 'dist/cli.js', 'secretless-mcp': 'dist/mcp-wrapper.js' },
      files: ['dist'],
      ...overrides,
    },
    null,
    2,
  );
}

function healthyFiles(): Record<string, string> {
  return {
    'package/package.json': fixturePackageJson(),
    'package/README.md': '# fixture\n',
    'package/LICENSE': 'Apache-2.0\n',
    'package/dist/cli.js': FIXTURE_CLI,
    'package/dist/mcp-wrapper.js': FIXTURE_CLI,
  };
}

/** A gzipped tarball with exactly these file entries, no directory entries. */
function buildTarball(name: string, files: Record<string, string>): string {
  const stage = fs.mkdtempSync(path.join(tmpRoot, 'stage-'));
  for (const [entry, content] of Object.entries(files)) {
    const target = path.join(stage, entry);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
    fs.chmodSync(target, 0o755);
  }
  const tarball = path.join(tmpRoot, name);
  const tar = spawnSync('tar', ['-czf', tarball, '-C', stage, ...Object.keys(files)], { encoding: 'utf-8' });
  expect(tar.status, tar.stderr).toBe(0);
  return tarball;
}

/**
 * A stub `hackmyagent` honouring `hackmyagent scan <dir> --json`: findings are
 * every ghp_-shaped token under <dir>. 'blind' reports nothing, ever — the
 * scanner shape the planted control exists to catch.
 */
function makeStubScanner(kind: 'find' | 'blind'): string {
  const dir = fs.mkdtempSync(path.join(tmpRoot, `stub-${kind}-`));
  const source = [
    '#!/usr/bin/env node',
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const target = process.argv[3];',
    'const findings = [];',
    'function walk(p) {',
    '  for (const entry of fs.readdirSync(p, { withFileTypes: true })) {',
    '    const full = path.join(p, entry.name);',
    '    if (entry.isDirectory()) walk(full);',
    "    else if (/ghp_[A-Za-z0-9]{36}/.test(fs.readFileSync(full, 'utf-8'))) findings.push({ file: full, rule: 'github-token' });",
    '  }',
    '}',
    `if (${JSON.stringify(kind === 'find')}) walk(target);`,
    'console.log(JSON.stringify({ findings }));',
    'process.exit(findings.length > 0 ? 1 : 0);',
    '',
  ].join('\n');
  const stub = path.join(dir, 'hackmyagent');
  fs.writeFileSync(stub, source);
  fs.chmodSync(stub, 0o755);
  return dir;
}

const stubDir = makeStubScanner('find');
const blindStubDir = makeStubScanner('blind');

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  census: Record<string, string>;
}

function runReview(args: string[], options: { scannerDir?: string } = {}): Run {
  const pathPrefix = options.scannerDir ? `${options.scannerDir}:` : '';
  const run = spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: 'utf-8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 600_000,
    env: { ...process.env, PATH: `${pathPrefix}${process.env.PATH ?? ''}`, TMPDIR: tmpRoot },
  });
  const censusLine = /^census: (.+)$/m.exec(run.stdout ?? '');
  const census: Record<string, string> = {};
  if (censusLine) {
    for (const pair of censusLine[1].split(' ')) {
      const [check, status] = pair.split('=');
      census[check] = status;
    }
  }
  return { status: run.status, stdout: run.stdout ?? '', stderr: run.stderr ?? '', census };
}

/** One review per scenario, shared across assertions. */
const memo = new Map<string, Run>();
function reviewOf(name: string, make: () => Run): Run {
  if (!memo.has(name)) memo.set(name, make());
  return memo.get(name)!;
}

const healthyRun = () =>
  reviewOf('healthy', () => runReview(['--tarball', buildTarball('healthy.tgz', healthyFiles())], { scannerDir: stubDir }));

function expectSingleFailure(run: Run, check: string) {
  expect(run.status).not.toBe(0);
  const failing = CHECKS.filter((name) => run.census[name] === 'fail');
  expect(failing).toEqual([check]);
  expect(run.stdout).toContain(`failing: ${check}`);
}

// ---------------------------------------------------------------------------
// SLS-06.AC2 — what the script refuses, and how it reports
// ---------------------------------------------------------------------------

describe('release-artifact-review.mjs reviews the packed bytes and reports every check', () => {
  it('SLS-06.AC2 the script refuses to run without a --tarball path', () => {
    const bare = runReview([]);
    expect(bare.status).toBe(2);
    expect(bare.stderr).toContain('usage:');

    const missing = runReview(['--tarball', path.join(tmpRoot, 'does-not-exist.tgz')]);
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain('no such tarball');
  });

  it('SLS-06.AC2 every check appears in the census whether it passed, failed or hit a precondition', { timeout: 120_000 }, () => {
    const healthy = healthyRun();
    for (const check of CHECKS) {
      expect(Object.keys(healthy.census), `census is missing ${check}`).toContain(check);
      expect(['pass', 'fail', 'precondition']).toContain(healthy.census[check]);
    }

    // On a failing run too: the census is not a success-path artifact.
    const poisoned = reviewOf('census-poisoned', () =>
      runReview(['--tarball', buildTarball('census-poisoned.tgz', { ...healthyFiles(), 'package/dist/.env': 'X=1\n' })], {
        scannerDir: stubDir,
      }),
    );
    for (const check of CHECKS) {
      expect(Object.keys(poisoned.census), `census is missing ${check}`).toContain(check);
    }
  });

  it('SLS-06.AC2 an entry outside dist/, README, LICENSE and package.json fails the entry allowlist', () => {
    const run = reviewOf('stray-entry', () =>
      runReview(['--tarball', buildTarball('stray.tgz', { ...healthyFiles(), 'package/extra.js': 'module.exports = 1;\n' })], {
        scannerDir: stubDir,
      }),
    );
    expectSingleFailure(run, 'entry-allowlist');
    expect(run.stdout).toContain('package/extra.js');
  });

  it('SLS-06.AC2 both bins are exercised: version, help, init help and the mcp wrapper', { timeout: 120_000 }, () => {
    const healthy = healthyRun();
    expect(healthy.stdout).toContain('secretless-ai --version');
    expect(healthy.stdout).toContain('secretless-ai --help');
    expect(healthy.stdout).toContain('secretless-ai init --help');
    expect(healthy.stdout).toContain('secretless-mcp --help');
  });

  it('SLS-06.AC2 an unresolvable hackmyagent is a precondition and a non-zero exit, never a pass', { timeout: 120_000 }, () => {
    const run = reviewOf('no-scanner', () => runReview(['--tarball', buildTarball('no-scanner.tgz', healthyFiles())]));
    expect(run.status).not.toBe(0);
    expect(run.census['credential-scan']).toBe('precondition');
    expect(run.stdout).toMatch(/check credential-scan: precondition: hackmyagent/);
    expect(run.stdout).toContain('preconditions not met: credential-scan');
  });

  it('SLS-06.AC2 a scanner that misses the planted control fails the scan instead of reporting clean', { timeout: 120_000 }, () => {
    const run = reviewOf('blind-scanner', () =>
      runReview(['--tarball', buildTarball('blind-scanner.tgz', healthyFiles())], { scannerDir: blindStubDir }),
    );
    expectSingleFailure(run, 'credential-scan');
    expect(run.stdout).toContain('planted control was not found');
  });

  it('SLS-06.AC2 the own-package census is placeholdered as an absent-script precondition', { timeout: 120_000 }, () => {
    // Measured at intake 2026-09-02: own-package-census.mjs exists in none of
    // the four CLI repos. Until it does, its line is a visible precondition.
    expect(fs.existsSync(path.join(REPO_ROOT, 'scripts', 'own-package-census.mjs'))).toBe(false);
    const healthy = healthyRun();
    expect(healthy.census['own-package-census']).toBe('precondition');
    expect(healthy.stdout).toContain('own-package census script absent');
  });
});

// ---------------------------------------------------------------------------
// SLS-06.AC3 — red first, per blocking class; then green on the real tarball
// ---------------------------------------------------------------------------

describe('each blocking class is caught by name, and the delivered tree passes', () => {
  it('SLS-06.AC3 a dotfile entry is caught by dot-entries', () => {
    const run = reviewOf('poison-dotfile', () =>
      runReview(['--tarball', buildTarball('poison-dotfile.tgz', { ...healthyFiles(), 'package/dist/.env': 'SECRET=1\n' })], {
        scannerDir: stubDir,
      }),
    );
    expectSingleFailure(run, 'dot-entries');
    expect(run.stdout).toContain('package/dist/.env');
  });

  it('SLS-06.AC3 a fixtures/ entry is caught by test-path-entries', () => {
    const run = reviewOf('poison-fixtures', () =>
      runReview(
        ['--tarball', buildTarball('poison-fixtures.tgz', { ...healthyFiles(), 'package/dist/fixtures/sample.js': '1;\n' })],
        { scannerDir: stubDir },
      ),
    );
    expectSingleFailure(run, 'test-path-entries');
    expect(run.stdout).toContain('package/dist/fixtures/sample.js');
  });

  it('SLS-06.AC3 a postinstall script is caught by install-scripts', () => {
    const files = {
      ...healthyFiles(),
      'package/package.json': fixturePackageJson({ scripts: { postinstall: 'node -e "1"' } }),
    };
    const run = reviewOf('poison-postinstall', () =>
      runReview(['--tarball', buildTarball('poison-postinstall.tgz', files)], { scannerDir: stubDir }),
    );
    expectSingleFailure(run, 'install-scripts');
    expect(run.stdout).toContain('postinstall');
  });

  it('SLS-06.AC3 a caret range on an @opena2a/ dependency is caught by opena2a-pinned', () => {
    const files = {
      ...healthyFiles(),
      'package/package.json': fixturePackageJson({ dependencies: { '@opena2a/cli-ui': '^0.4.0' } }),
    };
    const run = reviewOf('poison-caret', () =>
      runReview(['--tarball', buildTarball('poison-caret.tgz', files)], { scannerDir: stubDir }),
    );
    expectSingleFailure(run, 'opena2a-pinned');
    expect(run.stdout).toContain('@opena2a/cli-ui=^0.4.0');
  });

  it('SLS-06.AC3 a dist/cli.js that exits 1 on --version is caught by bin-smoke', { timeout: 120_000 }, () => {
    const files = { ...healthyFiles(), 'package/dist/cli.js': BROKEN_CLI };
    const run = reviewOf('poison-cli', () =>
      runReview(['--tarball', buildTarball('poison-cli.tgz', files)], { scannerDir: stubDir }),
    );
    expectSingleFailure(run, 'bin-smoke');
    expect(run.stdout).toContain('secretless-ai --version: exited 1');
  });

  it('SLS-06.AC3 a statically bad tarball is not installed: its dynamic checks are preconditions, not passes', () => {
    const poisoned = reviewOf('poison-dotfile', () =>
      runReview(['--tarball', buildTarball('poison-dotfile.tgz', { ...healthyFiles(), 'package/dist/.env': 'SECRET=1\n' })], {
        scannerDir: stubDir,
      }),
    );
    expect(poisoned.census['bin-smoke']).toBe('precondition');
    expect(poisoned.census['credential-scan']).toBe('precondition');
    expect(poisoned.census['npm-audit']).toBe('precondition');
  });

  it('SLS-06.AC3 the tarball packed from the delivered tree passes every runnable check and exits 0', { timeout: 600_000 }, () => {
    const packDir = fs.mkdtempSync(path.join(tmpRoot, 'pack-'));
    const pack = spawnSync('npm', ['pack', '--pack-destination', packDir], {
      cwd: REPO_ROOT,
      encoding: 'utf-8',
      timeout: 300_000,
    });
    expect(pack.status, pack.stderr).toBe(0);
    const tarball = path.join(packDir, pack.stdout.trim().split('\n').at(-1)!);

    const run = runReview(['--tarball', tarball], { scannerDir: stubDir });
    expect(run.stdout).toContain('result: pass');
    expect(run.status).toBe(0);
    for (const check of CHECKS) {
      expect(['pass', 'precondition'], `${check} is ${run.census[check]}`).toContain(run.census[check]);
      expect(run.census[check]).not.toBe('fail');
    }
    // Passing with something unrun is only tolerated for the placeholdered
    // census check; everything else actually ran.
    const preconditions = CHECKS.filter((check) => run.census[check] === 'precondition');
    expect(preconditions).toEqual(['own-package-census']);
  });

  it('SLS-06.AC3 a tarball with no dist/ exits non-zero with precondition in its output', () => {
    const files = {
      'package/package.json': fixturePackageJson(),
      'package/README.md': '# fixture\n',
    };
    const run = reviewOf('no-dist', () =>
      runReview(['--tarball', buildTarball('no-dist.tgz', files)], { scannerDir: stubDir }),
    );
    expect(run.status).not.toBe(0);
    expect(run.stdout).toContain('precondition');
    expect(run.census['bin-smoke']).toBe('precondition');
    expect(run.census['credential-scan']).toBe('precondition');
    expect(run.stdout).toContain('dist/ absent from the tarball');
  });
});
