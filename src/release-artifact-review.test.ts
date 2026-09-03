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
 * exactly that class — one `=fail` in the census, the right one. Then green: a
 * clean fixture passes every check, and the tarball packed from this delivered
 * tree passes every check whose verdict needs no network reading.
 *
 * The credential scanner is the real, exact-pinned hackmyagent from this
 * repository's node_modules/.bin — the same resolution the release `review`
 * job gets from `npm ci --ignore-scripts`. The two scanner-degradation cases
 * (unresolvable scanner, a scanner that misses the planted control) run a
 * copy of the script whose repo root is a scratch directory, so what its
 * node_modules/.bin holds is under the test's control.
 *
 * Deliberately absent here: any read of `CI` or `GITHUB_ACTIONS`. The tag
 * push that publishes is made on a machine where those variables are unset,
 * so a tolerance conditioned on them would exempt the publish path itself. A
 * precondition on the own-tarball run is a test failure in every environment.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'release-artifact-review.mjs');

const CHECKS = [
  'entry-allowlist',
  'no-dotfiles',
  'no-test-material',
  'no-install-scripts',
  'pinned-first-party-deps',
  'npm-audit',
  'global-install-smoke',
  'credential-scan',
  'consumer-closure',
];

/** The checks whose verdict needs no network reading. */
const NO_NETWORK_CHECKS = [
  'entry-allowlist',
  'no-dotfiles',
  'no-test-material',
  'no-install-scripts',
  'pinned-first-party-deps',
  'global-install-smoke',
  'credential-scan',
];

/** What satisfies each check's precondition, for the failure message. */
const PRECONDITION_REMEDY: Record<string, string> = {
  'npm-audit': 'registry access (there is no command; restore network to the npm registry)',
  'global-install-smoke': 'registry access (there is no command; restore network to the npm registry)',
  'credential-scan': 'npm ci --ignore-scripts',
  'consumer-closure': 'registry and GitHub API access (set GH_TOKEN for authenticated advisory reads)',
};

// ---------------------------------------------------------------------------
// Fixtures: tarballs built file-by-file
// ---------------------------------------------------------------------------

// Everything below executes files it just wrote — installed bins, stub
// scanners — so the scratch space must live on an exec-mounted filesystem.
// /tmp is noexec in some sandboxes; node_modules/.cache (gitignored,
// guaranteed present once vitest itself is installed) is not. The script's
// own work dir follows via TMPDIR.
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

// A shipped file carrying a value of the planted control's class: a
// credential-named const assembled at runtime from parts, same shape the
// script plants (sk- + proj- + 48 repeated characters), so no
// credential-shaped literal exists in this repository either.
const POISONED_DIST_FILE = [
  "const OPENAI_API_KEY = 'sk-' + 'proj-' + 'B'.repeat(48);",
  'module.exports = { OPENAI_API_KEY };',
  '',
].join('\n');

function fixturePackageJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify(
    {
      // Not an own-package name: the clean fixture's consumer closure must
      // hold zero own copies, so its consumer-closure check passes vacuously
      // with no advisory feed to read.
      name: 'sls06-review-fixture',
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

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  census: Record<string, string>;
}

function parseCensus(stdout: string): Record<string, string> {
  const censusLine = /^census: (.+)$/m.exec(stdout);
  const census: Record<string, string> = {};
  if (censusLine) {
    for (const pair of censusLine[1].split(' ')) {
      const [check, status] = pair.split('=');
      census[check] = status;
    }
  }
  return census;
}

function runReview(args: string[], options: { script?: string; env?: Record<string, string> } = {}): Run {
  const run = spawnSync(process.execPath, [options.script ?? SCRIPT, ...args], {
    encoding: 'utf-8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 600_000,
    env: { ...process.env, TMPDIR: tmpRoot, ...(options.env ?? {}) },
  });
  return {
    status: run.status,
    stdout: run.stdout ?? '',
    stderr: run.stderr ?? '',
    census: parseCensus(run.stdout ?? ''),
  };
}

/** One review per scenario, shared across assertions. */
const memo = new Map<string, Run>();
function reviewOf(name: string, make: () => Run): Run {
  if (!memo.has(name)) memo.set(name, make());
  return memo.get(name)!;
}

const healthyRun = () => reviewOf('healthy', () => runReview(['--tarball', buildTarball('healthy.tgz', healthyFiles())]));

function expectSingleFailure(run: Run, check: string) {
  expect(run.status).not.toBe(0);
  const failing = CHECKS.filter((name) => run.census[name] === 'fail');
  expect(failing).toEqual([check]);
  expect(run.stdout).toContain(`failing: ${check}`);
}

/**
 * A copy of the script rooted in a scratch directory, so its
 * node_modules/.bin scanner resolution is under the test's control. `env`
 * strips every node_modules/.bin entry off PATH (npm run puts this repo's on
 * PATH, which would hand the copy the real scanner as a fallback) while
 * keeping the system directories tar and npm live in.
 */
function relocatedScript(binStub?: { source: string }): { script: string; env: Record<string, string> } {
  const root = fs.mkdtempSync(path.join(tmpRoot, 'relocated-'));
  fs.mkdirSync(path.join(root, 'scripts'));
  fs.copyFileSync(SCRIPT, path.join(root, 'scripts', 'release-artifact-review.mjs'));
  if (binStub) {
    const binDir = path.join(root, 'node_modules', '.bin');
    fs.mkdirSync(binDir, { recursive: true });
    const stub = path.join(binDir, 'hackmyagent');
    fs.writeFileSync(stub, binStub.source);
    fs.chmodSync(stub, 0o755);
  }
  const systemPath = (process.env.PATH ?? '')
    .split(path.delimiter)
    .filter((dir) => !dir.includes('node_modules'))
    .join(path.delimiter);
  return { script: path.join(root, 'scripts', 'release-artifact-review.mjs'), env: { PATH: systemPath } };
}

/** A stub scanner that honours `secure --format json` but reports nothing. */
const BLIND_SCANNER = [
  '#!/usr/bin/env node',
  "if (process.argv.includes('--version')) { console.log('9.9.9'); process.exit(0); }",
  'console.log(JSON.stringify({ findings: [] }));',
  'process.exit(0);',
  '',
].join('\n');

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

  it('SLS-06.AC2 --advisory-states takes published or all and the states read are printed', { timeout: 300_000 }, () => {
    const bad = runReview(['--tarball', buildTarball('states-bad.tgz', healthyFiles()), '--advisory-states', 'draft']);
    expect(bad.status).toBe(2);
    expect(bad.stderr).toContain('--advisory-states must be published or all');

    const healthy = healthyRun();
    expect(healthy.stdout).toContain('advisory states: all');

    const published = reviewOf('states-published', () =>
      runReview(['--tarball', buildTarball('states-published.tgz', healthyFiles()), '--advisory-states', 'published']),
    );
    expect(published.stdout).toContain('advisory states: published');
  });

  it('SLS-06.AC2 every check appears in the census whether it passed, failed or hit a precondition', { timeout: 300_000 }, () => {
    const healthy = healthyRun();
    for (const check of CHECKS) {
      expect(Object.keys(healthy.census), `census is missing ${check}`).toContain(check);
      expect(['pass', 'fail', 'precondition']).toContain(healthy.census[check]);
    }

    // On a failing run too: the census is not a success-path artifact.
    const poisoned = reviewOf('poison-dotfile', () =>
      runReview(['--tarball', buildTarball('poison-dotfile.tgz', { ...healthyFiles(), 'package/dist/.env': 'X=1\n' })]),
    );
    for (const check of CHECKS) {
      expect(Object.keys(poisoned.census), `census is missing ${check}`).toContain(check);
    }
  });

  it('SLS-06.AC2 an entry outside dist/, README, LICENSE and package.json fails the entry allowlist', { timeout: 300_000 }, () => {
    const run = reviewOf('stray-entry', () =>
      runReview(['--tarball', buildTarball('stray.tgz', { ...healthyFiles(), 'package/extra.js': 'module.exports = 1;\n' })]),
    );
    expectSingleFailure(run, 'entry-allowlist');
    expect(run.stdout).toContain('package/extra.js');
  });

  it('SLS-06.AC2 both bins are exercised: version, help, init help and the mcp wrapper', { timeout: 300_000 }, () => {
    const healthy = healthyRun();
    expect(healthy.stdout).toContain('secretless-ai --version');
    expect(healthy.stdout).toContain('secretless-ai --help');
    expect(healthy.stdout).toContain('secretless-ai init --help');
    expect(healthy.stdout).toContain('secretless-mcp --help');
  });

  it('SLS-06.AC2 the exact-pinned hackmyagent resolves from node_modules/.bin under npm ci --ignore-scripts', () => {
    // The pin is what makes the release review job's scanner resolution
    // deterministic: `npm ci --ignore-scripts` reifies node_modules/.bin.
    const manifest = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8'));
    const pin = manifest.devDependencies?.hackmyagent;
    expect(pin, 'hackmyagent is not a devDependency').toBeDefined();
    expect(pin).toMatch(/^\d+\.\d+\.\d+$/);
    expect(fs.existsSync(path.join(REPO_ROOT, 'node_modules', '.bin', 'hackmyagent'))).toBe(true);
  });

  it('SLS-06.AC2 the scanner row prints the scanner version and PATH is the fallback, never the first choice', { timeout: 300_000 }, () => {
    const healthy = healthyRun();
    expect(healthy.stdout).toMatch(/check credential-scan: pass: hackmyagent@\d+\.\d+\.\d+/);

    // A blind scanner planted FIRST on PATH must lose to node_modules/.bin:
    // if PATH won, the control would go unflagged and this run would report a
    // precondition instead of a pass.
    const blindDir = fs.mkdtempSync(path.join(tmpRoot, 'path-blind-'));
    fs.writeFileSync(path.join(blindDir, 'hackmyagent'), BLIND_SCANNER);
    fs.chmodSync(path.join(blindDir, 'hackmyagent'), 0o755);
    const run = reviewOf('path-is-fallback', () =>
      runReview(['--tarball', buildTarball('path-fallback.tgz', healthyFiles())], {
        env: { PATH: `${blindDir}${path.delimiter}${process.env.PATH ?? ''}` },
      }),
    );
    expect(run.census['credential-scan']).toBe('pass');
  });

  it('SLS-06.AC2 an unresolvable hackmyagent is a precondition and a non-zero exit, never a pass', { timeout: 300_000 }, () => {
    const { script, env } = relocatedScript();
    const run = reviewOf('no-scanner', () =>
      runReview(['--tarball', buildTarball('no-scanner.tgz', healthyFiles())], { script, env }),
    );
    expect(run.status).not.toBe(0);
    expect(run.census['credential-scan']).toBe('precondition');
    expect(run.stdout).toMatch(/check credential-scan: precondition: hackmyagent not resolvable/);
    expect(run.stdout).toContain('preconditions not met: credential-scan');
  });

  it('SLS-06.AC2 a scanner that misses the planted control is a precondition naming the scanner version', { timeout: 300_000 }, () => {
    const { script, env } = relocatedScript({ source: BLIND_SCANNER });
    const run = reviewOf('blind-scanner', () =>
      runReview(['--tarball', buildTarball('blind-scanner.tgz', healthyFiles())], { script, env }),
    );
    expect(run.status).not.toBe(0);
    expect(run.census['credential-scan']).toBe('precondition');
    expect(run.stdout).toContain('control not flagged by hackmyagent@9.9.9');
  });
});

// ---------------------------------------------------------------------------
// SLS-06.AC3 — red first, per blocking class; then green
// ---------------------------------------------------------------------------

describe('each blocking class is caught by name, and the delivered tree passes', () => {
  it('SLS-06.AC3 a dotfile entry is caught by no-dotfiles', { timeout: 300_000 }, () => {
    const run = reviewOf('poison-dotfile', () =>
      runReview(['--tarball', buildTarball('poison-dotfile.tgz', { ...healthyFiles(), 'package/dist/.env': 'X=1\n' })]),
    );
    expectSingleFailure(run, 'no-dotfiles');
    expect(run.stdout).toContain('package/dist/.env');
  });

  it('SLS-06.AC3 a fixtures/ entry is caught by no-test-material', { timeout: 300_000 }, () => {
    const run = reviewOf('poison-fixtures', () =>
      runReview(
        ['--tarball', buildTarball('poison-fixtures.tgz', { ...healthyFiles(), 'package/dist/fixtures/sample.js': '1;\n' })],
      ),
    );
    expectSingleFailure(run, 'no-test-material');
    expect(run.stdout).toContain('package/dist/fixtures/sample.js');
  });

  it('SLS-06.AC3 a postinstall script is caught by no-install-scripts', { timeout: 300_000 }, () => {
    const files = {
      ...healthyFiles(),
      'package/package.json': fixturePackageJson({ scripts: { postinstall: 'node -e "1"' } }),
    };
    const run = reviewOf('poison-postinstall', () => runReview(['--tarball', buildTarball('poison-postinstall.tgz', files)]));
    expectSingleFailure(run, 'no-install-scripts');
    expect(run.stdout).toContain('postinstall');
  });

  it('SLS-06.AC3 a caret range on an @opena2a/ dependency is caught by pinned-first-party-deps', { timeout: 300_000 }, () => {
    const files = {
      ...healthyFiles(),
      'package/package.json': fixturePackageJson({ dependencies: { '@opena2a/cli-ui': '^0.4.0' } }),
    };
    const run = reviewOf('poison-caret', () => runReview(['--tarball', buildTarball('poison-caret.tgz', files)]));
    expectSingleFailure(run, 'pinned-first-party-deps');
    expect(run.stdout).toContain('@opena2a/cli-ui=^0.4.0');
  });

  it('SLS-06.AC3 a dist/cli.js that exits 1 on --version is caught by global-install-smoke', { timeout: 300_000 }, () => {
    const files = { ...healthyFiles(), 'package/dist/cli.js': BROKEN_CLI };
    const run = reviewOf('poison-cli', () => runReview(['--tarball', buildTarball('poison-cli.tgz', files)]));
    expectSingleFailure(run, 'global-install-smoke');
    expect(run.stdout).toContain('secretless-ai --version: exited 1');
  });

  it('SLS-06.AC3 a dist/ file carrying a value of the control class is caught by credential-scan, without echoing the value', { timeout: 300_000 }, () => {
    const files = { ...healthyFiles(), 'package/dist/config.js': POISONED_DIST_FILE };
    const run = reviewOf('poison-credential', () => runReview(['--tarball', buildTarball('poison-credential.tgz', files)]));
    expectSingleFailure(run, 'credential-scan');
    // The failure names checkId and file:line, never the matched text.
    expect(run.stdout).toMatch(/check credential-scan: fail: .*config\.js:\d+/);
    expect(run.stdout).not.toContain('sk-' + 'proj-' + 'B'.repeat(48));
  });

  it('SLS-06.AC3 a dependency on a deprecated hackmyagent version is caught by consumer-closure', { timeout: 600_000 }, () => {
    // Discovered at test time, and named: the registry's own answer to which
    // hackmyagent versions are deprecated.
    const view = spawnSync('npm', ['view', 'hackmyagent@*', 'version', 'deprecated', '--json'], {
      encoding: 'utf-8',
      timeout: 120_000,
    });
    expect(view.status, view.stderr).toBe(0);
    // npm's --json shape varies with the match count: an array of row objects
    // for many versions, one bare object for exactly one.
    const parsed = JSON.parse(view.stdout || 'null') as unknown;
    const rows: Array<{ version?: unknown; deprecated?: unknown }> = Array.isArray(parsed)
      ? parsed
      : parsed !== null && typeof parsed === 'object'
        ? 'version' in (parsed as object)
          ? [parsed as object]
          : Object.entries(parsed as Record<string, unknown>).map(([version, value]) =>
              value !== null && typeof value === 'object' ? { version, ...value } : { version, deprecated: value },
            )
        : [];
    const deprecatedVersions = rows
      .filter((row) => typeof row.deprecated === 'string' && row.deprecated.length > 0)
      .map((row) => String(row.version));
    expect(deprecatedVersions.length, 'no deprecated hackmyagent version on the registry to test with').toBeGreaterThan(0);
    const version = deprecatedVersions[0];
    console.log(`SLS-06.AC3 deprecated hackmyagent version used by this test: ${version}`);

    const files = {
      ...healthyFiles(),
      'package/package.json': fixturePackageJson({ dependencies: { hackmyagent: version } }),
    };
    const run = reviewOf('poison-deprecated', () => runReview(['--tarball', buildTarball('poison-deprecated.tgz', files)]));
    expect(run.census['consumer-closure']).toBe('fail');
    expect(run.status).not.toBe(0);
    expect(run.stdout).toContain(`hackmyagent@${version} is deprecated`);
    expect(run.stdout).toMatch(/failing: .*consumer-closure/);
  });

  it('SLS-06.AC3 a statically bad tarball is not installed: its dynamic checks are preconditions, not passes', { timeout: 300_000 }, () => {
    const poisoned = reviewOf('poison-dotfile', () =>
      runReview(['--tarball', buildTarball('poison-dotfile.tgz', { ...healthyFiles(), 'package/dist/.env': 'X=1\n' })]),
    );
    expect(poisoned.census['global-install-smoke']).toBe('precondition');
    expect(poisoned.census['credential-scan']).toBe('precondition');
    expect(poisoned.census['npm-audit']).toBe('precondition');
    expect(poisoned.census['consumer-closure']).toBe('precondition');
  });

  it('SLS-06.AC3 a clean fixture tarball exits 0 with every check pass', { timeout: 300_000 }, () => {
    const healthy = healthyRun();
    expect(healthy.stdout).toContain('result: pass');
    expect(healthy.status).toBe(0);
    for (const check of CHECKS) {
      expect(healthy.census[check], `${check} is ${healthy.census[check]}`).toBe('pass');
    }
  });

  it('SLS-06.AC3 the tarball packed from the delivered tree passes every no-network check, with no precondition anywhere', { timeout: 600_000 }, () => {
    const packDir = fs.mkdtempSync(path.join(tmpRoot, 'pack-'));
    const pack = spawnSync('npm', ['pack', '--ignore-scripts', '--pack-destination', packDir], {
      cwd: REPO_ROOT,
      encoding: 'utf-8',
      timeout: 300_000,
    });
    expect(pack.status, pack.stderr).toBe(0);
    const tarball = path.join(packDir, pack.stdout.trim().split('\n').at(-1)!);

    const run = runReview(['--tarball', tarball]);

    // A check that could not run here is a test failure: the publish path
    // itself runs outside CI, so an unrunnable check must surface loudly.
    for (const check of CHECKS) {
      if (run.census[check] === 'precondition') {
        const detail = new RegExp(`^check ${check}: precondition: (.*)$`, 'm').exec(run.stdout)?.[1] ?? '<no detail>';
        expect.fail(
          `check ${check} hit a precondition on the delivered tarball: ${detail}. ` +
            `Satisfy it with: ${PRECONDITION_REMEDY[check] ?? 'see the check output above'}`,
        );
      }
    }

    for (const check of NO_NETWORK_CHECKS) {
      expect(run.census[check], `${check} is ${run.census[check]}`).toBe('pass');
    }

    // consumer-closure may pass or fail — a fail names a nested own copy the
    // roadmap has to deal with, blocks the release job, and is quoted in the
    // delivery report; it is not a defect of this script.
    expect(['pass', 'fail'], `consumer-closure is ${run.census['consumer-closure']}`).toContain(run.census['consumer-closure']);
    expect(['pass', 'fail'], `npm-audit is ${run.census['npm-audit']}`).toContain(run.census['npm-audit']);
    if (run.census['consumer-closure'] === 'fail' || run.census['npm-audit'] === 'fail') {
      console.log('SLS-06.AC3 delivered-tarball verbatim (for the delivery report):');
      for (const line of run.stdout.split('\n')) {
        if (/^(check (npm-audit|consumer-closure)|census|result)/.test(line)) console.log(`  ${line}`);
      }
    }

    // Exit code 0 exactly when no check is fail or precondition.
    const anyBlocked = CHECKS.some((check) => run.census[check] !== 'pass');
    expect(run.status === 0).toBe(!anyBlocked);
  });

  it('SLS-06.AC3 a tarball with no dist/ exits non-zero with precondition in its output', { timeout: 300_000 }, () => {
    const files = {
      'package/package.json': fixturePackageJson(),
      'package/README.md': '# fixture\n',
    };
    const run = reviewOf('no-dist', () => runReview(['--tarball', buildTarball('no-dist.tgz', files)]));
    expect(run.status).not.toBe(0);
    expect(run.stdout).toContain('precondition');
    expect(run.census['global-install-smoke']).toBe('precondition');
    expect(run.census['credential-scan']).toBe('precondition');
    expect(run.stdout).toContain('dist/ absent from the tarball');
  });
});
