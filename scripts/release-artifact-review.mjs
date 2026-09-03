#!/usr/bin/env node

/**
 * release-artifact-review.mjs — the release gate's review of the packed tarball.
 *
 * Usage: node scripts/release-artifact-review.mjs --tarball <path>
 *
 * The bytes under review are the tarball `npm pack` produced in the release
 * `build` job — the same bytes the `publish` job later hands to `npm publish`.
 * Reviewing the repository tree instead would review something npm never
 * ships: `files` filtering, npm's own additions (README, LICENSE,
 * package.json) and anything a compromised build step smuggled into dist/ are
 * only visible in the packed artifact.
 *
 * Every check is named, and every run prints one `census:` line naming every
 * check with its status — pass, fail or precondition — so a check that could
 * not run is never silent. A check whose precondition does not hold reports
 * `precondition: <what is missing>` and (with one placeholdered exception,
 * own-package-census, see below) exits non-zero: an unrunnable review is a
 * blocked release, not a passed one.
 *
 * Checks, in order:
 *   entry-allowlist    every file entry is package/dist/**, package/README.md,
 *                      package/LICENSE or package/package.json — the closure of
 *                      package.json's `files: ["dist"]` plus what npm always adds
 *   dot-entries        no dotfile or dot-directory entry (.npmrc, .env, .git, …)
 *   test-path-entries  no entry path containing __tests__, fixtures or test/
 *   install-scripts    no preinstall, install or postinstall in the packed
 *                      package.json — nothing runs on the consumer's machine
 *   opena2a-pinned     no caret or tilde range on any @opena2a/* dependency:
 *                      first-party deps are pinned exactly
 *   npm-audit          `npm audit --omit=dev --audit-level=high` over a lockfile
 *                      resolved from the packed package.json (registry required)
 *   bin-smoke          `npm install -g <tarball> --ignore-scripts` into a clean
 *                      temp prefix, then with an empty HOME and a scrubbed env:
 *                      secretless-ai --version / --help / init --help and
 *                      secretless-mcp --help must exit 0 without a stack trace
 *   credential-scan    hackmyagent (node_modules/.bin or PATH) over a scratch
 *                      copy of the tarball's dist/ into which this script plants
 *                      one credential file: the planted control must be found,
 *                      and nothing else may be
 *   own-package-census own-package-census.mjs MODE=gate when it exists.
 *                      PLACEHOLDER (intake 2026-09-02): the script exists in
 *                      none of the four CLI repos yet, so its absence is
 *                      reported as a precondition without failing the run —
 *                      the one precondition that does not block, because it is
 *                      known-absent by the ruling that ordered this gate.
 */

import { spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY = 'https://registry.npmjs.org/';
const PLANTED_NAME = 'planted-credential-control.txt';

/** Ordered check names; the census line reports every one of these, always. */
const CHECK_NAMES = [
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

function usage(message) {
  process.stderr.write(`${message}\nusage: node scripts/release-artifact-review.mjs --tarball <path>\n`);
  process.exit(2);
}

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    encoding: 'utf-8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: options.timeout ?? 120_000,
    ...options,
  });
}

/** Records check outcomes and prints each one as it lands. */
class Results {
  constructor() {
    this.byName = new Map(); // name -> { status, detail, blocking }
  }
  record(name, status, detail, { blocking = true } = {}) {
    this.byName.set(name, { status, detail, blocking });
    console.log(`check ${name}: ${status}${detail ? `: ${detail}` : ''}`);
  }
  pass(name, detail) {
    this.record(name, 'pass', detail);
  }
  fail(name, detail) {
    this.record(name, 'fail', detail);
  }
  precondition(name, missing, options) {
    this.record(name, 'precondition', missing, options);
  }
  statusOf(name) {
    return this.byName.get(name)?.status ?? 'fail';
  }
  isBlocking(name) {
    return this.byName.get(name)?.blocking ?? true;
  }
}

function main() {
  const argv = process.argv.slice(2);
  const flagIndex = argv.indexOf('--tarball');
  if (flagIndex === -1 || flagIndex + 1 >= argv.length) usage('missing required --tarball <path>');
  const tarball = path.resolve(argv[flagIndex + 1]);
  if (!fs.existsSync(tarball)) usage(`no such tarball: ${tarball}`);

  console.log(`release-artifact-review: reviewing ${tarball}`);

  const results = new Results();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'release-artifact-review-'));
  try {
    review(tarball, work, results);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }

  // The census: every check, every run, no matter what happened above.
  console.log(`census: ${CHECK_NAMES.map((name) => `${name}=${results.statusOf(name)}`).join(' ')}`);

  const failing = CHECK_NAMES.filter((name) => results.statusOf(name) === 'fail');
  const preconditions = CHECK_NAMES.filter((name) => results.statusOf(name) === 'precondition');
  const blocking = preconditions.filter((name) => results.isBlocking(name));
  const placeholdered = preconditions.filter((name) => !results.isBlocking(name));

  if (failing.length > 0 || blocking.length > 0) {
    const parts = [];
    if (failing.length > 0) parts.push(`failing: ${failing.join(', ')}`);
    if (blocking.length > 0) parts.push(`preconditions not met: ${blocking.join(', ')}`);
    console.log(`result: fail — ${parts.join('; ')}`);
    process.exit(1);
  }
  const note = placeholdered.length > 0 ? ` (preconditions noted, not blocking: ${placeholdered.join(', ')})` : '';
  console.log(`result: pass${note}`);
  process.exit(0);
}

function review(tarball, work, results) {
  // -------------------------------------------------------------------------
  // Read the artifact: entry listing plus a full extraction.
  // -------------------------------------------------------------------------
  const listing = run('tar', ['-tzf', tarball]);
  if (listing.status !== 0) {
    // Not a readable tarball: no check below can run against these bytes.
    for (const name of CHECK_NAMES) results.precondition(name, `tarball unreadable: ${(listing.stderr || '').trim()}`);
    return;
  }
  const entries = listing.stdout.split('\n').filter((line) => line.length > 0);

  const extractDir = path.join(work, 'extract');
  fs.mkdirSync(extractDir);
  const extract = run('tar', ['-xzf', tarball, '-C', extractDir]);
  if (extract.status !== 0) {
    for (const name of CHECK_NAMES) results.precondition(name, `tarball unextractable: ${(extract.stderr || '').trim()}`);
    return;
  }
  const packageDir = path.join(extractDir, 'package');
  let pkg = null;
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf-8'));
  } catch {
    pkg = null;
  }

  // -------------------------------------------------------------------------
  // Static checks over the entry list and the packed package.json.
  // -------------------------------------------------------------------------

  // entry-allowlist. Directory entries (trailing slash — npm pack emits none,
  // but hand-rolled tarballs can) are exempt here and judged by the two path
  // checks below instead.
  const fileEntries = entries.filter((entry) => !entry.endsWith('/'));
  const disallowed = fileEntries.filter(
    (entry) => !/^package\/(dist\/.+|README\.md|LICENSE|package\.json)$/.test(entry),
  );
  if (disallowed.length > 0) {
    results.fail('entry-allowlist', `entries outside the allowlist: ${disallowed.join(', ')}`);
  } else {
    results.pass(
      'entry-allowlist',
      `${fileEntries.length} file entries, all within package/dist/, package/README.md, package/LICENSE, package/package.json`,
    );
  }

  // dot-entries: any path segment starting with a dot, file or directory.
  const dotted = entries.filter((entry) => entry.split('/').some((segment) => segment.startsWith('.')));
  if (dotted.length > 0) {
    results.fail('dot-entries', `dotfile or dot-directory entries: ${dotted.join(', ')}`);
  } else {
    results.pass('dot-entries');
  }

  // test-path-entries.
  const testish = entries.filter(
    (entry) => entry.includes('__tests__') || entry.includes('fixtures') || entry.includes('test/'),
  );
  if (testish.length > 0) {
    results.fail('test-path-entries', `test/fixture paths in the artifact: ${testish.join(', ')}`);
  } else {
    results.pass('test-path-entries');
  }

  // install-scripts.
  if (pkg === null) {
    results.fail('install-scripts', 'packed package.json missing or unparseable');
  } else {
    const lifecycle = ['preinstall', 'install', 'postinstall'].filter((name) => pkg.scripts?.[name] !== undefined);
    if (lifecycle.length > 0) {
      results.fail('install-scripts', `install-time lifecycle scripts in the packed package.json: ${lifecycle.join(', ')}`);
    } else {
      results.pass('install-scripts');
    }
  }

  // opena2a-pinned.
  if (pkg === null) {
    results.fail('opena2a-pinned', 'packed package.json missing or unparseable');
  } else {
    const loose = [];
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [name, range] of Object.entries(pkg[section] ?? {})) {
        if (name.startsWith('@opena2a/') && /^[\^~]/.test(String(range))) {
          loose.push(`${section}.${name}=${range}`);
        }
      }
    }
    if (loose.length > 0) {
      results.fail('opena2a-pinned', `caret/tilde range on first-party dependencies: ${loose.join(', ')}`);
    } else {
      results.pass('opena2a-pinned');
    }
  }

  // A statically bad tarball is not installed and not scanned: its failure is
  // already blocking, and running a hostile artifact to gather more evidence
  // is the wrong trade. The dynamic checks report the unmet precondition.
  const staticFailure = [
    'entry-allowlist',
    'dot-entries',
    'test-path-entries',
    'install-scripts',
    'opena2a-pinned',
  ].some((name) => results.statusOf(name) !== 'pass');

  const distDir = path.join(packageDir, 'dist');
  const distPresent = fs.existsSync(distDir) && fs.statSync(distDir).isDirectory();

  const prodDeps = { ...(pkg?.dependencies ?? {}), ...(pkg?.optionalDependencies ?? {}) };
  const hasProdDeps = Object.keys(prodDeps).length > 0;

  // Registry reachability, probed once, only when something below needs it.
  let registryReachable = null;
  const registryOk = () => {
    if (registryReachable === null) {
      const ping = run('npm', ['ping', '--registry', REGISTRY], { timeout: 30_000 });
      registryReachable = ping.status === 0;
    }
    return registryReachable;
  };

  // -------------------------------------------------------------------------
  // npm-audit
  // -------------------------------------------------------------------------
  if (staticFailure) {
    results.precondition('npm-audit', 'static checks failed; the artifact was not resolved against the registry');
  } else if (pkg === null) {
    results.precondition('npm-audit', 'packed package.json missing or unparseable');
  } else if (!hasProdDeps) {
    results.pass('npm-audit', 'no production dependencies to audit');
  } else if (!registryOk()) {
    results.precondition('npm-audit', 'registry unreachable (npm ping failed)');
  } else {
    const auditDir = path.join(work, 'audit');
    fs.cpSync(packageDir, auditDir, { recursive: true });
    const auditHome = path.join(work, 'audit-home');
    fs.mkdirSync(auditHome);
    const env = { ...process.env, HOME: auditHome };
    const lock = run(
      'npm',
      ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', '--registry', REGISTRY],
      { cwd: auditDir, env, timeout: 300_000 },
    );
    if (lock.status !== 0) {
      results.fail('npm-audit', `could not resolve a lockfile from the packed package.json: ${tailOf(lock)}`);
    } else {
      const audit = run('npm', ['audit', '--omit=dev', '--audit-level=high', '--registry', REGISTRY], {
        cwd: auditDir,
        env,
        timeout: 300_000,
      });
      if (audit.status === 0) {
        results.pass('npm-audit', 'no high-or-above advisories in the production dependency tree');
      } else {
        results.fail('npm-audit', `high-or-above advisories (or audit error): ${tailOf(audit)}`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // bin-smoke
  // -------------------------------------------------------------------------
  if (staticFailure) {
    results.precondition('bin-smoke', 'static checks failed; the tarball was not installed');
  } else if (!distPresent) {
    results.precondition('bin-smoke', 'dist/ absent from the tarball; there is nothing to install');
  } else if (hasProdDeps && !registryOk()) {
    results.precondition('bin-smoke', 'registry unreachable and the package has dependencies to install');
  } else {
    const prefix = path.join(work, 'prefix');
    const installHome = path.join(work, 'install-home');
    fs.mkdirSync(prefix);
    fs.mkdirSync(installHome);
    const install = run(
      'npm',
      ['install', '-g', tarball, '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', prefix],
      { env: { ...process.env, HOME: installHome }, timeout: 600_000 },
    );
    if (install.status !== 0) {
      results.fail('bin-smoke', `npm install -g --ignore-scripts failed: ${tailOf(install)}`);
    } else {
      const commands = [
        ['secretless-ai', ['--version']],
        ['secretless-ai', ['--help']],
        ['secretless-ai', ['init', '--help']],
        ['secretless-mcp', ['--help']],
      ];
      const problems = [];
      const ran = [];
      for (const [bin, args] of commands) {
        const label = `${bin} ${args.join(' ')}`;
        const binPath = path.join(prefix, 'bin', bin);
        if (!fs.existsSync(binPath)) {
          problems.push(`${label}: ${bin} was not installed into the prefix`);
          continue;
        }
        // Empty HOME, minimal PATH, no proxy variables: the bins must stand up
        // with nothing from this machine's environment and nothing remote.
        const runHome = fs.mkdtempSync(path.join(work, 'bin-home-'));
        const result = run(binPath, args, {
          env: {
            PATH: `${path.dirname(process.execPath)}:${path.join(prefix, 'bin')}`,
            HOME: runHome,
            NO_COLOR: '1',
          },
          timeout: 60_000,
        });
        const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
        if (result.status !== 0) {
          problems.push(`${label}: exited ${result.status}`);
        } else if (/\n\s+at .*:\d+:\d+/.test(output)) {
          problems.push(`${label}: printed a stack trace`);
        } else {
          ran.push(label);
        }
      }
      if (problems.length > 0) {
        results.fail('bin-smoke', problems.join('; '));
      } else {
        results.pass('bin-smoke', `clean-prefix install ok; ${ran.join(', ')} all exited 0 with no stack trace`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // credential-scan
  // -------------------------------------------------------------------------
  if (staticFailure) {
    results.precondition('credential-scan', 'static checks failed; the artifact was not scanned');
  } else if (!distPresent) {
    results.precondition('credential-scan', 'dist/ absent from the tarball; there is nothing to scan');
  } else {
    const scanner = resolveHackmyagent();
    if (scanner === null) {
      results.precondition('credential-scan', 'hackmyagent not resolvable (node_modules/.bin or PATH)');
    } else {
      const scratch = path.join(work, 'scan', 'dist');
      fs.cpSync(distDir, scratch, { recursive: true });
      // The planted control: realistic secrets, freshly generated so no
      // placeholder allowlist can excuse them. If the scanner cannot find
      // this file, its "zero findings" means nothing.
      fs.writeFileSync(path.join(scratch, PLANTED_NAME), plantedCredentials());
      const scan = run(scanner, ['scan', path.dirname(scratch), '--json'], { timeout: 300_000 });
      const findings = parseFindings(scan.stdout ?? '');
      if (findings === null) {
        results.fail('credential-scan', `unparseable scanner output (exit ${scan.status}): ${tailOf(scan)}`);
      } else {
        const planted = findings.filter((f) => String(f.file ?? f.path ?? '').includes(PLANTED_NAME));
        const others = findings.filter((f) => !String(f.file ?? f.path ?? '').includes(PLANTED_NAME));
        if (planted.length === 0) {
          results.fail('credential-scan', 'the planted control was not found — the scanner is not detecting');
        } else if (others.length > 0) {
          const where = others.map((f) => String(f.file ?? f.path ?? '<unknown>'));
          results.fail('credential-scan', `credential findings in the artifact: ${[...new Set(where)].join(', ')}`);
        } else {
          results.pass('credential-scan', "planted control found; zero findings in the artifact's dist/");
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // own-package-census
  // -------------------------------------------------------------------------
  const censusScript = path.join(REPO_ROOT, 'scripts', 'own-package-census.mjs');
  if (!fs.existsSync(censusScript)) {
    // The placeholdered exception: known absent in all four CLI repos at
    // intake (2026-09-02), so its absence is visible but not blocking.
    results.precondition('own-package-census', 'own-package census script absent', { blocking: false });
  } else {
    const census = run(process.execPath, [censusScript, '--tarball', tarball], {
      env: { ...process.env, MODE: 'gate' },
      timeout: 300_000,
    });
    if (census.status === 0) {
      results.pass('own-package-census');
    } else {
      results.fail('own-package-census', `own-package-census.mjs MODE=gate exited ${census.status}: ${tailOf(census)}`);
    }
  }
}

/** The last few output lines of a spawn result, for a failure detail. */
function tailOf(result) {
  const text = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim();
  return text.split('\n').slice(-4).join(' | ').slice(0, 600);
}

/** hackmyagent, from this repo's node_modules/.bin or from PATH. */
function resolveHackmyagent() {
  const candidates = [path.join(REPO_ROOT, 'node_modules', '.bin', 'hackmyagent')];
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (dir.length > 0) candidates.push(path.join(dir, 'hackmyagent'));
  }
  for (const candidate of candidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      /* not this one */
    }
  }
  return null;
}

/** Fresh, realistic credential material for the planted control file. */
function plantedCredentials() {
  const upper = (n) =>
    crypto.randomBytes(n * 2).toString('base64').replace(/[^A-Z0-9]/g, '').slice(0, n).padEnd(n, '7');
  const alnum = (n) =>
    crypto.randomBytes(n * 2).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, n).padEnd(n, 'x');
  return [
    '# planted credential control — written by release-artifact-review.mjs into a scratch copy only',
    `aws_access_key_id = AKIA${upper(16)}`,
    `aws_secret_access_key = ${alnum(40)}`,
    `github_token = ghp_${alnum(36)}`,
    '',
  ].join('\n');
}

/** The scanner's findings array, or null when the output is not usable. */
function parseFindings(stdout) {
  const text = stdout.trim();
  const start = text.indexOf('{');
  if (start === -1) return null;
  try {
    const parsed = JSON.parse(text.slice(start));
    return Array.isArray(parsed.findings) ? parsed.findings : null;
  } catch {
    return null;
  }
}

main();
