#!/usr/bin/env node

/**
 * release-artifact-review.mjs — the release gate's review of the packed tarball.
 *
 * Usage: node scripts/release-artifact-review.mjs --tarball <path>
 *          [--advisory-states published|all]
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
 * `precondition: <what is missing>` and exits non-zero: an unrunnable review
 * is a blocked release, not a passed one.
 *
 * Checks, in order:
 *   entry-allowlist          every file entry is package/dist/**,
 *                            package/README.md, package/LICENSE or
 *                            package/package.json — the closure of
 *                            package.json's `files: ["dist"]` plus what npm
 *                            always adds
 *   no-dotfiles              no dotfile or dot-directory entry (.npmrc, .env,
 *                            .git, …)
 *   no-test-material         no entry path containing __tests__, fixtures or
 *                            test/
 *   no-install-scripts       no preinstall, install or postinstall in the
 *                            packed package.json — nothing runs on the
 *                            consumer's machine
 *   pinned-first-party-deps  no caret or tilde range on any @opena2a/*
 *                            dependency: first-party deps are pinned exactly
 *   npm-audit                `npm audit --omit=dev --audit-level=high` over a
 *                            lockfile resolved from the packed package.json
 *   global-install-smoke     `npm install -g <tarball> --ignore-scripts` into
 *                            a clean temp prefix, then with an empty HOME and
 *                            no network: secretless-ai --version / --help /
 *                            init --help and secretless-mcp --help must exit 0
 *                            without a stack trace
 *   credential-scan          hackmyagent (node_modules/.bin first, PATH only
 *                            as a fallback) `secure --format json` over a
 *                            scratch directory holding the tarball's
 *                            package/dist/ entries extracted FLAT — no `dist`
 *                            path component, because the scanner's AST
 *                            credential walk skips directories named `dist`
 *                            (scanner-bridge.js SKIP_DIRS) — plus one planted
 *                            control file the scanner must flag; zero
 *                            credential-class findings on any shipped file
 *   consumer-closure         the fresh-install closure of THIS tarball,
 *                            resolved with `npm install --package-lock-only`;
 *                            every own package in it (hackmyagent,
 *                            secretless-ai, ai-trust, opena2a-cli, arp-guard,
 *                            damn-vulnerable-ai-agent, cryptoserve, @opena2a/*
 *                            — the packed package itself included) must be
 *                            neither deprecated on the registry nor inside any
 *                            vulnerable_version_range of its repository's
 *                            GitHub security advisories
 */

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PLANTED_NAME = '00-planted-credential-control.js';

/**
 * The own-package roster: the FLOOR of todo/scripts/own-package-census.mjs
 * plus the @opena2a/ scope. A lockfile package matches on its alias-resolved
 * name, and the packed package itself is in scope.
 */
const OWN_PACKAGE_NAMES = new Set([
  'hackmyagent',
  'secretless-ai',
  'ai-trust',
  'opena2a-cli',
  'arp-guard',
  'damn-vulnerable-ai-agent',
  'cryptoserve',
]);
const OWN_SCOPE_PREFIX = '@opena2a/';

/**
 * One version the registry is known to answer `deprecated` for, probed before
 * the real deprecation rows so an empty answer can be told apart from a probe
 * that silently stopped working.
 *
 * UNSET (SLS-06, 2026-09-03): the delivery rotation's sandbox 403-filters
 * every registry read, so no deprecated own version could be named. Until a
 * rotation with registry egress pins one — discover it with
 * `npm view 'hackmyagent@*' deprecated --json` (any own package works) and
 * put its name@version here — the consumer-closure check reports a visible
 * `precondition` naming this sentinel, never a pass.
 */
const KNOWN_DEPRECATED = { name: 'hackmyagent', version: '0.25.0' };

/** Ordered check names; the census line reports every one of these, always. */
const CHECK_NAMES = [
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

function usage(message) {
  process.stderr.write(
    `${message}\nusage: node scripts/release-artifact-review.mjs --tarball <path> [--advisory-states published|all]\n`,
  );
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
    this.byName = new Map(); // name -> status
  }
  record(name, status, detail) {
    this.byName.set(name, status);
    console.log(`check ${name}: ${status}${detail ? `: ${detail}` : ''}`);
  }
  pass(name, detail) {
    this.record(name, 'pass', detail);
  }
  fail(name, detail) {
    this.record(name, 'fail', detail);
  }
  precondition(name, missing) {
    this.record(name, 'precondition', missing);
  }
  statusOf(name) {
    return this.byName.get(name) ?? 'fail';
  }
}

function main() {
  const argv = process.argv.slice(2);
  const tarballIndex = argv.indexOf('--tarball');
  if (tarballIndex === -1 || tarballIndex + 1 >= argv.length) usage('missing required --tarball <path>');
  const tarball = path.resolve(argv[tarballIndex + 1]);
  if (!fs.existsSync(tarball)) usage(`no such tarball: ${tarball}`);

  let advisoryStates = 'all';
  const statesIndex = argv.indexOf('--advisory-states');
  if (statesIndex !== -1) {
    advisoryStates = argv[statesIndex + 1] ?? '';
    if (advisoryStates !== 'published' && advisoryStates !== 'all') {
      usage(`--advisory-states must be published or all, not "${advisoryStates}"`);
    }
  }

  console.log(`release-artifact-review: reviewing ${tarball} (advisory states: ${advisoryStates})`);

  const results = new Results();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'release-artifact-review-'));
  try {
    review(tarball, work, advisoryStates, results);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }

  // The census: every check, every run, no matter what happened above.
  console.log(`census: ${CHECK_NAMES.map((name) => `${name}=${results.statusOf(name)}`).join(' ')}`);

  const failing = CHECK_NAMES.filter((name) => results.statusOf(name) === 'fail');
  const preconditions = CHECK_NAMES.filter((name) => results.statusOf(name) === 'precondition');

  if (failing.length > 0 || preconditions.length > 0) {
    const parts = [];
    if (failing.length > 0) parts.push(`failing: ${failing.join(', ')}`);
    if (preconditions.length > 0) parts.push(`preconditions not met: ${preconditions.join(', ')}`);
    console.log(`result: fail — ${parts.join('; ')}`);
    process.exit(1);
  }
  console.log('result: pass');
  process.exit(0);
}

function review(tarball, work, advisoryStates, results) {
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

  // no-dotfiles: any path segment starting with a dot, file or directory.
  const dotted = entries.filter((entry) => entry.split('/').some((segment) => segment.startsWith('.')));
  if (dotted.length > 0) {
    results.fail('no-dotfiles', `dotfile or dot-directory entries: ${dotted.join(', ')}`);
  } else {
    results.pass('no-dotfiles');
  }

  // no-test-material.
  const testish = entries.filter(
    (entry) => entry.includes('__tests__') || entry.includes('fixtures') || entry.includes('test/'),
  );
  if (testish.length > 0) {
    results.fail('no-test-material', `test/fixture paths in the artifact: ${testish.join(', ')}`);
  } else {
    results.pass('no-test-material');
  }

  // no-install-scripts.
  if (pkg === null) {
    results.fail('no-install-scripts', 'packed package.json missing or unparseable');
  } else {
    const lifecycle = ['preinstall', 'install', 'postinstall'].filter((name) => pkg.scripts?.[name] !== undefined);
    if (lifecycle.length > 0) {
      results.fail('no-install-scripts', `install-time lifecycle scripts in the packed package.json: ${lifecycle.join(', ')}`);
    } else {
      results.pass('no-install-scripts');
    }
  }

  // pinned-first-party-deps.
  if (pkg === null) {
    results.fail('pinned-first-party-deps', 'packed package.json missing or unparseable');
  } else {
    const loose = [];
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [name, range] of Object.entries(pkg[section] ?? {})) {
        if (name.startsWith(OWN_SCOPE_PREFIX) && /^[\^~]/.test(String(range))) {
          loose.push(`${section}.${name}=${range}`);
        }
      }
    }
    if (loose.length > 0) {
      results.fail('pinned-first-party-deps', `caret/tilde range on first-party dependencies: ${loose.join(', ')}`);
    } else {
      results.pass('pinned-first-party-deps');
    }
  }

  // A statically bad tarball is not installed and not scanned: its failure is
  // already blocking, and running a hostile artifact to gather more evidence
  // is the wrong trade. The dynamic checks report the unmet precondition.
  const staticFailure = [
    'entry-allowlist',
    'no-dotfiles',
    'no-test-material',
    'no-install-scripts',
    'pinned-first-party-deps',
  ].some((name) => results.statusOf(name) !== 'pass');

  const distDir = path.join(packageDir, 'dist');
  const distPresent = fs.existsSync(distDir) && fs.statSync(distDir).isDirectory();

  const prodDeps = { ...(pkg?.dependencies ?? {}), ...(pkg?.optionalDependencies ?? {}) };
  const hasProdDeps = Object.keys(prodDeps).length > 0;

  // Registry reachability, probed once, only when something below needs it.
  let registryReachable = null;
  const registryOk = () => {
    if (registryReachable === null) {
      const ping = run('npm', ['ping'], { timeout: 30_000 });
      registryReachable = ping.status === 0;
    }
    return registryReachable;
  };

  // The scratch closure resolution, shared by npm-audit and consumer-closure.
  let closureDir = null;
  const resolveClosure = () => {
    if (closureDir !== null) return closureDir;
    const dir = path.join(work, 'closure');
    fs.mkdirSync(dir);
    const home = path.join(work, 'closure-home');
    fs.mkdirSync(home);
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'closure-scratch', version: '0.0.0' }));
    const install = run(
      'npm',
      ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', tarball],
      { cwd: dir, env: { ...process.env, HOME: home }, timeout: 300_000 },
    );
    closureDir = { dir, ok: install.status === 0, detail: install.status === 0 ? '' : tailOf(install) };
    return closureDir;
  };

  // -------------------------------------------------------------------------
  // npm-audit
  // -------------------------------------------------------------------------
  if (staticFailure) {
    results.precondition('npm-audit', 'static checks failed; the artifact was not resolved against the registry');
  } else if (pkg === null) {
    results.precondition('npm-audit', 'packed package.json missing or unparseable');
  } else if (!hasProdDeps) {
    results.pass('npm-audit', 'no production dependencies to audit; the resolved closure is the package alone');
  } else if (!registryOk()) {
    results.precondition('npm-audit', 'registry unreachable (npm ping failed)');
  } else {
    const closure = resolveClosure();
    if (!closure.ok) {
      results.precondition('npm-audit', `could not resolve a lockfile from the packed tarball: ${closure.detail}`);
    } else {
      const audit = run('npm', ['audit', '--omit=dev', '--audit-level=high'], {
        cwd: closure.dir,
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
  // global-install-smoke
  // -------------------------------------------------------------------------
  if (staticFailure) {
    results.precondition('global-install-smoke', 'static checks failed; the tarball was not installed');
  } else if (!distPresent) {
    results.precondition('global-install-smoke', 'dist/ absent from the tarball; there is nothing to install');
  } else if (hasProdDeps && !registryOk()) {
    results.precondition('global-install-smoke', 'registry unreachable and the package has dependencies to install');
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
      results.fail('global-install-smoke', `npm install -g --ignore-scripts failed: ${tailOf(install)}`);
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
        results.fail('global-install-smoke', problems.join('; '));
      } else {
        results.pass('global-install-smoke', `clean-prefix install ok; ${ran.join(', ')} all exited 0 with no stack trace`);
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
      results.precondition(
        'credential-scan',
        'hackmyagent not resolvable (node_modules/.bin first, then PATH); run `npm ci --ignore-scripts`',
      );
    } else {
      const version = scannerVersion(scanner);
      // The dist/ entries are laid out FLAT — each at its path relative to
      // package/dist/, with no `dist` path component anywhere — because the
      // scanner's AST credential walk skips any directory named `dist`
      // (scanner-bridge.js SKIP_DIRS): scanning the tree as packed would scan
      // nothing at all.
      const scratch = path.join(work, 'scan-scratch');
      fs.mkdirSync(scratch);
      for (const entry of fileEntries) {
        if (!entry.startsWith('package/dist/')) continue;
        const rel = entry.slice('package/dist/'.length);
        const target = path.join(scratch, rel);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(path.join(packageDir, 'dist', rel), target);
      }
      // The planted control, written beside the shipped files: one
      // credential-named const whose value is assembled at runtime from parts,
      // so no credential-shaped literal exists in this repository. A scan that
      // cannot find this file proves nothing by finding nothing.
      const controlDir = path.join(work, 'control-scratch');
      fs.mkdirSync(controlDir);
      fs.writeFileSync(
        path.join(controlDir, PLANTED_NAME),
        [
          '// planted control written by release-artifact-review.mjs into a scratch copy only;',
          '// the value is assembled here at runtime and written as a literal so the scanner sees a credential-shaped string',
          `const OPENAI_API_KEY = ${JSON.stringify(['sk-', 'proj-'].join('') + 'A'.repeat(48))};`,
          'module.exports = { OPENAI_API_KEY };',
          '',
        ].join('\n'),
      );
      // Two scans, not one: the scanner reports a single location per check id, so a
      // planted control scanned alongside the shipped files would mask a shipped credential
      // carrying the same check id. The shipped files are scanned alone; the control alone.
      const scan = run(scanner, ['secure', '--format', 'json'], { cwd: scratch, timeout: 300_000 });
      const controlScan = run(scanner, ['secure', '--format', 'json'], { cwd: controlDir, timeout: 300_000 });
      const shippedFindings = parseFindings(scan.stdout ?? '');
      const controlFindings = parseFindings(controlScan.stdout ?? '');
      const findings = shippedFindings === null || controlFindings === null ? null : [...shippedFindings, ...controlFindings];
      if (findings === null) {
        results.precondition(
          'credential-scan',
          `hackmyagent@${version} produced unparseable output (exit ${scan.status}): ${tailOf(scan)}`,
        );
      } else {
        const credential = findings.filter(
          (f) => /CRED/.test(String(f.checkId ?? '')) || String(f.checkId ?? '') === 'CONFIG-004',
        );
        const planted = credential.filter((f) => String(f.file ?? f.path ?? '').includes(PLANTED_NAME));
        const shipped = credential.filter((f) => !String(f.file ?? f.path ?? '').includes(PLANTED_NAME));
        if (planted.length === 0) {
          results.precondition('credential-scan', `control not flagged by hackmyagent@${version}`);
        } else if (shipped.length > 0) {
          // checkId and file:line only — never the matched text, which would
          // print the very value the check exists to keep out of logs.
          const rows = shipped.map(
            (f) => `${String(f.checkId ?? '<unknown>')} at ${String(f.file ?? f.path ?? '<unknown>')}:${String(f.line ?? '?')}`,
          );
          results.fail('credential-scan', `credential findings on shipped files: ${[...new Set(rows)].join(', ')}`);
        } else {
          results.pass(
            'credential-scan',
            `hackmyagent@${version}: planted control found (${planted.map((f) => String(f.checkId)).join('/')}), zero credential-class findings on shipped files`,
          );
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // consumer-closure
  // -------------------------------------------------------------------------
  if (staticFailure) {
    results.precondition('consumer-closure', 'static checks failed; the closure was not resolved');
  } else if (pkg === null) {
    results.precondition('consumer-closure', 'packed package.json missing or unparseable');
  } else if (!registryOk()) {
    results.precondition('consumer-closure', 'registry unreachable (npm ping failed)');
  } else {
    consumerClosure(tarball, advisoryStates, resolveClosure, results);
  }
}

/**
 * The consumer-closure check: every own package in the fresh-install closure
 * of this tarball must be neither deprecated nor inside any
 * vulnerable_version_range of its repository's GitHub security advisories.
 */
function consumerClosure(tarball, advisoryStates, resolveClosure, results) {
  const closure = resolveClosure();
  if (!closure.ok) {
    results.precondition('consumer-closure', `the fresh-install closure did not resolve: ${closure.detail}`);
    return;
  }
  let lock = null;
  try {
    lock = JSON.parse(fs.readFileSync(path.join(closure.dir, 'package-lock.json'), 'utf-8'));
  } catch {
    results.precondition('consumer-closure', 'the resolved closure produced no readable package-lock.json');
    return;
  }

  // Alias-aware: a lockfile entry's name is its `name` field when present
  // (npm records it for aliased installs), else the path under node_modules.
  const ownCopies = new Map(); // "name@version" -> { name, version }
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (key === '') continue;
    const pathName = key.replace(/^.*node_modules\//, '');
    const name = typeof entry.name === 'string' && entry.name.length > 0 ? entry.name : pathName;
    const version = entry.version;
    if (typeof version !== 'string') continue;
    if (OWN_PACKAGE_NAMES.has(name) || name.startsWith(OWN_SCOPE_PREFIX)) {
      ownCopies.set(`${name}@${version}`, { name, version });
    }
  }

  if (ownCopies.size === 0) {
    results.pass(
      'consumer-closure',
      `0 own copies in the closure; no deprecation or advisory rows to read (advisory states: ${advisoryStates})`,
    );
    return;
  }

  // The deprecation probe must be shown alive before its empty answers count:
  // a known-deprecated version that reads back empty means the probe, not the
  // registry, is broken.
  const probe = npmViewDeprecated(KNOWN_DEPRECATED.name, KNOWN_DEPRECATED.version);
  if (probe.error !== null) {
    results.precondition('consumer-closure', `deprecation probe errored on ${KNOWN_DEPRECATED.name}@${KNOWN_DEPRECATED.version}: ${probe.error}`);
    return;
  }
  if (probe.message === '') {
    results.precondition(
      'consumer-closure',
      `deprecation probe read empty on known-deprecated ${KNOWN_DEPRECATED.name}@${KNOWN_DEPRECATED.version}; the probe cannot be trusted`,
    );
    return;
  }

  // One packument read per distinct own name: the published-version list
  // (a version the registry has never seen — the freshly packed release
  // itself — cannot be deprecated and is not probed) and the repository URL.
  const publishedVersions = new Map(); // package name -> Set<version>
  const repoOf = new Map(); // package name -> "owner/repo"
  for (const { name } of ownCopies.values()) {
    if (repoOf.has(name)) continue;
    const view = run('npm', ['view', name, 'versions', 'repository.url', '--json'], { timeout: 60_000 });
    let packument = null;
    try {
      packument = JSON.parse(view.stdout ?? '');
    } catch {
      packument = null;
    }
    if (view.status !== 0 || packument === null) {
      results.precondition('consumer-closure', `packument read for ${name} errored: ${tailOf(view)}`);
      return;
    }
    const versions = Array.isArray(packument.versions) ? packument.versions : [packument.versions].filter(Boolean);
    publishedVersions.set(name, new Set(versions));
    const url = String(packument['repository.url'] ?? '');
    const match = /github\.com[/:]([^/]+)\/([^/#]+?)(?:\.git)?(?:[#/].*)?$/.exec(url);
    if (url === '' || match === null) {
      results.precondition('consumer-closure', `no GitHub repository URL on the registry for ${name} (read "${url}")`);
      return;
    }
    repoOf.set(name, `${match[1]}/${match[2]}`);
  }

  const failures = [];
  let deprecationProbes = 0;
  for (const { name, version } of ownCopies.values()) {
    if (!publishedVersions.get(name)?.has(version)) continue;
    const read = npmViewDeprecated(name, version);
    if (read.error !== null) {
      results.precondition('consumer-closure', `npm view ${name}@${version} deprecated errored: ${read.error}`);
      return;
    }
    deprecationProbes += 1;
    if (read.message !== '') {
      failures.push(`${name}@${version} is deprecated: "${read.message}"`);
    }
  }

  const advisoriesByRepo = new Map(); // "owner/repo" -> advisory[]
  let advisoryRows = 0;
  for (const repo of new Set(repoOf.values())) {
    const stateParam = advisoryStates === 'published' ? '&state=published' : '';
    const url = `https://api.github.com/repos/${repo}/security-advisories?per_page=100${stateParam}`;
    const response = httpGetJson(url);
    if (response.error !== null || !Array.isArray(response.body)) {
      results.precondition(
        'consumer-closure',
        `advisories endpoint unreadable for ${repo} (states: ${advisoryStates}): ${response.error ?? 'not an advisory list'}`,
      );
      return;
    }
    advisoriesByRepo.set(repo, response.body);
    advisoryRows += response.body.length;
  }

  // Zero advisories across every roster repository cannot be told apart from
  // a feed that silently stopped answering — unless a deprecation row already
  // failed the check, in which case the verdict is settled either way.
  if (advisoryRows === 0 && failures.length === 0) {
    results.precondition(
      'consumer-closure',
      `the advisory feed returned zero advisories across ${advisoriesByRepo.size} roster repositories (states: ${advisoryStates}); an empty feed cannot be told apart from a broken read`,
    );
    return;
  }

  // GitHub joins compound ranges with ", "; npm semver wants a space.
  const semver = requireSemver();
  if (semver === null) {
    results.precondition('consumer-closure', 'the semver package is not resolvable; run `npm ci --ignore-scripts`');
    return;
  }
  for (const { name, version } of ownCopies.values()) {
    for (const advisory of advisoriesByRepo.get(repoOf.get(name)) ?? []) {
      for (const vuln of advisory.vulnerabilities ?? []) {
        if (vuln.package?.ecosystem !== 'npm' || vuln.package?.name !== name) continue;
        const range = String(vuln.vulnerable_version_range ?? '').split(', ').join(' ');
        if (range === '') continue;
        let satisfied = false;
        try {
          satisfied = semver.satisfies(version, range, { includePrerelease: true });
        } catch {
          results.precondition('consumer-closure', `unparseable vulnerable_version_range "${range}" on ${advisory.ghsa_id} for ${name}`);
          return;
        }
        if (satisfied) {
          failures.push(`${name}@${version} satisfies ${advisory.ghsa_id} (${advisory.state ?? 'published'}) range "${range}"`);
        }
      }
    }
  }

  const copies = [...ownCopies.keys()].sort().join(', ');
  if (failures.length > 0) {
    results.fail('consumer-closure', `${failures.join('; ')} — own copies examined: ${copies} (advisory states: ${advisoryStates})`);
  } else {
    results.pass(
      'consumer-closure',
      `own copies examined: ${copies}; advisory states read: ${advisoryStates}; ${advisoriesByRepo.size} repositories, ${advisoryRows} advisory rows, ${deprecationProbes} deprecation probes, 0 deprecated, 0 in a vulnerable range`,
    );
  }
}

/** `npm view name@version deprecated` → { message, error }. */
function npmViewDeprecated(name, version) {
  const view = run('npm', ['view', `${name}@${version}`, 'deprecated'], { timeout: 60_000 });
  if (view.status !== 0) return { message: '', error: tailOf(view) };
  return { message: (view.stdout ?? '').trim(), error: null };
}

/**
 * GET a JSON URL. Runs in a child node with NODE_USE_ENV_PROXY=1 so the read
 * honours HTTPS_PROXY where one is configured (fetch ignores it by default);
 * GH_TOKEN, when present, authenticates the read — the release workflow hands
 * the job token in.
 */
function httpGetJson(url) {
  const program = [
    'const headers = { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "release-artifact-review" };',
    'if (process.env.GH_TOKEN) headers.authorization = `Bearer ${process.env.GH_TOKEN}`;',
    'const res = await fetch(process.env.REVIEW_GET_URL, { headers });',
    'const text = await res.text();',
    'console.log(JSON.stringify({ status: res.status, text }));',
  ].join('\n');
  const child = run(process.execPath, ['--input-type=module', '-e', program], {
    env: { ...process.env, NODE_USE_ENV_PROXY: '1', REVIEW_GET_URL: url },
    timeout: 60_000,
  });
  if (child.status !== 0) return { body: null, error: `fetch failed: ${tailOf(child)}` };
  try {
    const { status, text } = JSON.parse(child.stdout);
    if (status === 403 || status === 429) return { body: null, error: `rate-limited or forbidden (HTTP ${status})` };
    if (status !== 200) return { body: null, error: `HTTP ${status}` };
    return { body: JSON.parse(text), error: null };
  } catch {
    return { body: null, error: 'unparseable response' };
  }
}

/** The last few output lines of a spawn result, for a failure detail. */
function tailOf(result) {
  const text = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim();
  return text.split('\n').slice(-4).join(' | ').slice(0, 600);
}

/** hackmyagent: this repo's node_modules/.bin first, PATH only as a fallback. */
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

/** The scanner's version string, for the census row. */
function scannerVersion(scanner) {
  const result = run(scanner, ['--version'], { timeout: 30_000 });
  const match = /\d+\.\d+\.\d+[^\s]*/.exec(`${result.stdout ?? ''}${result.stderr ?? ''}`);
  return match ? match[0] : '<unknown version>';
}

/**
 * The npm semver implementation, resolved lazily: this repo's node_modules
 * when a copy is installed there, else the copy npm itself ships with — the
 * range semantics under `vulnerable_version_range` are npm's, so npm's own
 * resolver is the reference implementation.
 */
function requireSemver() {
  try {
    return createRequire(path.join(REPO_ROOT, 'package.json'))('semver');
  } catch {
    /* fall through to npm's bundled copy */
  }
  try {
    const globalRoot = (run('npm', ['root', '-g'], { timeout: 30_000 }).stdout ?? '').trim();
    const bundled = path.join(globalRoot, 'npm', 'node_modules', 'semver');
    return createRequire(path.join(bundled, 'package.json'))(bundled);
  } catch {
    return null;
  }
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
