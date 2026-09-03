import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * The release path in .github/workflows/release.yml, and the install-config
 * guard on every job that runs `npm ci`.
 *
 * Why this file exists. The old release.yml was one job that held
 * `contents: write` and `id-token: write` together, checked out the tree,
 * built, tested and published from it, and then verified attestations on the
 * BARE package name — which reads whatever `latest` is, not what this run
 * published. Nothing reviewed the bytes npm would actually ship.
 *
 * The split under test: `build` packs the tarball and records its digest;
 * `review` runs scripts/release-artifact-review.mjs over those exact bytes;
 * `publish` — the only job with `id-token: write`, with no checkout —
 * publishes the reviewed tarball and verifies the VERSIONED package's
 * provenance and integrity against the recorded digest; the GitHub release
 * runs in its own job with `contents: write` and no id-token.
 *
 * The same indent-walk reading as src/ci-gate.test.ts: no YAML dependency,
 * comments stripped before any substring assertion.
 */

const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const RELEASE = fs.readFileSync(path.join(REPO_ROOT, '.github', 'workflows', 'release.yml'), 'utf-8');
const CI = fs.readFileSync(path.join(REPO_ROOT, '.github', 'workflows', 'ci.yml'), 'utf-8');

/** The guard command AC4 fixes, verbatim. */
const GUARD_GREP = String.raw`git ls-files | grep -E '(^|/)(\.npmrc|\.yarnrc(\.yml)?|\.pnpmfile\.cjs|\.envrc)$'`;

// ---------------------------------------------------------------------------
// Indent-walk helpers
// ---------------------------------------------------------------------------

function stripComments(block: string): string {
  return block
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
}

function topLevelBlock(workflow: string, key: string): string {
  const lines = workflow.split('\n');
  const start = lines.findIndex((line) => line === `${key}:` || line.startsWith(`${key}:`));
  expect(start, `workflow has no top-level "${key}:"`).toBeGreaterThanOrEqual(0);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || /^\s/.test(lines[end]))) end += 1;
  return lines.slice(start, end).join('\n');
}

function jobIds(workflow: string): string[] {
  return stripComments(topLevelBlock(workflow, 'jobs'))
    .split('\n')
    .map((line) => /^ {2}([A-Za-z][A-Za-z0-9_-]*):/.exec(line))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => m[1]);
}

function jobBlock(workflow: string, jobId: string): string {
  const lines = topLevelBlock(workflow, 'jobs').split('\n');
  const start = lines.findIndex((line) => line === `  ${jobId}:`);
  expect(start, `workflow has no job "${jobId}"`).toBeGreaterThanOrEqual(0);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || /^ {3,}/.test(lines[end]))) end += 1;
  return stripComments(lines.slice(start, end).join('\n'));
}

/** The entries under a job's `permissions:` key, e.g. ["contents: read"]. */
function jobPermissions(job: string): string[] {
  const lines = job.split('\n');
  const start = lines.findIndex((line) => line === '    permissions:');
  if (start === -1) return [];
  const entries: string[] = [];
  for (let i = start + 1; i < lines.length && /^ {6}\S/.test(lines[i]); i += 1) {
    entries.push(lines[i].trim());
  }
  return entries;
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

/** The script body of the guard step (its `run: |` block), dedented. */
function guardScript(job: string): string {
  const step = stepBlocks(job).find((block) => block.includes(GUARD_GREP));
  expect(step, 'job has no guard step').toBeDefined();
  const lines = step!.split('\n');
  const runIndex = lines.findIndex((line) => /^ {8}run: \|$/.test(line));
  expect(runIndex, 'guard step is not a run: | block').toBeGreaterThanOrEqual(0);
  return lines
    .slice(runIndex + 1)
    .filter((line) => line.trim() !== '')
    .map((line) => line.slice(10))
    .join('\n');
}

// ---------------------------------------------------------------------------
// SLS-06.AC1 — the split release path
// ---------------------------------------------------------------------------

describe('release.yml is split into build, tarball review and publish', () => {
  it('SLS-06.AC1 still triggers on v* tag pushes only', () => {
    const on = stripComments(topLevelBlock(RELEASE, 'on'));
    expect(on).toContain('push:');
    expect(on).toContain('tags:');
    expect(on).toMatch(/^ {6}- 'v\*'$/m);
    expect(on).not.toContain('branches:');
  });

  it('SLS-06.AC1 the top level grants neither contents: write nor id-token: write', () => {
    const permissions = stripComments(topLevelBlock(RELEASE, 'permissions'));
    expect(permissions).toContain('contents: read');
    expect(permissions).not.toContain('contents: write');
    expect(permissions).not.toContain('id-token');
  });

  it('SLS-06.AC1 the jobs are build, review, publish and a release job, joined by needs in that order', () => {
    expect(jobIds(RELEASE)).toEqual(['build', 'review', 'publish', 'github-release']);
    expect(jobBlock(RELEASE, 'review')).toMatch(/^ {4}needs: build$/m);
    expect(jobBlock(RELEASE, 'publish')).toMatch(/^ {4}needs: review$/m);
    expect(jobBlock(RELEASE, 'github-release')).toMatch(/^ {4}needs: publish$/m);
  });

  it('SLS-06.AC1 build has contents: read only, installs with --ignore-scripts, builds, tests, packs, records the sha256 and uploads the tarball', () => {
    const build = jobBlock(RELEASE, 'build');
    expect(jobPermissions(build)).toEqual(['contents: read']);
    expect(build).toContain('- run: npm ci --ignore-scripts');
    expect(build).toContain('- run: npm run build');
    expect(build).toContain('- run: npm test');
    expect(build).toContain('npm pack --pack-destination');
    expect(build).toContain('tarball-sha256=${sha256}');
    expect(build).toContain('>> "$GITHUB_OUTPUT"');
    expect(build).toMatch(/^ {6}tarball-sha256: \$\{\{ steps\.pack\.outputs\.tarball-sha256 \}\}$/m);
    expect(build).toContain('uses: actions/upload-artifact@v4');
  });

  it('SLS-06.AC1 review downloads the artifact and fails on a non-zero exit of the review script', () => {
    const review = jobBlock(RELEASE, 'review');
    expect(review).toContain('uses: actions/download-artifact@v4');
    expect(review).toContain('run: node scripts/release-artifact-review.mjs --tarball "$TARBALL"');
    // Nothing swallows the exit code: a non-zero exit of any step fails the job.
    expect(review).not.toContain('continue-on-error');
    expect(review).not.toContain('|| true');
    // And the bytes reviewed are the bytes built: the digest is confirmed first.
    expect(review.indexOf('sha256sum')).toBeGreaterThanOrEqual(0);
    expect(review.indexOf('sha256sum')).toBeLessThan(review.indexOf('release-artifact-review.mjs'));
  });

  it('SLS-06.AC1 publish holds id-token: write and nothing else, and never checks out a tree', () => {
    const publish = jobBlock(RELEASE, 'publish');
    expect(jobPermissions(publish)).toEqual(['id-token: write']);
    expect(publish).not.toContain('actions/checkout');
    expect(publish).toContain('run: npm publish "$TARBALL" --provenance --access public');
  });

  it('SLS-06.AC1 no job other than publish carries id-token: write', () => {
    for (const jobId of jobIds(RELEASE)) {
      const permissions = jobPermissions(jobBlock(RELEASE, jobId));
      if (jobId === 'publish') {
        expect(permissions).toContain('id-token: write');
      } else {
        expect(permissions.join('\n')).not.toContain('id-token');
      }
    }
    // ci.yml grants no id-token anywhere either.
    expect(stripComments(CI)).not.toContain('id-token');
  });

  it('SLS-06.AC1 the post-publish verification is versioned and checks predicateType and dist.integrity against the recorded digest', () => {
    const publish = jobBlock(RELEASE, 'publish');
    const verify = stepBlocks(publish).find((step) => step.includes('dist.attestations'));
    expect(verify, 'publish has no attestation verify step').toBeDefined();

    // After publish, not before.
    expect(publish.indexOf('npm publish')).toBeLessThan(publish.indexOf('dist.attestations'));

    // Versioned, never the bare package name: `npm view secretless-ai` reads
    // whatever `latest` is, which is not necessarily what this run published.
    expect(verify!).toContain('npm view "secretless-ai@${version}" dist.attestations');
    expect(verify!).toContain('npm view "secretless-ai@${version}" dist.integrity');
    expect(RELEASE).not.toMatch(/npm view "secretless-ai" /);

    expect(verify!).toContain('https://slsa.dev/provenance/v1');
    // The integrity read from the registry is compared against the digest
    // recorded at build time: same bytes end to end.
    expect(verify!).toContain('EXPECTED_SHA256: ${{ needs.review.outputs.tarball-sha256 }}');
    expect(verify!).toContain('sha512-');
  });

  it('SLS-06.AC1 the GitHub release runs in its own job with contents: write and no id-token', () => {
    const release = jobBlock(RELEASE, 'github-release');
    expect(jobPermissions(release)).toEqual(['contents: write']);
    expect(release).toContain('uses: softprops/action-gh-release@v2');
    expect(release).not.toContain('id-token');
    // And in a job of its own means: not sharing a job with publish.
    expect(jobBlock(RELEASE, 'publish')).not.toContain('gh-release');
  });
});

// ---------------------------------------------------------------------------
// SLS-06.AC4 — the install-config guard on every npm ci job
// ---------------------------------------------------------------------------

describe('every job that runs npm ci guards against tracked install-config files first', () => {
  const npmCiJobs: Array<[string, string, string]> = [];
  for (const [file, workflow] of [
    ['ci.yml', CI],
    ['release.yml', RELEASE],
  ] as const) {
    for (const jobId of jobIds(workflow)) {
      const job = jobBlock(workflow, jobId);
      if (/npm ci/.test(job)) npmCiJobs.push([file, jobId, job]);
    }
  }

  it('SLS-06.AC4 the npm ci jobs are exactly the ones the guard must cover', () => {
    expect(npmCiJobs.map(([file, jobId]) => `${file}:${jobId}`)).toEqual([
      'ci.yml:gate',
      'ci.yml:build-and-test',
      'release.yml:build',
      'release.yml:review',
    ]);
  });

  it('SLS-06.AC4 each npm ci job runs the exact guard grep before its install step', () => {
    for (const [file, jobId, job] of npmCiJobs) {
      const label = `${file}:${jobId}`;
      const guardIndex = job.indexOf(GUARD_GREP);
      expect(guardIndex, `${label} has no guard step`).toBeGreaterThanOrEqual(0);
      expect(guardIndex, `${label} guards after installing`).toBeLessThan(job.indexOf('npm ci'));
      // The guard fails the job when the grep prints: grep-found enters the
      // `then` branch, and the branch exits 1.
      expect(guardScript(job)).toContain(`if ${GUARD_GREP}; then`);
      expect(guardScript(job)).toContain('exit 1');
    }
  });

  it('SLS-06.AC4 no guard step carries continue-on-error or an if:', () => {
    for (const [file, jobId, job] of npmCiJobs) {
      const guard = stepBlocks(job).find((step) => step.includes(GUARD_GREP));
      expect(guard, `${file}:${jobId} has no guard step`).toBeDefined();
      expect(guard!).not.toContain('continue-on-error');
      expect(guard!).not.toMatch(/^\s+if:/m);
    }
  });

  it('SLS-06.AC4 the release build job installs with npm ci --ignore-scripts', () => {
    expect(jobBlock(RELEASE, 'build')).toContain('- run: npm ci --ignore-scripts');
    expect(jobBlock(RELEASE, 'review')).toContain('- run: npm ci --ignore-scripts');
  });

  it('SLS-06.AC4 on the delivered tree the guard grep prints nothing', () => {
    const run = spawnSync('bash', ['-c', GUARD_GREP], { cwd: REPO_ROOT, encoding: 'utf-8' });
    expect(run.stdout).toBe('');
    // grep exits 1 on no match, which the guard's `if` reads as "clean".
    expect(run.status).toBe(1);
  });

  it('SLS-06.AC4 the committed guard script passes on the delivered tree and fails a tree with one tracked .npmrc', () => {
    const script = guardScript(jobBlock(RELEASE, 'build'));

    // Green: the delivered tree tracks no install-config file.
    const clean = spawnSync('bash', ['-c', script], { cwd: REPO_ROOT, encoding: 'utf-8' });
    expect(clean.status).toBe(0);

    // Red: a scratch repository with one tracked .npmrc. `git ls-files` reads
    // the index, so an added file is enough — no commit required.
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'npmrc-guard-'));
    spawnSync('git', ['init', '--quiet'], { cwd: scratch });
    fs.writeFileSync(path.join(scratch, '.npmrc'), 'registry=https://registry.evil.example/\n');
    fs.writeFileSync(path.join(scratch, 'index.js'), '\n');
    spawnSync('git', ['add', '.npmrc', 'index.js'], { cwd: scratch });

    const dirty = spawnSync('bash', ['-c', script], { cwd: scratch, encoding: 'utf-8' });
    expect(dirty.status).toBe(1);
    expect(dirty.stdout).toContain('.npmrc');

    // A nested one is caught too: the pattern anchors on (^|/).
    spawnSync('git', ['rm', '--cached', '--quiet', '.npmrc'], { cwd: scratch });
    fs.mkdirSync(path.join(scratch, 'packages', 'app'), { recursive: true });
    fs.writeFileSync(path.join(scratch, 'packages', 'app', '.envrc'), 'export X=1\n');
    spawnSync('git', ['add', 'packages/app/.envrc'], { cwd: scratch });
    const nested = spawnSync('bash', ['-c', script], { cwd: scratch, encoding: 'utf-8' });
    expect(nested.status).toBe(1);
    expect(nested.stdout).toContain('packages/app/.envrc');

    fs.rmSync(scratch, { recursive: true, force: true });
  });
});
