/**
 * Lockstep equivalence test: local src/patterns.ts must match
 * @opena2a/credential-patterns byte-for-byte.
 *
 * The package was published in PR 1 by relocating this file. As long as
 * secretless-ai keeps a local CommonJS-compatible copy (the public
 * `import { CREDENTIAL_PATTERNS } from 'secretless-ai'` API depends on it),
 * any drift between the two catalogs is a bug. This test fires on:
 *  - new patterns added on one side only
 *  - regex source/flags changed on one side only
 *  - allowlist (KNOWN_EXAMPLE_KEYS / PLACEHOLDER_INDICATORS) drift
 *  - SECRET_FILE_PATTERNS / CONFIG_FILES / SOURCE_FILE_EXTENSIONS / SOURCE_SKIP_DIRS drift
 *  - findRealMatch / isKnownExample behavioral drift on oracle inputs
 *
 * When the package version bumps, intentional changes land here first
 * (re-sync src/patterns.ts), then the package version pin in package.json
 * is bumped. A failing test means: do not ship until the catalogs match.
 */
import { describe, it, expect } from 'vitest';

import {
  CREDENTIAL_PATTERNS as LOCAL_PATTERNS,
  CREDENTIAL_PREFIX_QUICK_CHECK as LOCAL_QUICK_CHECK,
  KNOWN_EXAMPLE_KEYS as LOCAL_EXAMPLES,
  PLACEHOLDER_INDICATORS as LOCAL_PLACEHOLDERS,
  SECRET_FILE_PATTERNS as LOCAL_SECRET_FILES,
  CONFIG_FILES as LOCAL_CONFIG_FILES,
  SOURCE_FILE_EXTENSIONS as LOCAL_SOURCE_EXTS,
  SOURCE_SKIP_DIRS as LOCAL_SKIP_DIRS,
} from './patterns';
import { findRealMatch as localFindRealMatch, isKnownExample as localIsKnownExample } from './scan';

type PkgModule = typeof import('@opena2a/credential-patterns');

let pkgPromise: Promise<PkgModule> | null = null;
function loadPkg(): Promise<PkgModule> {
  if (!pkgPromise) pkgPromise = import('@opena2a/credential-patterns');
  return pkgPromise;
}

describe('lockstep: local src/patterns.ts === @opena2a/credential-patterns', () => {
  it('CREDENTIAL_PATTERNS arrays have identical length', async () => {
    const pkg = await loadPkg();
    expect(LOCAL_PATTERNS.length).toBe(pkg.CREDENTIAL_PATTERNS.length);
  });

  it('CREDENTIAL_PATTERNS entries match by index (id, name, regex.source, regex.flags, envPrefix, category)', async () => {
    const pkg = await loadPkg();
    const len = Math.max(LOCAL_PATTERNS.length, pkg.CREDENTIAL_PATTERNS.length);
    const drift: string[] = [];
    for (let i = 0; i < len; i++) {
      const local = LOCAL_PATTERNS[i];
      const remote = pkg.CREDENTIAL_PATTERNS[i];
      if (!local || !remote) {
        drift.push(`index ${i}: missing on ${local ? 'package' : 'local'} side`);
        continue;
      }
      if (local.id !== remote.id) drift.push(`index ${i}: id local=${local.id} pkg=${remote.id}`);
      if (local.name !== remote.name) drift.push(`index ${i} (${local.id}): name local=${local.name} pkg=${remote.name}`);
      if (local.regex.source !== remote.regex.source) drift.push(`index ${i} (${local.id}): regex.source local=${local.regex.source} pkg=${remote.regex.source}`);
      if (local.regex.flags !== remote.regex.flags) drift.push(`index ${i} (${local.id}): regex.flags local=${local.regex.flags} pkg=${remote.regex.flags}`);
      if (local.envPrefix !== remote.envPrefix) drift.push(`index ${i} (${local.id}): envPrefix local=${local.envPrefix} pkg=${remote.envPrefix}`);
      if (local.category !== remote.category) drift.push(`index ${i} (${local.id}): category local=${local.category} pkg=${remote.category}`);
    }
    expect(drift, drift.join('\n')).toEqual([]);
  });

  it('CREDENTIAL_PREFIX_QUICK_CHECK source + flags match', async () => {
    const pkg = await loadPkg();
    expect(LOCAL_QUICK_CHECK.source).toBe(pkg.CREDENTIAL_PREFIX_QUICK_CHECK.source);
    expect(LOCAL_QUICK_CHECK.flags).toBe(pkg.CREDENTIAL_PREFIX_QUICK_CHECK.flags);
  });

  it('KNOWN_EXAMPLE_KEYS sets contain identical members', async () => {
    const pkg = await loadPkg();
    const localList = [...LOCAL_EXAMPLES].sort();
    const pkgList = [...pkg.KNOWN_EXAMPLE_KEYS].sort();
    expect(localList).toEqual(pkgList);
  });

  it('PLACEHOLDER_INDICATORS arrays match (order-sensitive)', async () => {
    const pkg = await loadPkg();
    expect(LOCAL_PLACEHOLDERS).toEqual(pkg.PLACEHOLDER_INDICATORS);
  });

  it('SECRET_FILE_PATTERNS arrays match (order-sensitive)', async () => {
    const pkg = await loadPkg();
    expect(LOCAL_SECRET_FILES).toEqual(pkg.SECRET_FILE_PATTERNS);
  });

  it('CONFIG_FILES arrays match (order-sensitive)', async () => {
    const pkg = await loadPkg();
    expect(LOCAL_CONFIG_FILES).toEqual(pkg.CONFIG_FILES);
  });

  it('SOURCE_FILE_EXTENSIONS sets contain identical members', async () => {
    const pkg = await loadPkg();
    const localList = [...LOCAL_SOURCE_EXTS].sort();
    const pkgList = [...pkg.SOURCE_FILE_EXTENSIONS].sort();
    expect(localList).toEqual(pkgList);
  });

  it('SOURCE_SKIP_DIRS sets contain identical members', async () => {
    const pkg = await loadPkg();
    const localList = [...LOCAL_SKIP_DIRS].sort();
    const pkgList = [...pkg.SOURCE_SKIP_DIRS].sort();
    expect(localList).toEqual(pkgList);
  });
});

describe('lockstep: isKnownExample / findRealMatch parity on oracle inputs', () => {
  // Each row covers a real allowlist branch in isKnownExample. A behavior
  // change in either implementation flips one of these.
  const ORACLE_LINES: string[] = [
    'const k = "AKIAIOSFODNN7EXAMPLE"',                 // KNOWN_EXAMPLE_KEYS hit
    'const k = "AKIAREALKEY1234567890"',                // real-looking AWS key, no allowlist marker
    '# TODO: rotate AKIAREALKEY1234567890 next sprint', // issue #50: TODO is a placeholder substring -> example
    'const k = "your_api_key_here"',                    // PLACEHOLDER_INDICATORS hit
    '// example: AKIAREALKEY1234567890',                // comment-marker example branch
    'const real = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"', // real-looking GitHub PAT
    'old="AKIAIOSFODNN7EXAMPLE"; new_="ghp_abcdefghijklmnopqrstuvwxyz1234567890"', // issue #51 shadowing
    'plain text with no credential',                    // no match at all
  ];

  it('isKnownExample returns identical results across local vs package on every oracle line × every regex match', async () => {
    const pkg = await loadPkg();
    const drift: string[] = [];
    for (const line of ORACLE_LINES) {
      for (const pattern of LOCAL_PATTERNS) {
        const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags + (pattern.regex.flags.includes('g') ? '' : 'g'));
        for (const m of line.matchAll(globalRegex)) {
          const local = localIsKnownExample(line, m);
          const remote = pkg.isKnownExample(line, m);
          if (local !== remote) {
            drift.push(`pattern=${pattern.id} match=${m[0]} line=${JSON.stringify(line)} local=${local} pkg=${remote}`);
          }
        }
      }
    }
    expect(drift, drift.join('\n')).toEqual([]);
  });

  it('findRealMatch returns identical results across local vs package on every oracle line × every pattern', async () => {
    const pkg = await loadPkg();
    const drift: string[] = [];
    for (const line of ORACLE_LINES) {
      for (const pattern of LOCAL_PATTERNS) {
        const localResult = localFindRealMatch(line, pattern);
        const remoteResult = pkg.findRealMatch(line, pattern);
        const localStr = localResult ? localResult[0] : null;
        const remoteStr = remoteResult ? remoteResult[0] : null;
        if (localStr !== remoteStr) {
          drift.push(`pattern=${pattern.id} line=${JSON.stringify(line)} local=${localStr} pkg=${remoteStr}`);
        }
      }
    }
    expect(drift, drift.join('\n')).toEqual([]);
  });

  it('PR 1 contract: AWS allowlist still catches AKIAIOSFODNN7EXAMPLE in package', async () => {
    const pkg = await loadPkg();
    expect(pkg.KNOWN_EXAMPLE_KEYS.has('AKIAIOSFODNN7EXAMPLE')).toBe(true);
    expect(pkg.KNOWN_EXAMPLE_KEYS.has('AKIAI44QH8DHBEXAMPLE')).toBe(true);
  });

  it('PR 1 contract: findRealMatch on AWS-example + real-PAT line returns the PAT, not null (issue #51)', async () => {
    const pkg = await loadPkg();
    const line = 'const old = "AKIAIOSFODNN7EXAMPLE"; const new_ = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";';
    const ghPattern = pkg.CREDENTIAL_PATTERNS.find((p: import('@opena2a/credential-patterns').CredentialPattern) => p.id === 'github-pat')!;
    const m = pkg.findRealMatch(line, ghPattern);
    expect(m).not.toBeNull();
    expect(m![0]).toBe('ghp_abcdefghijklmnopqrstuvwxyz1234567890');
  });
});
