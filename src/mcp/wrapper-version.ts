/**
 * The version a `secretless-mcp` wrapper reports.
 *
 * `protect-mcp` copies `dist/` to `~/.secretless-ai/bin` and MCP client configs
 * point at that copy by absolute path. The copy does not update when the
 * package does, so a machine can run an old wrapper against a current package;
 * `secretless-mcp --version` is how that mismatch is read. The copy has no
 * `package.json` above it, so `installWrapper` writes the version beside it
 * (WRAPPER_VERSION_FILE) and the wrapper reads that first. Run from the package
 * itself, the wrapper walks up to the package's own `package.json`.
 *
 * `mcp-wrapper.ts` imports this module, so it stays a leaf: no package-relative
 * require, for the reason set out in `argv.ts`.
 */

import * as fs from 'fs';
import * as path from 'path';

export const WRAPPER_VERSION_FILE = 'wrapper-version.json';
const PACKAGE_NAME = 'secretless-ai';

/** Version of the nearest `secretless-ai` package.json at or above `startDir`, or null. */
export function packageVersionAbove(startDir: string): string | null {
  let dir = path.resolve(startDir);
  const root = path.parse(dir).root;
  for (let depth = 0; dir !== root && depth < 20; depth++) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf-8'));
      if (pkg.name === PACKAGE_NAME && typeof pkg.version === 'string') return pkg.version;
    } catch {
      // No package.json here, or not parseable: keep walking up.
    }
    dir = path.dirname(dir);
  }
  return null;
}

/** Version of the wrapper whose files live in `dir`, or 'unknown' when neither source is present. */
export function readWrapperVersion(dir: string): string {
  try {
    const recorded = JSON.parse(fs.readFileSync(path.join(dir, WRAPPER_VERSION_FILE), 'utf-8'));
    if (typeof recorded.version === 'string' && recorded.version) return recorded.version;
  } catch {
    // Not an installed copy (or the record is unreadable): fall through to the package.
  }
  return packageVersionAbove(dir) ?? 'unknown';
}

/** A semver version: MAJOR.MINOR.PATCH, an optional prerelease, an optional build. */
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/** Whether `version` is a semver version, as a package.json version is; `'unknown'` is not. */
export function isVersion(version: string): boolean {
  return VERSION.test(version);
}

/**
 * The order of two versions by semver precedence: negative when `a` is lower
 * than `b`, 0 when they are equal, positive when it is higher, and undefined
 * when either is not a version. A prerelease is lower than its release, and
 * build metadata is not compared.
 */
export function compareVersions(a: string, b: string): number | undefined {
  const left = VERSION.exec(a);
  const right = VERSION.exec(b);
  if (!left || !right) return undefined;
  for (let i = 1; i <= 3; i++) {
    const diff = Number(left[i]) - Number(right[i]);
    if (diff !== 0) return diff;
  }
  const leftPre = left[4] === undefined ? [] : left[4].split('.');
  const rightPre = right[4] === undefined ? [] : right[4].split('.');
  if (leftPre.length === 0 || rightPre.length === 0) return rightPre.length - leftPre.length;
  for (let i = 0; i < Math.min(leftPre.length, rightPre.length); i++) {
    const x = leftPre[i];
    const y = rightPre[i];
    if (x === y) continue;
    const xNumeric = /^\d+$/.test(x);
    const yNumeric = /^\d+$/.test(y);
    if (xNumeric && yNumeric) return Number(x) - Number(y);
    if (xNumeric !== yNumeric) return xNumeric ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return leftPre.length - rightPre.length;
}

/** Record `version` beside an installed wrapper copy in `binDir`. */
export function writeWrapperVersion(binDir: string, version: string): void {
  fs.writeFileSync(
    path.join(binDir, WRAPPER_VERSION_FILE),
    JSON.stringify({ name: PACKAGE_NAME, version }) + '\n',
    { mode: 0o600 },
  );
}
