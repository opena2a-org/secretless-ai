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

/** Record `version` beside an installed wrapper copy in `binDir`. */
export function writeWrapperVersion(binDir: string, version: string): void {
  fs.writeFileSync(
    path.join(binDir, WRAPPER_VERSION_FILE),
    JSON.stringify({ name: PACKAGE_NAME, version }) + '\n',
    { mode: 0o600 },
  );
}
