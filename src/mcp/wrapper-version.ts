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

/**
 * The most bytes of a version file read (WRAPPER_VERSION_FILE, or a
 * package.json at or above a wrapper's directory). protect-mcp and mcp-status
 * read these beside the wrapper a config's command names, so a larger file,
 * and one that is not a regular file, is not read and gives no version. The
 * same bound as BINDING_COPY_READ_LIMIT (discover.ts), which this module does
 * not import.
 */
export const VERSION_FILE_READ_LIMIT = 1024 * 1024;

/**
 * The text of a regular file of at most VERSION_FILE_READ_LIMIT bytes, or
 * undefined when it is missing, not a regular file, larger, or unreadable.
 * The file is opened without blocking and checked again once open, so a file
 * swapped for a FIFO after the first check does not hang the read.
 */
function readVersionFile(file: string): string | undefined {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > VERSION_FILE_READ_LIMIT) return undefined;
  } catch {
    return undefined;
  }
  let fd: number;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  } catch {
    return undefined;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > VERSION_FILE_READ_LIMIT) return undefined;
    const chunks: Buffer[] = [];
    const chunk = Buffer.alloc(64 * 1024);
    let total = 0;
    for (;;) {
      const read = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (read === 0) return Buffer.concat(chunks, total).toString('utf-8');
      total += read;
      // It grew after the check: no version from it.
      if (total > VERSION_FILE_READ_LIMIT) return undefined;
      chunks.push(Buffer.from(chunk.subarray(0, read)));
    }
  } catch {
    return undefined;
  } finally {
    fs.closeSync(fd);
  }
}

/** Version of the nearest `secretless-ai` package.json at or above `startDir`, or null. */
export function packageVersionAbove(startDir: string): string | null {
  let dir = path.resolve(startDir);
  const root = path.parse(dir).root;
  for (let depth = 0; dir !== root && depth < 20; depth++) {
    try {
      const text = readVersionFile(path.join(dir, 'package.json'));
      const pkg = text === undefined ? undefined : JSON.parse(text);
      if (pkg?.name === PACKAGE_NAME && typeof pkg.version === 'string') return pkg.version;
    } catch {
      // Not parseable: keep walking up, as for no package.json here.
    }
    dir = path.dirname(dir);
  }
  return null;
}

/** Version of the wrapper whose files live in `dir`, or 'unknown' when neither source is present. */
export function readWrapperVersion(dir: string): string {
  try {
    const text = readVersionFile(path.join(dir, WRAPPER_VERSION_FILE));
    const recorded = text === undefined ? undefined : JSON.parse(text);
    if (typeof recorded?.version === 'string' && recorded.version) return recorded.version;
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
