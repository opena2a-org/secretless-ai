/**
 * The command a line tells its reader to run, where the line promises what
 * this build does: the wrapper's refusals and the lines `protect-mcp` and
 * `mcp-status` print. The command names this build, in the first form that
 * applies:
 *
 * 1. Its node binary and its CLI script, `cli.js` beside this module, as two
 *    quoted absolute paths, the form the shell hook uses, when that script is
 *    this package's CLI. Run from any directory, the line starts this copy
 *    and consults no project tree. The quotes are a POSIX shell's, so on
 *    `win32` the line takes the next form that applies.
 * 2. Its exact version for npx, which starts a copy only when its package id
 *    is that version. Without a version, npx starts the first copy npm finds
 *    (the project's node_modules/.bin, npm's global bin, then any version in
 *    the project or the global tree), which may be an earlier build that does
 *    none of what the line says.
 * 3. The unversioned form, when the version is not an exact one, as for a
 *    wrapper copy that records none.
 *
 * Unlike a hook prefix (hook-prefix.ts), a copy in the npx cache is named by
 * its path: a printed line is run while that copy is there, and a wrapper
 * started from the cache already depends on the same directory.
 *
 * The wrapper loads this module from the copy of `dist/` that protect-mcp
 * installed before, which has no package.json above it, so it stays a leaf:
 * no package-relative require (see `argv.ts`), and the version is the
 * caller's (`VERSION` in the CLI, `readWrapperVersion` in the wrapper).
 */

import * as fs from 'fs';
import * as path from 'path';
import { shellHookCommand, shellQuote } from './env';

export interface PrintedCommandOptions {
  /** The node binary; defaults to the one running. */
  execPath?: string;
  pathEnv?: string;
  /** The CLI script; defaults to `cli.js` beside this module. */
  script?: string;
  /** The platform whose terminal reads the line; defaults to the one running. */
  platform?: NodeJS.Platform;
}

/** A path that a shell line or a git config value carries unchanged. */
export function writablePath(p: string): boolean {
  return path.isAbsolute(p) && !/[\x00-\x1f\x7f]/.test(p);
}

export function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/** True when `script` is this package's CLI: a file whose package.json names `secretless-ai`. */
export function isOwnCli(script: string): boolean {
  if (!isFile(script)) return false;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(path.dirname(script), '..', 'package.json'), 'utf-8'));
    return pkg?.name === 'secretless-ai';
  } catch {
    return false;
  }
}

/**
 * Whether `version` names one exact release, the only version a shell line
 * carries: a range, a tag or anything else does not.
 */
export function isExactVersion(version: string): boolean {
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version);
}

/** `command` as a line names it for this build, whose version is `version`. */
export function printedCommand(command: string, version: string, options: PrintedCommandOptions = {}): string {
  const [node, script] = shellHookCommand(
    options.execPath ?? process.execPath,
    options.pathEnv ?? process.env.PATH ?? '',
    options.script ?? path.join(__dirname, 'cli.js'),
  );
  const posixShell = (options.platform ?? process.platform) !== 'win32';
  if (posixShell && writablePath(node) && writablePath(script) && isOwnCli(script)) {
    return `${shellQuote(node)} ${shellQuote(script)} ${command}`;
  }
  if (isExactVersion(version)) return `npx secretless-ai@${version} ${command}`;
  return `npx secretless-ai ${command}`;
}
