/**
 * The command prefix written into a hook or helper that a later process runs:
 * the git pre-commit hook, the Claude Code Stop hook and the git credential
 * helper.
 *
 * The prefix names the copy that wrote it, so the hook runs that code from
 * whatever directory git or Claude Code starts it in: the node binary and this
 * package's CLI script as absolute paths, the form the shell hook uses (#333).
 * When those paths cannot be resolved, it names the running version exactly
 * and keeps npx on the local npm cache. It is never a bare `npx secretless-ai`.
 */

import * as fs from 'fs';
import * as path from 'path';
import { shellHookCommand, shellQuote } from './env';
import { VERSION } from './commands/utils';

export interface HookPrefixOptions {
  /** The node binary; defaults to the one running. */
  execPath?: string;
  pathEnv?: string;
  /** The CLI script; defaults to `cli.js` beside this module. */
  script?: string;
  /** The version the npx form pins; defaults to this package's. */
  version?: string;
}

/** A path that a shell line or a git config value carries unchanged. */
function writablePath(p: string): boolean {
  return path.isAbsolute(p) && !/[\x00-\x1f\x7f]/.test(p);
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/** True when `script` is this package's CLI: a file whose package.json names `secretless-ai`. */
function isOwnCli(script: string): boolean {
  if (!isFile(script)) return false;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(path.dirname(script), '..', 'package.json'), 'utf-8'));
    return pkg?.name === 'secretless-ai';
  } catch {
    return false;
  }
}

/**
 * The version goes into a shell line, so only one exact release is accepted;
 * a range, a tag or anything else is refused rather than quoted.
 */
function exactVersion(version: string): string {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`Refusing to write "${version}" into a hook: not an exact version.`);
  }
  return version;
}

export function commandPrefixForHooks(options: HookPrefixOptions = {}): string {
  const execPath = options.execPath ?? process.execPath;
  const pathEnv = options.pathEnv ?? process.env.PATH ?? '';
  const script = options.script ?? path.join(__dirname, 'cli.js');
  if (writablePath(script) && writablePath(execPath) && isFile(execPath) && isOwnCli(script)) {
    const command = shellHookCommand(execPath, pathEnv, script);
    if (command.every(writablePath)) return command.map(shellQuote).join(' ');
  }
  return `npm_config_offline=true npx --yes secretless-ai@${exactVersion(options.version ?? VERSION)}`;
}
