import * as fs from 'fs';
import * as path from 'path';

/**
 * Reading a recording's tape: which tapes the repository carries and what each
 * one types where a viewer can see it. Shared by the test that checks those
 * commands against the CLI and the test that checks them against the sidecar,
 * so the two cannot come to read a tape differently.
 */

export const REPO_ROOT = path.resolve(__dirname, '..');

/** Every tape under docs/, as paths relative to the repository root. */
export function tapeFiles(): string[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(path.join(REPO_ROOT, dir), { withFileTypes: true })) {
      const relative = path.posix.join(dir, entry.name);
      if (entry.isDirectory()) walk(relative);
      else if (entry.name.endsWith('.tape')) files.push(relative);
    }
  };
  walk('docs');
  return files.sort();
}

/**
 * The lines a tape types on screen, in order: the text of each `Type` line
 * outside a `Hide`..`Show` block. A hidden block is setup the viewer never
 * sees (entering the fixture, clearing the screen), so it is not a command the
 * recording shows anyone.
 */
export function typedCommands(tape: string): string[] {
  const typed: string[] = [];
  let hidden = false;
  for (const line of tape.split('\n')) {
    if (/^Hide\b/.test(line)) hidden = true;
    else if (/^Show\b/.test(line)) hidden = false;
    else if (!hidden) {
      const m = line.match(/^Type(?:@\S+)?\s+(["'`])(.*)\1\s*$/);
      if (m) typed.push(m[2]);
    }
  }
  return typed;
}

/** The programs a tape declares with `Require`, which VHS checks before it records. */
export function requiredPrograms(tape: string): string[] {
  return [...tape.matchAll(/^Require\s+(\S+)\s*$/gm)].map(m => m[1]);
}
