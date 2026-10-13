import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { prepareArgv } from './argv';
import { REPO_ROOT, tapeFiles, typedCommands, requiredPrograms } from './tape.test-support';

/**
 * A recording shows a command and what it prints, and a viewer types what they
 * saw. So every line a tape types on screen has to be a command this CLI runs:
 * a verb it dispatches, flags that verb registers, and nothing else on the
 * line. `docs-commands.test.ts` holds the Markdown to that; a tape is not
 * Markdown, and the tape this replaced was last edited six months after its
 * recording was last rendered, with nothing comparing the two.
 *
 * The check is the parser the CLI itself runs first (`prepareArgv`), so a flag
 * added to or dropped from a verb changes the answer here without an edit.
 */

/** Commands the CLI dispatches, read from `cli.ts` the way `docs-commands.test.ts` reads them. */
function dispatchedCommands(): Set<string> {
  const cli = fs.readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf-8');
  const commands = new Set<string>();
  for (const m of cli.matchAll(/^\s*case '([a-z][a-z-]*)':/gm)) commands.add(m[1]);
  for (const m of cli.matchAll(/command === '([a-z][a-z-]*)'/g)) commands.add(m[1]);
  return commands;
}

const commands = dispatchedCommands();

/** Why the CLI would not run a typed line as it stands, or null when it would. */
function refusal(typed: string): string | null {
  // A pipe, a redirect, a second command or a substitution is the shell's work.
  // The viewer would be shown something the command alone does not print.
  if (/[|;&<>`$\\]/.test(typed)) return 'is more than the command alone';
  const tokens = typed.trim().split(/\s+/);
  if (tokens[0] === 'npx') tokens.shift();
  if (tokens.shift() !== 'secretless-ai') return 'is not a secretless-ai command';
  const verb = tokens[0];
  if (!verb || !commands.has(verb)) return 'names no command the CLI dispatches';
  const { errors, warnings } = prepareArgv(verb, tokens);
  return errors.length + warnings.length > 0 ? [...errors, ...warnings].join(' ') : null;
}

describe('commands a recording types on screen', () => {
  const tapes = tapeFiles();

  it('finds tapes to check, and a command list to check them against', () => {
    // An empty list of either would make every assertion below pass over nothing.
    expect(tapes.length).toBeGreaterThan(0);
    expect(commands.size).toBeGreaterThan(20);
    expect(commands.has('init')).toBe(true);
  });

  it('reads what a tape types on screen and leaves out its hidden setup', () => {
    const tape = [
      'Require npx',
      'Hide',
      'Type "cd /work/project && clear"',
      'Enter',
      'Show',
      'Type "npx secretless-ai init"',
      'Enter',
      "Type@80ms 'npx secretless-ai verify --all'",
      'Sleep 2s',
    ].join('\n');
    expect(typedCommands(tape)).toEqual(['npx secretless-ai init', 'npx secretless-ai verify --all']);
    expect(requiredPrograms(tape)).toEqual(['npx']);
  });

  it('refuses a flag the verb does not register, a verb the CLI does not dispatch, and anything beside the command', () => {
    // Pinned in both directions before the real tapes are read: a check that
    // cannot fire says nothing when it is green.
    expect(refusal('npx secretless-ai init')).toBeNull();
    expect(refusal('secretless-ai verify --all')).toBeNull();

    expect(refusal('npx secretless-ai init --no-such-flag')).toContain('--no-such-flag');
    expect(refusal('npx secretless-ai no-such-command')).toBe('names no command the CLI dispatches');
    expect(refusal('npx secretless-ai')).toBe('names no command the CLI dispatches');
    expect(refusal('npx secretless-ai scan | head')).toBe('is more than the command alone');
    expect(refusal('npx secretless-ai init && npx secretless-ai verify')).toBe('is more than the command alone');
    expect(refusal('echo done')).toBe('is not a secretless-ai command');
  });

  it('every tape types at least one command on screen', () => {
    const silent = tapes.filter(tape => typedCommands(fs.readFileSync(path.join(REPO_ROOT, tape), 'utf-8')).length === 0);
    expect(silent).toEqual([]);
  });

  it('only types commands the CLI runs as typed', () => {
    const offenders: string[] = [];
    for (const tape of tapes) {
      for (const typed of typedCommands(fs.readFileSync(path.join(REPO_ROOT, tape), 'utf-8'))) {
        const why = refusal(typed);
        if (why) offenders.push(`${tape}: ${typed} (${why})`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('declares the programs it types with Require, so a render without one stops before it records', () => {
    const offenders: string[] = [];
    for (const tape of tapes) {
      const text = fs.readFileSync(path.join(REPO_ROOT, tape), 'utf-8');
      const required = requiredPrograms(text);
      for (const typed of typedCommands(text)) {
        const tokens = typed.trim().split(/\s+/);
        const programs = tokens[0] === 'npx' ? tokens.slice(0, 2) : tokens.slice(0, 1);
        for (const program of programs) {
          if (!required.includes(program)) offenders.push(`${tape}: ${typed} (no Require ${program})`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
