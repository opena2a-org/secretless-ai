import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * `opena2a secrets` runs the secretless-ai release opena2a-cli depends on, not
 * the one this README describes. The README's "Using with opena2a-cli" section
 * said only "Secretless powers `opena2a secrets`." while opena2a-cli 0.10.13
 * depended on `secretless-ai@^0.14.1`, a release with no `secret push`,
 * `secret sync`, `git-credential` or `telemetry` command, so a reader who ran
 * this README's sections through `opena2a secrets` got an unknown command.
 * The section has to name the range opena2a-cli depends on, the command that
 * prints it, and as missing from that release only commands this CLI has, so
 * that running them through `npx secretless-ai` works.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const README = fs.readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf-8');
const HEADING = '## Using with opena2a-cli';
const CHECK = 'npm view opena2a-cli dependencies.secretless-ai';

/** The section's prose, fenced code blocks dropped. */
function sectionProse(): string {
  const start = README.indexOf(`\n${HEADING}\n`);
  expect(start, `README.md must hold a "${HEADING}" section`).toBeGreaterThan(-1);
  const rest = README.slice(start + HEADING.length + 2);
  const end = rest.search(/^## /m);
  return (end === -1 ? rest : rest.slice(0, end)).replace(/^\s*```[\s\S]*?^\s*```\s*$/gm, '');
}

/** Commands `cli.ts` dispatches, read the way docs-commands.test.ts reads them. */
function dispatchedCommands(): Set<string> {
  const cli = fs.readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf-8');
  const commands = new Set<string>();
  for (const m of cli.matchAll(/^\s*case '([a-z][a-z-]*)':/gm)) commands.add(m[1]);
  for (const m of cli.matchAll(/command === '([a-z][a-z-]*)'/g)) commands.add(m[1]);
  return commands;
}

/** Subcommands a command module dispatches (`secret push` is `case 'push':` in src/commands). */
function dispatchedSubcommands(): Set<string> {
  const dir = path.join(REPO_ROOT, 'src', 'commands');
  const subs = new Set<string>();
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.ts') || name.endsWith('.test.ts')) continue;
    const src = fs.readFileSync(path.join(dir, name), 'utf-8');
    for (const m of src.matchAll(/^\s*case '([a-z][a-z-]*)':/gm)) subs.add(m[1]);
  }
  return subs;
}

describe('README: the secretless-ai release opena2a secrets runs', () => {
  it('names the secretless-ai range opena2a-cli depends on and the opena2a-cli version it was read from', () => {
    const prose = sectionProse();
    expect(
      prose,
      `${HEADING} must say which secretless-ai release \`opena2a secrets\` runs, as ` +
        '"opena2a-cli <version> depends on `secretless-ai@<range>`"',
    ).toMatch(/opena2a-cli \d+\.\d+\.\d+ depends on `secretless-ai@\^?\d+\.\d+\.\d+`/);
  });

  it('gives the command that prints the range the latest opena2a-cli depends on', () => {
    expect(sectionProse()).toContain(`\`${CHECK}\``);
  });

  it('names as missing from that release only commands this CLI dispatches', () => {
    const prose = sectionProse();
    const sentence = prose.match(/has no ((?:`[^`]+`(?:, | or )?)+) command/);
    expect(sentence, `${HEADING} must name the commands the embedded release lacks, as "has no \`a\`, \`b\` or \`c\` command"`).not.toBeNull();
    const named = [...sentence![1].matchAll(/`([^`]+)`/g)].map(m => m[1]);
    expect(named.length).toBeGreaterThan(0);

    const commands = dispatchedCommands();
    const subs = dispatchedSubcommands();
    const unknown = named.filter(span => {
      const [verb, sub, ...more] = span.split(/\s+/);
      if (more.length > 0 || !commands.has(verb)) return true;
      return sub !== undefined && !subs.has(sub);
    });
    expect(unknown, 'README names these as commands to run through `npx secretless-ai`, and this CLI does not dispatch them').toEqual([]);
  });
});
