import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Top-level help opens with a line that says what the tool does. It read "Keep
 * secrets out of AI context." The README's opening paragraph and the package
 * description are narrower: they say what Secretless sets up, and that a hook
 * and deny rules enforce the read gate in Claude Code. A reader of `--help` was
 * told more than the README stands behind.
 *
 * Help now prints the package description, which src/package-description.test.ts
 * holds to the README. These tests hold help to it: the same sentences in the
 * same order, standalone and under a host CLI, inside an 80-column terminal.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const PACKAGE: { description: string; version: string } = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8'),
);

const TERMINAL_COLUMNS = 80;

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.resetModules();
});

/** What top-level help prints, standalone or under a host CLI that sets `prefix`. */
async function helpText(prefix?: string): Promise<string> {
  if (prefix !== undefined) vi.stubEnv('SECRETLESS_CLI_PREFIX', prefix);
  // The prefix is read once, when the module loads.
  vi.resetModules();
  const { printHelp } = await import('./commands/help.js');
  const printed: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    printed.push(args.join(' '));
  });
  printHelp();
  return printed.join('\n');
}

/** The lines above the first help section that are not the name and release line. */
function openingLines(help: string): string[] {
  const lines = help.split('\n');
  const firstSection = lines.findIndex((l) => /^ {2}Quick start:$/.test(l));
  expect(firstSection, 'help no longer has a "Quick start:" section to read the opening above').toBeGreaterThan(0);
  return lines
    .slice(0, firstSection)
    .filter((l) => l.trim() !== '' && l !== `  Secretless v${PACKAGE.version}`);
}

const asOneLine = (lines: string[]): string => lines.map((l) => l.trim()).join(' ');

describe('top-level help opening', () => {
  it('is the package description, sentence for sentence', async () => {
    expect(
      asOneLine(openingLines(await helpText())),
      'top-level help must open with the `description` in package.json, so `--help` claims no ' +
        'more than the README and the registry listing do',
    ).toBe(PACKAGE.description);
  });

  it('is the same description under a host CLI, without the name and release line', async () => {
    const help = await helpText('opena2a secrets');
    expect(help).not.toMatch(/Secretless v/);
    expect(asOneLine(openingLines(help))).toBe(PACKAGE.description);
  });

  it('keeps the name and release line first when run standalone', async () => {
    const printed = (await helpText()).split('\n').filter((l) => l.trim() !== '');
    expect(printed[0]).toBe(`  Secretless v${PACKAGE.version}`);
  });

  it('carries no wording that every tool or every path is covered', async () => {
    const opening = asOneLine(openingLines(await helpText()));
    for (const absolute of [/\bany AI\b/i, /\bout of AI\b/i, /\binvisible\b/i, /\bnever\b/i, /\ball AI\b/i]) {
      expect(opening, `the help opening matches ${absolute}`).not.toMatch(absolute);
    }
  });

  it(`fits a ${TERMINAL_COLUMNS}-column terminal, indented like the rest of help`, async () => {
    const lines = openingLines(await helpText());
    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines) {
      expect(line.length, `"${line}" is wider than ${TERMINAL_COLUMNS} columns`).toBeLessThanOrEqual(TERMINAL_COLUMNS);
      expect(line, `"${line}" is not indented two spaces`).toMatch(/^ {2}\S/);
    }
  });
});

/**
 * The comment above the line of src/commands/help.ts that wraps the
 * description for help says what the description states. It still said the
 * description states "what is not blocked" after that limit had moved from the
 * description to the README's "What it does not cover" section (#496). Each
 * entry pairs a thing the comment can say the description states with the
 * description text that bears it out. The comment has to say at least one of
 * them, and the description has to bear out each one it says.
 */
const HELP_SOURCE = path.join(REPO_ROOT, 'src', 'commands', 'help.ts');
const DESCRIPTION_LINE = /\bwrapList\(DESCRIPTION\b/;

interface DescriptionClaim {
  /** What the comment says the description states. */
  name: string;
  said: RegExp;
  bornOutBy: RegExp;
}

const SETS_UP = 'what Secretless sets up';
const ENFORCED = 'where the read gate is enforced';
const LIMITS = 'what is not blocked, covered or enforced';

const DESCRIPTION_CLAIMS: readonly DescriptionClaim[] = [
  { name: SETS_UP, said: /\bwhat Secretless sets up\b/, bornOutBy: /\bsets up\b/ },
  {
    name: ENFORCED,
    said: /\bwhere the read gate is enforced\b/,
    bornOutBy: /\bIn Claude Code a hook and deny rules enforce\b/,
  },
  {
    name: LIMITS,
    said: /\bnot (blocked|covered|enforced)\b|\bdoes not (block|cover|enforce)\b|\bnothing enforces\b/,
    bornOutBy: /\bnot blocked\b|\bnothing enforces\b/,
  },
];

/** The `//` lines directly above the first line of `source` that matches `line`, as one line of text. */
function commentAbove(source: string, line: RegExp): string {
  const lines = source.split('\n');
  const at = lines.findIndex((l) => line.test(l));
  if (at === -1) return '';
  let start = at;
  while (start > 0 && /^\s*\/\//.test(lines[start - 1])) start--;
  return lines
    .slice(start, at)
    .map((l) => l.replace(/^\s*\/\/\s?/, '').trim())
    .join(' ');
}

function claimsSaid(comment: string): DescriptionClaim[] {
  return DESCRIPTION_CLAIMS.filter(({ said }) => said.test(comment));
}

/** What `comment` says `description` states that `description` does not bear out. */
function claimsNotBorneOut(comment: string, description: string): string[] {
  return claimsSaid(comment)
    .filter(({ bornOutBy }) => !bornOutBy.test(description))
    .map(({ name }) => name);
}

describe('the comment above the description in src/commands/help.ts', () => {
  const comment = commentAbove(fs.readFileSync(HELP_SOURCE, 'utf-8'), DESCRIPTION_LINE);

  it('says at least one thing DESCRIPTION_CLAIMS knows, and package.json `description` bears out each one it says', () => {
    expect(comment, `src/commands/help.ts has no comment above the line matching ${DESCRIPTION_LINE}`).not.toBe('');
    expect(
      claimsSaid(comment).length,
      `"${comment}" says nothing DESCRIPTION_CLAIMS pairs with description text; add what it says the description states`,
    ).toBeGreaterThan(0);
    expect(
      claimsNotBorneOut(comment, PACKAGE.description),
      `"${comment}" says the description states something package.json \`description\` does not`,
    ).toEqual([]);
  });
});

describe('checking what a comment says the description states', () => {
  const LIMITS_COMMENT =
    'The package description, not a line written here: it says where the read gate is enforced ' +
    'and what is not blocked, and a test holds it to the README.';
  const WITH_LIMITS =
    'Example sets up AI coding tools not to read credential files. In Claude Code a hook and deny ' +
    'rules enforce that. A command that prints its own credential is not blocked.';
  const WITHOUT_LIMITS =
    'Example sets up Claude Code and Aider not to read credential files. In Claude Code a hook and ' +
    'deny rules enforce that.';

  it('reads the comment lines directly above the line as one line, stopping at the first line that is not a comment', () => {
    const source = [
      '// Not this one.',
      'const banner = "";',
      '  // The first line',
      '  //   and the second.',
      "  const description = wrapList(DESCRIPTION.trim().split(/\\s+/), '  ').join('\\n');",
    ].join('\n');
    expect(commentAbove(source, DESCRIPTION_LINE)).toBe('The first line and the second.');
  });

  it('reads nothing where the line has no comment above it or is not in the source', () => {
    expect(commentAbove('const description = wrapList(DESCRIPTION, "  ");', DESCRIPTION_LINE)).toBe('');
    expect(commentAbove('// A comment.\nconst banner = "";', DESCRIPTION_LINE)).toBe('');
  });

  it('flags a comment that says the description states what is not blocked where it states no limit', () => {
    expect(claimsNotBorneOut(LIMITS_COMMENT, WITHOUT_LIMITS)).toEqual([LIMITS]);
    expect(claimsNotBorneOut(LIMITS_COMMENT, WITH_LIMITS)).toEqual([]);
  });

  it('flags a comment that says the description states where the read gate is enforced where it does not', () => {
    expect(claimsNotBorneOut(LIMITS_COMMENT, 'Example sets up AI coding tools not to read credential files.')).toEqual([
      ENFORCED,
      LIMITS,
    ]);
  });

  it('passes a comment naming what Secretless sets up and where the read gate is enforced where the description states both', () => {
    const comment =
      'The package description, not a line written here: it names what Secretless sets up and where ' +
      'the read gate is enforced. A test holds it to the README.';
    expect(claimsSaid(comment).map(({ name }) => name)).toEqual([SETS_UP, ENFORCED]);
    expect(claimsNotBorneOut(comment, WITHOUT_LIMITS)).toEqual([]);
    expect(claimsNotBorneOut(comment, 'Example stores API keys outside your project files.')).toEqual([SETS_UP, ENFORCED]);
  });

  it('finds nothing said in a comment that names none of the entries', () => {
    expect(claimsSaid('The package description, not a line written here.')).toEqual([]);
  });
});

describe('wrapList', () => {
  it('breaks between words, keeps their order and stays inside the width', async () => {
    const { wrapList, NOTE_WIDTH } = await import('./commands/utils.js');
    const words = Array.from({ length: 60 }, (_, i) => `word${i}`);
    const lines = wrapList(words, '  ');
    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(NOTE_WIDTH);
      expect(line.startsWith('  ')).toBe(true);
    }
    expect(lines.map((l: string) => l.trim()).join(' ')).toBe(words.join(' '));
  });

  it('gives a word wider than the limit a line of its own rather than splitting it', async () => {
    const { wrapList, NOTE_WIDTH } = await import('./commands/utils.js');
    const wide = 'x'.repeat(NOTE_WIDTH + 5);
    expect(wrapList(['a', wide, 'b'], '  ')).toEqual(['  a', `  ${wide}`, '  b']);
  });

  it('returns no line for no words', async () => {
    const { wrapList } = await import('./commands/utils.js');
    expect(wrapList([], '  ')).toEqual([]);
    expect(wrapList([''], '  ')).toEqual([]);
  });
});
