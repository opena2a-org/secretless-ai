import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Top-level help opens with a line that says what the tool does. It read "Keep
 * secrets out of AI context." The README's opening paragraph and the package
 * description are narrower: a hook and deny rules enforce the read gate in
 * Claude Code, the other tools get instruction or ignore files that nothing
 * enforces, and a command that prints its own credential is not blocked. A
 * reader of `--help` was told more than the README stands behind.
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
