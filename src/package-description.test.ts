import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * The package description is the line `npm search`, `npm view` and the
 * registry listing show beside the name, before a reader opens the README. It
 * read "One command to keep secrets out of AI. Works with Claude Code, Cursor,
 * Copilot, Windsurf, and any AI coding tool." A hook and deny rules enforce the
 * read gate in Claude Code alone, so a reader who chose the package from the
 * listing was told more than the README stands behind.
 *
 * These tests hold the description to the README's opening paragraph: the
 * same sentences in the same order, as plain text. That paragraph says what
 * Secretless does and claims enforcement for Claude Code and no other tool.
 * What it does not cover, the instruction and ignore files that nothing
 * enforces and a command whose own output is a credential, has its own section
 * near the end of the README. The license is the last badge of the README
 * header and the manifest's `license` field, so neither the paragraph nor the
 * description repeats it. A change to either one fails here until the other
 * follows.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const README = fs.readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf-8');
const PACKAGE: { description: string; license: string } = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8'),
);

/** The OpenA2A project bar, the last line of the README header. */
const ECOSYSTEM_LINE = /^> \*\*\[OpenA2A.*$/m;

/** Where the header ends: after the project bar, or after the title where there is none. */
function headerEnd(readme: string): number {
  const bar = ECOSYSTEM_LINE.exec(readme) ?? /^# .*$/m.exec(readme);
  return bar ? bar.index + bar[0].length : 0;
}

/** The text up to the first section that follows `from`. */
function untilFirstSection(readme: string, from: number): string {
  const rest = readme.slice(from);
  const firstSection = rest.search(/^## /m);
  return firstSection === -1 ? rest : rest.slice(0, firstSection);
}

function paragraphsOf(text: string): string[] {
  return text
    .split(/\n{2,}/)
    .map((p) => p.replace(/\n/g, ' ').trim())
    .filter((p) => p !== '');
}

/** A paragraph of badge images or links and nothing else: a badge row or a navigation line. */
function onlyBadgesOrLinks(paragraph: string): boolean {
  return (
    paragraph
      .replace(/\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)/g, '')
      .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
      .replace(/\[[^\]]*\]\([^)]*\)/g, '')
      .replace(/[\s·|]/g, '') === ''
  );
}

/** The README's paragraphs between its header and its first section that describe the package. */
function openingParagraphs(readme: string): string[] {
  return paragraphsOf(untilFirstSection(readme, headerEnd(readme))).filter((p) => !onlyBadgesOrLinks(p));
}

interface Badge {
  alt: string;
  /** The text a shields.io badge shows, read from its image address; empty for other badges. */
  label: string;
}

/** The last badge of the header's badge row: the first paragraph above the project bar made only of badge images. */
function lastHeaderBadge(readme: string): Badge | undefined {
  const bar = ECOSYSTEM_LINE.exec(readme);
  const header = bar ? readme.slice(0, bar.index) : untilFirstSection(readme, 0);
  const row = paragraphsOf(header).find((p) => /!\[/.test(p) && onlyBadgesOrLinks(p));
  const images = [...(row ?? '').matchAll(/!\[([^\]]*)\]\(([^)\s]*)[^)]*\)/g)];
  const last = images[images.length - 1];
  if (!last) return undefined;
  const shown = /\/badge\/([^?#]*)/.exec(last[2]);
  return { alt: last[1], label: shown ? decodeURIComponent(shown[1]) : '' };
}

/** Whether `text` names `license`, ignoring case and the spaces, dots, underscores and hyphens between its parts. */
function namesLicense(text: string, license: string): boolean {
  const parts = license.split(/[^a-z0-9]+/i).filter(Boolean);
  return parts.length > 0 && new RegExp(`\\b${parts.join('[\\s._-]*')}\\b`, 'i').test(text);
}

function badgeNamesLicense(badge: Badge | undefined, license: string): boolean {
  return badge !== undefined && (namesLicense(badge.alt, license) || namesLicense(badge.label, license));
}

/** Markdown as the plain text a listing shows: link text without its target, no code or bold marks. */
function plainText(markdown: string): string {
  return markdown
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[`*]/g, '');
}

function sentences(text: string): string[] {
  return text.split(/(?<=[.!?])\s+/).map((s) => s.trim()).filter(Boolean);
}

/** Words that say a read is refused, not only discouraged. */
const ENFORCING = /\b(hooks?|deny rules?|enforced?|enforces|block(s|ed|ing)?)\b/i;

/** The tools that get an instruction or ignore file, which nothing enforces. */
const INSTRUCTION_ONLY = /\b(Cursor|Copilot|Windsurf|Cline|Aider)\b/;

/** The README section that says what Secretless does not cover. */
const LIMITS_HEADING = 'What it does not cover';

/**
 * The sentences that name a hook, deny rules, enforcement or blocking and are
 * not about Claude Code alone: they leave Claude Code out, or they also name a
 * tool that gets only an instruction or ignore file. What those tools get is
 * said in the README's closing section, not beside the enforcement sentence.
 */
function unscopedEnforcementSentences(description: string): string[] {
  return sentences(description).filter(
    (s) => ENFORCING.test(s) && (!/\bClaude Code\b/.test(s) || INSTRUCTION_ONLY.test(s)),
  );
}

/** The text of the `## heading` section, up to the next section; empty where there is none. */
function sectionBody(readme: string, heading: string): string {
  const marker = `\n## ${heading}\n`;
  const start = readme.indexOf(marker);
  if (start === -1) return '';
  const rest = readme.slice(start + marker.length);
  const next = rest.search(/^## /m);
  return next === -1 ? rest : rest.slice(0, next);
}

describe('package.json description', () => {
  const paragraphs = openingParagraphs(README);
  const opening = sentences(plainText(paragraphs[0] ?? ''));

  it('the README opens with one description paragraph and carries the license as the last header badge', () => {
    expect(
      paragraphs,
      'README.md must hold exactly one paragraph of description between its header and its first ' +
        'section; the package description is read from it',
    ).toHaveLength(1);
    expect(
      badgeNamesLicense(lastHeaderBadge(README), PACKAGE.license),
      `the last badge of the README header's badge row must name the license (${PACKAGE.license})`,
    ).toBe(true);
    expect(
      namesLicense(paragraphs[0] ?? '', PACKAGE.license),
      `the description paragraph must not name the license (${PACKAGE.license}); the header badge carries it`,
    ).toBe(false);
    expect(opening.length, 'the opening paragraph says nothing').toBeGreaterThan(0);
  });

  it('is the README opening paragraph', () => {
    expect(
      PACKAGE.description,
      'package.json `description` is what `npm search` and the registry listing show. It must say ' +
        'what the README opening paragraph says, sentence for sentence, so the listing claims no ' +
        'more than the README does. Change both in the same commit.',
    ).toBe(opening.join(' '));
  });

  it('says where the read gate is enforced and claims it for no other tool', () => {
    // Read from the description itself, so an edit that widens the claim in
    // the README and the manifest together fails here.
    expect(
      PACKAGE.description,
      'package.json description no longer says where the read gate is enforced',
    ).toMatch(/In Claude Code a hook and deny rules enforce/);
    expect(
      unscopedEnforcementSentences(PACKAGE.description),
      'a sentence of the description that names enforcement must name Claude Code and no other tool',
    ).toEqual([]);
  });

  it('leaves what is not covered to a section near the end of the README', () => {
    const headings = README.split('\n').filter((l) => l.startsWith('## '));
    const limits = headings.indexOf(`## ${LIMITS_HEADING}`);
    expect(limits, `README.md must hold a "## ${LIMITS_HEADING}" section`).toBeGreaterThan(-1);
    expect(limits, `"${LIMITS_HEADING}" must come after "Install"`).toBeGreaterThan(headings.indexOf('## Install'));
    const section = sectionBody(README, LIMITS_HEADING);
    expect(section, 'the section no longer says the instruction and ignore files are not enforced').toMatch(
      /nothing enforces/,
    );
    expect(section, 'the section no longer says the guard cannot see what a command prints').toMatch(
      /cannot see what it prints/,
    );
    for (const text of [README, PACKAGE.description]) {
      expect(text).not.toMatch(/prints its own credential is not blocked/);
    }
  });

  it('carries no wording that every tool or every path is covered', () => {
    for (const absolute of [/\bany AI\b/i, /\bout of AI\b/i, /\binvisible\b/i, /\bnever\b/i, /\ball AI\b/i]) {
      expect(PACKAGE.description, `package.json description matches ${absolute}`).not.toMatch(absolute);
    }
  });

  it('is one line of plain text', () => {
    expect(PACKAGE.description).not.toMatch(/[\n\r`*\[\]]/);
    expect(PACKAGE.description).toBe(PACKAGE.description.trim());
  });
});

describe('reading the description and license from a README header', () => {
  const LICENSE = 'Apache-2.0';
  const STATUS = '[![Status: stable](https://img.shields.io/badge/status-stable-green)](STATUS.md)';
  const CI = '[![CI](https://example.test/ci/badge.svg)](https://example.test/ci)';
  const LICENSE_BADGE = '[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)';

  function readme(badges: string[], ...description: string[]): string {
    return [
      '# Example',
      badges.join('\n'),
      '> **[OpenA2A](https://github.com/opena2a-org)**: [CLI](https://github.com/opena2a-org/opena2a) · **Example**',
      '[Website](https://example.test) · [Discord](https://example.test/chat)',
      ...description,
      '## Quick start',
      'Run it.',
    ].join('\n\n');
  }

  it('passes a README with the header, the license as its last badge, and one description paragraph', () => {
    const text = readme([STATUS, CI, LICENSE_BADGE], 'Example does one thing. It says what it does not do.');
    expect(openingParagraphs(text)).toEqual(['Example does one thing. It says what it does not do.']);
    expect(badgeNamesLicense(lastHeaderBadge(text), LICENSE)).toBe(true);
    expect(namesLicense(openingParagraphs(text)[0], LICENSE)).toBe(false);
  });

  it('fails a README with two description paragraphs below the project bar', () => {
    const text = readme([STATUS, CI, LICENSE_BADGE], 'Example does one thing.', 'It also does another.');
    expect(openingParagraphs(text)).toHaveLength(2);
  });

  it('fails a README whose last header badge does not name the license', () => {
    expect(badgeNamesLicense(lastHeaderBadge(readme([STATUS, LICENSE_BADGE, CI], 'Example.')), LICENSE)).toBe(false);
    expect(badgeNamesLicense(lastHeaderBadge(readme([STATUS, CI], 'Example.')), LICENSE)).toBe(false);
  });

  it('fails a description paragraph that names the license in a sentence of its own', () => {
    const text = readme([STATUS, CI, LICENSE_BADGE], 'Example does one thing. Apache 2.0.');
    expect(namesLicense(openingParagraphs(text)[0], LICENSE)).toBe(true);
  });
});

describe('finding enforcement sentences that are not about Claude Code alone', () => {
  it('flags a sentence that puts a hook or blocking on a tool that gets only an instruction or ignore file', () => {
    expect(unscopedEnforcementSentences('PreToolUse hooks block credential reads in Claude Code, Cursor and Windsurf.')).toHaveLength(1);
    expect(unscopedEnforcementSentences('In Claude Code and Aider a hook and deny rules enforce that.')).toHaveLength(1);
  });

  it('flags the enforcement sentence that also lists what the other tools get', () => {
    expect(
      unscopedEnforcementSentences(
        'In Claude Code a hook and deny rules enforce that; Cursor and Aider get instruction or ignore files that nothing enforces.',
      ),
    ).toHaveLength(1);
  });

  it('flags a sentence that claims blocking without naming Claude Code', () => {
    expect(unscopedEnforcementSentences('Blocks AI coding tools from reading secret files.')).toHaveLength(1);
  });

  it('passes a sentence that names the tools it sets up and an enforcement sentence scoped to Claude Code', () => {
    expect(
      unscopedEnforcementSentences(
        'Example sets up Claude Code, Cursor and Aider not to read credential files. In Claude Code a hook and deny rules enforce that.',
      ),
    ).toEqual([]);
  });
});

describe('reading one section of a README', () => {
  const text = ['# Example', `## ${LIMITS_HEADING}`, 'Limits here.', '## Documentation', 'Links.'].join('\n\n');

  it('returns the body of the section and stops at the next one', () => {
    expect(sectionBody(text, LIMITS_HEADING).trim()).toBe('Limits here.');
  });

  it('returns nothing for a section the README does not hold', () => {
    expect(sectionBody(text, 'No such section')).toBe('');
  });
});
