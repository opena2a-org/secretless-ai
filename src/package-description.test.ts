import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * The package description is the line `npm search`, `npm view` and the
 * registry listing show beside the name, before a reader opens the README. It
 * read "One command to keep secrets out of AI. Works with Claude Code, Cursor,
 * Copilot, Windsurf, and any AI coding tool." The README's opening paragraph is
 * narrower: a hook and deny rules enforce the read gate in Claude Code, the
 * other tools get instruction or ignore files that nothing enforces, and a
 * command that prints its own credential is not blocked. A reader who chose
 * the package from the listing was told more than the README stands behind.
 *
 * These tests hold the description to that paragraph: the same sentences in
 * the same order, as plain text. The license is the last badge of the README
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

  it('says where the read gate is enforced and what is not blocked', () => {
    // The limits a reader of the listing needs before installing. Read from
    // the description itself, so an edit that drops one from the README and
    // the manifest together fails here.
    const limits: Array<[RegExp, string]> = [
      [/In Claude Code a hook and deny rules enforce/, 'where the read gate is enforced'],
      [/nothing enforces/, 'that the other tools get files nothing enforces'],
      [/prints its own credential is not blocked/, 'that a command printing its own credential is not blocked'],
    ];
    for (const [limit, what] of limits) {
      expect(PACKAGE.description, `package.json description no longer says ${what}`).toMatch(limit);
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
