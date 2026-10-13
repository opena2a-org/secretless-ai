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
 * the same order, as plain text, without the license line that the manifest's
 * `license` field already carries. A change to either one fails here until the
 * other follows.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const README = fs.readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf-8');
const PACKAGE: { description: string; license: string } = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8'),
);

/** A paragraph a reader does not take as the description: the title, badges or the project bar. */
const NOT_DESCRIPTION = /^(#|\[!\[|>)/;

/** The README's paragraphs above its first section that describe the package. */
function openingParagraphs(readme: string): string[] {
  const firstSection = readme.search(/^## /m);
  const top = firstSection === -1 ? readme : readme.slice(0, firstSection);
  return top
    .split(/\n{2,}/)
    .map((p) => p.replace(/\n/g, ' ').trim())
    .filter((p) => p !== '' && !NOT_DESCRIPTION.test(p));
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

/** A name with its spaces, dots and hyphens dropped, so "Apache 2.0." and "Apache-2.0" compare equal. */
const bare = (text: string): string => text.replace(/[\s.-]/g, '').toLowerCase();

describe('package.json description', () => {
  const paragraphs = openingParagraphs(README);
  const opening = sentences(plainText(paragraphs[0] ?? ''));
  const withoutLicense = opening.filter((s) => bare(s) !== bare(PACKAGE.license));

  it('the README opens with one description paragraph that names the license in a sentence of its own', () => {
    expect(
      paragraphs,
      'README.md must hold exactly one paragraph of description between its title and its first ' +
        'section; the package description is read from it',
    ).toHaveLength(1);
    expect(
      opening.length - withoutLicense.length,
      `the opening paragraph must name the license (${PACKAGE.license}) in a sentence of its own, ` +
        'which the package description leaves to the `license` field',
    ).toBe(1);
    expect(withoutLicense.length, 'the opening paragraph says nothing besides the license').toBeGreaterThan(0);
  });

  it('is the README opening paragraph without its license line', () => {
    expect(
      PACKAGE.description,
      'package.json `description` is what `npm search` and the registry listing show. It must say ' +
        'what the README opening paragraph says, sentence for sentence, so the listing claims no ' +
        'more than the README does. Change both in the same commit.',
    ).toBe(withoutLicense.join(' '));
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
