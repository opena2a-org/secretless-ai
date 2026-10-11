import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Many MCP client configs hold no key: `protect-mcp` reports "No plaintext
 * secrets found in MCP configs. Already clean." for them. The client
 * application reads a config to start its servers; the model sees what the
 * config holds only when an assistant reads that file. The README's "MCP
 * server protection" section said every config has plaintext keys and that
 * the LLM sees them, and the MCP guide and the use-case index said the same.
 * These pages may say configs often hold keys, and must make what the model
 * sees conditional on an assistant reading the file.
 */

const REPO_ROOT = path.resolve(__dirname, '..');

/** The README section under `heading`, up to the next `## ` heading. */
function readmeSection(heading: string): string {
  const readme = fs.readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf-8');
  const start = readme.indexOf(`\n${heading}\n`);
  expect(start, `README.md must hold a "${heading}" section`).toBeGreaterThan(-1);
  const rest = readme.slice(start + heading.length + 2);
  const end = rest.search(/^## /m);
  return end === -1 ? rest : rest.slice(0, end);
}

/** `text`'s prose sentences: fenced code blocks and inline code spans dropped. */
function sentences(text: string): string[] {
  const prose = text
    .replace(/^\s*```[\s\S]*?^\s*```\s*$/gm, '')
    .replace(/`[^`\n]*`/g, 'CODE');
  return prose
    .split(/(?<=[.!?])\s+|\n\s*\n/)
    .map((s) => s.replace(/\s+/g, ' ').trim())
    .filter((s) => s.length > 0);
}

const PAGES: { label: string; text: () => string }[] = [
  { label: 'README.md "## MCP server protection"', text: () => readmeSection('## MCP server protection') },
  {
    label: 'docs/use-cases/secure-mcp-configs.md',
    text: () => fs.readFileSync(path.join(REPO_ROOT, 'docs', 'use-cases', 'secure-mcp-configs.md'), 'utf-8'),
  },
  {
    label: 'docs/USE-CASES.md',
    text: () => fs.readFileSync(path.join(REPO_ROOT, 'docs', 'USE-CASES.md'), 'utf-8'),
  },
];

describe('docs: what an MCP config exposes', () => {
  for (const page of PAGES) {
    it(`${page.label} does not say every MCP config holds plaintext keys`, () => {
      const claims = sentences(page.text()).filter(
        (s) =>
          /\bMCP\b/.test(s) &&
          /\b(configs?|configuration|JSON)\b/i.test(s) &&
          /\bplaintext\b/i.test(s) &&
          /\b(keys?|credentials?|secrets?)\b/i.test(s) &&
          !/\b(often|many|some|may|might)\b/i.test(s),
      );
      expect(
        claims,
        'a sentence that MCP configs hold plaintext keys must say they often do, not that every one does',
      ).toEqual([]);
    });

    it(`${page.label} makes what the model sees conditional on an assistant reading the file`, () => {
      const claims = sentences(page.text()).filter(
        (s) =>
          /\b(LLM|model|AI tool|assistant)s?\b/i.test(s) &&
          /\b(sees?|visible)\b/i.test(s) &&
          !/\b(only|if|unless)\b/i.test(s),
      );
      expect(
        claims,
        'a sentence that the model sees a key must say it does only when an assistant reads the file',
      ).toEqual([]);
    });
  }
});
