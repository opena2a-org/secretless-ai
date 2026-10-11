import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { pathToFileURL } from 'url';

/**
 * scripts/check-docs-prose.mjs holds the Markdown a reader sees to two rules:
 * no dash punctuation (a spaced double hyphen, an em dash, a spaced en dash)
 * and no section named "Why this exists" or "Why this matters". `npm test`
 * runs it before the suite. These tests hold what it reports, what it skips
 * as code, and which files it reads.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'check-docs-prose.mjs');

// Built from code points so this file shows which character each case is.
const EM = String.fromCharCode(0x2014);
const EN = String.fromCharCode(0x2013);

interface Finding {
  line: number;
  message: string;
}

interface CheckModule {
  findProseIssues(text: string): Finding[];
  isInScope(relPath: string): boolean;
  filesInScope(root?: string): string[];
}

const load = (): Promise<CheckModule> => import(pathToFileURL(SCRIPT).href);

async function findings(...lines: string[]): Promise<string[]> {
  const { findProseIssues } = await load();
  return findProseIssues(lines.join('\n')).map(f => `${f.line}: ${f.message}`);
}

describe('check-docs-prose findings', () => {
  it('names the line of each dash used as punctuation', async () => {
    expect(
      await findings(
        '# Title',
        '',
        `One ${EM} two.`,
        'Three -- four.',
        `Five ${EN} six.`,
        'A sentence wrapped after the dash --',
        '-- and one wrapped before it.',
        `Unspaced${EM}em dash.`,
      ),
    ).toEqual([
      '3: em dash',
      '4: double hyphen used as a dash',
      '5: spaced en dash',
      '6: double hyphen used as a dash',
      '7: double hyphen used as a dash',
      '8: em dash',
    ]);
  });

  it('names a "Why this exists" or "Why this matters" heading or bold label', async () => {
    expect(
      await findings(
        '## Why this exists',
        '### why this matters',
        '**Why this exists:** a label standing in for a heading.',
        '## Why this is not a `postinstall` hook',
        'Prose that asks why this exists is not a section.',
      ),
    ).toEqual([
      '1: section named "Why this exists" or "Why this matters"',
      '2: section named "Why this exists" or "Why this matters"',
      '3: section named "Why this exists" or "Why this matters"',
    ]);
  });

  it('passes hyphens that are not dashes', async () => {
    expect(
      await findings(
        'An end-to-end run passes --force and -n to the command.',
        `A range: \`22:00\`${EN}\`06:00\`, or pages 1${EN}2.`,
        '---',
        '| Flag | Effect |',
        '|---|---|',
      ),
    ).toEqual([]);
  });

  it('skips fenced code, inline code, HTML comments and front matter', async () => {
    expect(
      await findings(
        '---',
        `title: Front ${EM} matter`,
        '---',
        '```bash',
        'npx secretless-ai run -- node app.js',
        '```',
        '~~~',
        `Quoted output ${EM} as printed.`,
        '~~~',
        '  ```',
        '  indented -- fence inside a list item',
        '  ```',
        `Inline \`run -- env\` and \`a ${EM} b\` are code.`,
        'A span that wraps `scan',
        '-- --help` onto the next line is still code.',
        `<!-- a comment ${EM} spanning`,
        'two lines -- here -->',
      ),
    ).toEqual([]);
  });

  it('keeps line numbers after the skipped blocks', async () => {
    expect(
      await findings(
        '```',
        'code -- line',
        '```',
        '<!-- one',
        'two -->',
        'A span `that',
        'wraps` here.',
        'Prose -- line eight.',
      ),
    ).toEqual(['8: double hyphen used as a dash']);
  });
});

describe('check-docs-prose file set', () => {
  it('reads published Markdown and leaves history, licenses, build output and test data alone', async () => {
    const { isInScope } = await load();
    for (const p of ['README.md', 'docs/scanning.md', 'docs/testing/release-smoke.md', 'docs/guide.mdx']) {
      expect(isInScope(p), p).toBe(true);
    }
    for (const p of [
      'CHANGELOG.md',
      'changelog.d/316.md',
      'LICENSE.md',
      'node_modules/pkg/README.md',
      'dist/README.md',
      'test/hma/README.md',
      'src/__fixtures__/doc.md',
      'corpus/malicious/a.md',
      'src/cli.ts',
    ]) {
      expect(isInScope(p), p).toBe(false);
    }
  });

  it('this repository passes, and the test script runs the check', async () => {
    const { filesInScope } = await load();
    const files = filesInScope();
    expect(files).toContain('README.md');
    expect(files).not.toContain('CHANGELOG.md');

    const run = spawnSync(process.execPath, [SCRIPT], { cwd: REPO_ROOT, encoding: 'utf8' });
    expect(run.stdout + run.stderr).toContain('no findings');
    expect(run.status).toBe(0);

    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    expect(pkg.scripts['check:docs']).toBe('node scripts/check-docs-prose.mjs');
    expect(pkg.scripts.test).toContain('npm run check:docs');
  });
});
