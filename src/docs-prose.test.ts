import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
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

  it('closes a run of backticks only on a run of the same length, and reads an unmatched run as text', async () => {
    expect(
      await findings(
        'A span ``with a ` and -- inside`` is code.',
        '',
        'An unmatched ``` run, then `a -- b` as code.',
        '',
        'A lone ` backtick, then -- as prose.',
        '',
        'A `span that does not',
        '',
        '-- cross` a blank line.',
      ),
    ).toEqual(['5: double hyphen used as a dash', '9: double hyphen used as a dash']);
  });

  it('checks a paragraph of growing unmatched backtick runs in time linear in its length', async () => {
    const { findProseIssues } = await load();
    let text = '';
    for (let n = 1; text.length < 2 * 1024 * 1024; n++) text += '`'.repeat(n) + ' a ';
    text += ' -- ';

    const started = Date.now();
    const found = findProseIssues(text);
    const elapsed = Date.now() - started;

    // Each run used to search to the end of the paragraph for its partner:
    // about 6 s for this 2 MB paragraph, against a few milliseconds now.
    expect(elapsed).toBeLessThan(1000);
    expect(found).toEqual([{ line: 1, message: 'double hyphen used as a dash' }]);
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

describe('check-docs-prose run on a repository', () => {
  const made: string[] = [];
  afterEach(() => {
    while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
  });

  // The script checks the repository it sits in, so each test copies it into a
  // fresh one. GIT_* variables set by a calling hook would point git elsewhere.
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('GIT_')));

  function git(root: string, ...args: string[]): void {
    const run = spawnSync('git', args, { cwd: root, env, encoding: 'utf8' });
    expect(run.status, run.stderr).toBe(0);
  }

  /** A git repository holding the script and `files`, every file tracked. */
  function repoWith(files: Record<string, string>): string {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'docs-prose-'));
    made.push(root);
    fs.mkdirSync(path.join(root, 'scripts'));
    fs.copyFileSync(SCRIPT, path.join(root, 'scripts', 'check-docs-prose.mjs'));
    for (const [rel, text] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.writeFileSync(path.join(root, rel), text);
    }
    git(root, 'init', '-q');
    git(root, 'add', '--', ...Object.keys(files));
    return root;
  }

  const check = (root: string) =>
    spawnSync(process.execPath, [path.join(root, 'scripts', 'check-docs-prose.mjs')], {
      cwd: root,
      env,
      encoding: 'utf8',
    });

  it('names file:line for each finding and exits 1', () => {
    const root = repoWith({
      'README.md': '# Readme\n\nPlain prose.\n',
      'docs/guide.md': `# Guide\n\nOne ${EM} two.\n`,
    });

    const run = check(root);

    expect(run.stdout).toBe('docs/guide.md:3: em dash\n');
    expect(run.stderr).toBe(
      'check-docs-prose: 1 finding(s) in 2 file(s). ' +
        'Rewrite each dash as a period, comma, colon or parentheses; fold a "Why this exists" section into the prose above it.\n',
    );
    expect(run.status).toBe(1);
  });

  it('counts only the files it read: a tracked file deleted from the working tree is not counted as checked', () => {
    const root = repoWith({
      'README.md': '# Readme\n\nPlain prose.\n',
      'docs/gone.md': '# Gone\n',
      'docs/guide.md': `# Guide\n\nOne ${EM} two.\n`,
    });
    fs.rmSync(path.join(root, 'docs', 'gone.md'));

    const failing = check(root);
    expect(failing.stderr).toContain('check-docs-prose: 1 finding(s) in 2 file(s).');
    expect(failing.status).toBe(1);

    fs.writeFileSync(path.join(root, 'docs', 'guide.md'), '# Guide\n\nOne, two.\n');
    const passing = check(root);
    expect(passing.stdout).toBe('check-docs-prose: 2 file(s) checked, no findings.\n');
    expect(passing.status).toBe(0);
  });

  it('checks the repository when started through a symbolic link to it', () => {
    const root = repoWith({
      'README.md': '# Readme\n\nPlain prose.\n',
      'docs/guide.md': `# Guide\n\nOne ${EM} two.\n`,
    });
    const link = `${root}-link`;
    fs.symlinkSync(root, link, 'dir');
    made.push(link);

    // Node resolves the link in the path of the script it runs. Started this
    // way, as it is from the macOS temporary directory, the script took itself
    // for an imported module and exited 0 with no output and nothing checked.
    const run = check(link);

    expect(run.stdout).toBe('docs/guide.md:3: em dash\n');
    expect(run.stderr).toContain('check-docs-prose: 1 finding(s) in 2 file(s).');
    expect(run.status).toBe(1);
  });
});
