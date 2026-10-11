#!/usr/bin/env node
/**
 * check-docs-prose.mjs: the punctuation and heading rules for the Markdown a
 * reader outside the tool sees.
 *
 * Every tracked `.md` and `.mdx` file is checked, except the release history
 * (CHANGELOG.md, changelog.d/), license text, vendored or built output, and
 * test-data directories, whose text is compared byte for byte by a test. A
 * finding is one of:
 *
 *   - a double hyphen used as a dash: `--` with whitespace or a line boundary
 *     on both sides, so a dash wrapped onto the start or end of a line counts;
 *   - an em dash (U+2014);
 *   - an en dash with whitespace or a line boundary on both sides (U+2013);
 *   - a heading, or a bold line standing in for one, named "Why this exists"
 *     or "Why this matters".
 *
 * Fenced code blocks, inline code spans, front matter and HTML comments are
 * not prose and are skipped: a `--` there is a command's end-of-options
 * separator or quoted program output.
 *
 *   node scripts/check-docs-prose.mjs
 *
 * Exit 0 when every file passes, 1 naming `file:line` for each finding, 2 when
 * the tracked file list cannot be read.
 */

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Directories whose text is not prose for a reader: built, vendored or test data. */
const EXCLUDED_DIRS = new Set([
  'node_modules', 'vendor', 'dist', 'build', 'changelog.d',
  'test', 'tests', '__tests__', 'testdata', 'fixture', 'fixtures', '__fixtures__',
  'corpus', 'golden', 'goldens', 'snapshot', 'snapshots', '__snapshots__',
  'example-input', 'example-inputs',
]);

/** Whether a repository-relative path is held to the prose rules. */
export function isInScope(relPath) {
  const parts = relPath.split(/[\\/]/);
  const base = parts[parts.length - 1];
  if (!/\.mdx?$/i.test(base)) return false;
  if (/^changelog\.md$/i.test(base) || /^licen[cs]e/i.test(base)) return false;
  return !parts.slice(0, -1).some(dir => EXCLUDED_DIRS.has(dir));
}

const FENCE_OPEN = /^\s*(`{3,}|~{3,})/;
const FENCE_CLOSE = /^\s*(`{3,}|~{3,})\s*$/;
const HEADING = /^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$/;
const BOLD_LABEL = /^\s*(\*\*|__)\s*why this (exists|matters)\b/i;
const WHY_THIS = /^why this (exists|matters)\b/i;

// A run of N backticks closes on the next run of exactly N, and a code span may
// wrap onto the next line but does not cross a blank line.
const CODE_SPAN = /(?<!`)(`+)(?!`)(?:(?!\n[ \t]*\n)[\s\S])*?(?<!`)\1(?!`)/g;
const HTML_COMMENT = /<!--[\s\S]*?(?:-->|$)/g;

const RULES = [
  { pattern: /(^|\s)--(?=\s|$)/, message: 'double hyphen used as a dash' },
  { pattern: /\u2014/, message: 'em dash' },
  { pattern: /(^|\s)\u2013(?=\s|$)/, message: 'spaced en dash' },
];

/** The line breaks in a removed span, so the lines after it keep their numbers. */
const lineBreaksOf = s => s.replace(/[^\n]/g, '');

/**
 * The prose lines of a Markdown text, numbered as in the file: front matter and
 * fenced code blocks become empty lines, HTML comments are removed and each
 * inline code span becomes the word `code`. A word rather than a space, so the
 * en dash between two code spans in a range does not read as a spaced one.
 */
function proseLines(text) {
  const lines = text.split(/\r?\n/);
  let start = 0;
  if (lines[0] === '---') {
    const end = lines.findIndex((l, n) => n > 0 && (l === '---' || l === '...'));
    if (end !== -1) start = end + 1;
  }
  let fence = null;
  const kept = lines.map((line, i) => {
    if (i < start) return '';
    if (fence) {
      const close = line.match(FENCE_CLOSE);
      if (close && close[1][0] === fence[0] && close[1].length >= fence.length) fence = null;
      return '';
    }
    const open = line.match(FENCE_OPEN);
    if (open) {
      fence = open[1];
      return '';
    }
    return line;
  });
  return kept
    .join('\n')
    .replace(CODE_SPAN, span => 'code' + lineBreaksOf(span))
    .replace(HTML_COMMENT, comment => lineBreaksOf(comment))
    .split('\n');
}

/**
 * The findings in one Markdown text, each as `{ line, message }` with a
 * 1-based line number.
 */
export function findProseIssues(text) {
  const findings = [];
  proseLines(text).forEach((prose, i) => {
    for (const rule of RULES) {
      if (rule.pattern.test(prose)) findings.push({ line: i + 1, message: rule.message });
    }
    const heading = prose.match(HEADING);
    if ((heading && WHY_THIS.test(heading[1].replace(/^[*_]+/, ''))) || BOLD_LABEL.test(prose)) {
      findings.push({ line: i + 1, message: 'section named "Why this exists" or "Why this matters"' });
    }
  });
  return findings;
}

/** Tracked Markdown files the rules apply to, repository-relative. */
export function filesInScope(root = REPO_ROOT) {
  const out = execFileSync('git', ['ls-files', '-z', '--', '*.md', '*.mdx'], { cwd: root, encoding: 'utf8' });
  return out.split('\0').filter(f => f && isInScope(f)).sort();
}

function main() {
  let files;
  try {
    files = filesInScope();
  } catch (err) {
    console.error(`check-docs-prose: cannot list tracked Markdown files with git: ${err.message}`);
    return 2;
  }
  let count = 0;
  for (const file of files) {
    const full = path.join(REPO_ROOT, file);
    if (!fs.existsSync(full)) continue;
    for (const f of findProseIssues(fs.readFileSync(full, 'utf8'))) {
      console.log(`${file}:${f.line}: ${f.message}`);
      count++;
    }
  }
  if (count > 0) {
    console.error(
      `check-docs-prose: ${count} finding(s) in ${files.length} file(s). ` +
        'Rewrite each dash as a period, comma, colon or parentheses; fold a "Why this exists" section into the prose above it.',
    );
    return 1;
  }
  console.log(`check-docs-prose: ${files.length} file(s) checked, no findings.`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = main();
}
