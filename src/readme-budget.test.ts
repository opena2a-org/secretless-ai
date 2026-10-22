import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { DEMO_START, demoCaption } from './tape.test-support';

/**
 * The README is the page a visitor reads before installing. It is held to a
 * short form: the first command and its output at the top, a list of tasks
 * that link to the section for each, one usage section, install, telemetry,
 * what it does not cover, documentation and license. Reference detail lives
 * under docs/ with a link from the README. At 4376 words in 16 sections a
 * reader had to scroll past
 * the architecture, the supported-tools table and the backends to reach
 * Telemetry, and the sample output and two paragraphs carried version numbers
 * that went stale on every release.
 *
 * These tests hold the budgets, and hold that a section moved out of the
 * README is on the page it moved to. A move leaves links behind, so every
 * relative link and anchor in the README and docs/ is checked against the file
 * and heading it names.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const README_PATH = path.join(REPO_ROOT, 'README.md');
const README_LINE_BUDGET = 400;
const README_WORD_BUDGET = 896;
const README_SECTION_BUDGET = 8;
const PARAGRAPH_WORD_CAP = 69;
const LONG_PARAGRAPH_WORDS = 60;
const LONG_PARAGRAPHS_ALLOWED = 1;
const FIRST_COMMAND = 'npx secretless-ai init';
const FIRST_SCREEN_LINES = 30;
const TASK_LIST_HEADING = 'Common tasks';

/** A release number or a calendar date: text that is wrong after the next release. */
const VERSION_OR_DATE = /v?[0-9]+\.[0-9]+\.[0-9]+|20[0-9]{2}-[0-9]{2}-[0-9]{2}/;

/** Each section that left the README, and the page it is on now. */
const MOVED_SECTIONS: Array<[heading: string, page: string]> = [
  ['From source', 'docs/install.md'],
  ['Verifying what was installed', 'docs/install.md'],
  ['How it works', 'docs/how-it-works.md'],
  ['Architecture', 'docs/how-it-works.md'],
  ['Supported tools', 'docs/how-it-works.md'],
  ['Storage backends', 'docs/how-it-works.md'],
  ['NanoMind integration', 'docs/how-it-works.md'],
  ['Store secrets and use them in AI sessions', 'docs/managing-secrets.md'],
  ['Record what a credential is for', 'docs/managing-secrets.md'],
  ['Move secrets to another machine', 'docs/managing-secrets.md'],
  ['Track an exposed key until it is rotated', 'docs/managing-secrets.md'],
  ['Give git a stored token over HTTPS', 'docs/managing-secrets.md'],
  ['Ask your AI assistant to use a secret', 'docs/managing-secrets.md'],
  ['What the guard cannot see', 'docs/managing-secrets.md'],
  ['Push secrets to a cloud secret store', 'docs/managing-secrets.md'],
  ['MCP server protection', 'docs/commands.md'],
  ['Triage helpers', 'docs/commands.md'],
  ['Exit codes and scan coverage', 'docs/commands.md'],
  ['Using with opena2a-cli', 'docs/commands.md'],
  ['Use cases', 'docs/USE-CASES.md'],
  ['Contributing', 'CONTRIBUTING.md'],
];

const FENCE = /^\s*(```|~~~)/;
const HEADING = /^(#{1,6})\s+(.+?)\s*#*\s*$/;

const readme = (): string => fs.readFileSync(README_PATH, 'utf-8');
const wordCount = (text: string): number => text.split(/\s+/).filter(Boolean).length;

/** Markdown the project publishes to users: the README and everything under docs/. */
function publishedMarkdown(): string[] {
  const files = [README_PATH];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.md')) files.push(full);
    }
  };
  walk(path.join(REPO_ROOT, 'docs'));
  return files;
}

/** Lines outside fenced code blocks, with their 1-based line numbers. */
function proseLines(text: string): Array<[number, string]> {
  const out: Array<[number, string]> = [];
  let inFence = false;
  text.split('\n').forEach((line, i) => {
    if (FENCE.test(line)) { inFence = !inFence; return; }
    if (!inFence) out.push([i + 1, line]);
  });
  return out;
}

/**
 * The paragraphs a reader meets: runs of lines outside fenced code, ended by a
 * blank line, a heading or a code block. A list with no blank line between its
 * items is one paragraph, as it is one block on the page.
 */
function paragraphs(text: string): string[] {
  const out: string[] = [];
  let current: string[] = [];
  let last = 0;
  const end = (): void => {
    if (current.length > 0) out.push(current.join(' '));
    current = [];
  };
  for (const [n, line] of proseLines(text)) {
    if (n !== last + 1 || line.trim() === '' || HEADING.test(line)) end();
    if (line.trim() !== '' && !HEADING.test(line)) current.push(line);
    last = n;
  }
  end();
  return out;
}

/** GitHub's anchor for a heading: lowercase, punctuation dropped, spaces to hyphens. */
function headingAnchor(text: string): string {
  return text.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
}

/** Every anchor GitHub generates for a file's headings, numbering repeats as it does. */
function anchorsOf(file: string): Set<string> {
  const seen = new Map<string, number>();
  const anchors = new Set<string>();
  for (const [, line] of proseLines(fs.readFileSync(file, 'utf-8'))) {
    const h = line.match(HEADING);
    if (!h) continue;
    const base = headingAnchor(h[2]);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    anchors.add(n === 0 ? base : `${base}-${n}`);
  }
  return anchors;
}

/** Relative link targets on a line; code spans are dropped so `[a](b)` in code is not a link. */
function relativeLinks(line: string): string[] {
  const text = line.replace(/`[^`]*`/g, '');
  const targets: string[] = [];
  for (const m of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(m[1])) continue; // https:, mailto: and other schemes
    targets.push(m[1]);
  }
  return targets;
}

/** The file a relative link names and its anchor, read from the page that holds the link. */
function resolveLink(fromFile: string, target: string): { dest: string; anchor: string } {
  const hash = target.indexOf('#');
  const rel = hash === -1 ? target : target.slice(0, hash);
  const anchor = hash === -1 ? '' : decodeURIComponent(target.slice(hash + 1));
  const dest = rel === '' ? fromFile : path.resolve(path.dirname(fromFile), decodeURIComponent(rel));
  return { dest, anchor };
}

/**
 * The first line of the first fenced block in the section a link lands on: the
 * section under the heading the anchor names, up to the next heading of that
 * level or above, or the whole page for a link with no anchor.
 */
function firstCodeLineAt(file: string, anchor: string): string | null {
  const lines = fs.readFileSync(file, 'utf-8').split('\n');
  let start = 0;
  let level = 0;
  if (anchor) {
    let inFence = false;
    start = lines.findIndex((line) => {
      if (FENCE.test(line)) { inFence = !inFence; return false; }
      const h = inFence ? null : line.match(HEADING);
      if (!h || headingAnchor(h[2]) !== anchor) return false;
      level = h[1].length;
      return true;
    });
    if (start === -1) return null;
  }
  let inFence = false;
  for (const line of lines.slice(start + 1)) {
    if (FENCE.test(line)) {
      if (!inFence) inFence = true;
      else return null;
      continue;
    }
    if (inFence) {
      if (line.trim() !== '') return line.trim();
      continue;
    }
    const h = line.match(HEADING);
    if (anchor && h && h[1].length <= level) return null;
  }
  return null;
}

describe('README length budget', () => {
  it(`README.md is under ${README_LINE_BUDGET} lines`, () => {
    // Counted the way `wc -l` counts: newline characters.
    const lines = (readme().match(/\n/g) ?? []).length;
    expect(
      lines,
      `README.md is ${lines} lines; the budget for a CLI README is under ${README_LINE_BUDGET}. ` +
        'Move reference detail to a page under docs/ and link it from the README.',
    ).toBeLessThan(README_LINE_BUDGET);
  });

  it(`README.md is at most ${README_WORD_BUDGET} words in at most ${README_SECTION_BUDGET} sections`, () => {
    // Counted the way `wc -w` counts: runs of non-space characters, code included.
    const words = wordCount(readme());
    expect(
      words,
      `README.md is ${words} words; the budget is ${README_WORD_BUDGET}. ` +
        'Move reference detail to a page under docs/ and link it from the README.',
    ).toBeLessThanOrEqual(README_WORD_BUDGET);

    const sections = readme().split('\n').filter(l => l.startsWith('## '));
    expect(sections.length, `README.md sections: ${sections.join(', ')}`).toBeLessThanOrEqual(README_SECTION_BUDGET);
  });

  it(`no README paragraph is over ${PARAGRAPH_WORD_CAP} words, and at most ${LONG_PARAGRAPHS_ALLOWED} is over ${LONG_PARAGRAPH_WORDS}`, () => {
    const sized = paragraphs(readme()).map(p => ({ words: wordCount(p), starts: p.slice(0, 60) }));
    // Guard against a reader that finds no paragraphs, which would pass any cap.
    expect(sized.length).toBeGreaterThan(10);
    expect(sized.filter(p => p.words > PARAGRAPH_WORD_CAP), 'split these, or move them to a page under docs/').toEqual([]);
    expect(sized.filter(p => p.words > LONG_PARAGRAPH_WORDS).length).toBeLessThanOrEqual(LONG_PARAGRAPHS_ALLOWED);
  });

  it('reads a list as one paragraph and a code block as none', () => {
    expect(paragraphs('# Title\n\nOne two.\nThree.\n\n- a b\n- c d\n\n```\nnot prose\n```\nAfter the block.\n'))
      .toEqual(['One two. Three.', '- a b - c d', 'After the block.']);
  });

  it('no README line carries a release number or a date, other than the caption the recording\'s sidecar gives it', () => {
    // A sample that prints a version banner is shown from below the banner,
    // and the whole of it is kept under docs/captures/. The caption under the
    // recording names the version and the day of its render: the render
    // script writes it from docs/vhs/init.json, and
    // src/recording-sidecar.test.ts holds that sidecar to the version in
    // package.json, so it is the one line that moves with each release. It is
    // allowed only as that exact line, in its place under the image.
    const sidecar = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'docs', 'vhs', 'init.json'), 'utf-8'));
    const lines = readme().split('\n');
    const captionAt = lines.indexOf(DEMO_START) === -1 ? -1 : lines.indexOf(DEMO_START) + 2;
    const stale = lines.flatMap((line, i) =>
      VERSION_OR_DATE.test(line) && !(i === captionAt && line === demoCaption(sidecar)) ? [`${i + 1}: ${line}`] : [],
    );
    expect(stale).toEqual([]);
  });

  it(`the first command and the start of its output are in the first ${FIRST_SCREEN_LINES} lines`, () => {
    let commandLine = 0;
    let outputLine = 0;
    let inFence = false;
    readme().split('\n').forEach((line, i) => {
      if (FENCE.test(line)) {
        inFence = !inFence;
        // The first block opened after the command is its output.
        if (inFence && commandLine && !outputLine) outputLine = i + 2;
        return;
      }
      if (!commandLine && line.includes(FIRST_COMMAND)) commandLine = i + 1;
    });
    expect(commandLine, `README.md no longer runs \`${FIRST_COMMAND}\``).toBeGreaterThan(0);
    expect(outputLine, `README.md shows no output block after \`${FIRST_COMMAND}\``).toBeGreaterThan(0);
    expect(commandLine).toBeLessThanOrEqual(FIRST_SCREEN_LINES);
    expect(outputLine).toBeLessThanOrEqual(FIRST_SCREEN_LINES);
  });

  it('the scan coverage reference is under docs/ and the README links to it', () => {
    expect(fs.existsSync(path.join(REPO_ROOT, 'docs', 'scanning.md'))).toBe(true);
    expect(readme()).toContain('](docs/scanning.md)');
    expect(readme()).toContain('](docs/scanning.md#what-a-directory-scan-opens)');
  });
});

describe('sections moved out of the README', () => {
  it.each(MOVED_SECTIONS)('"%s" is a heading in %s', (heading, page) => {
    const file = path.join(REPO_ROOT, page);
    expect(fs.existsSync(file), `${page} does not exist`).toBe(true);
    const headings = proseLines(fs.readFileSync(file, 'utf-8')).flatMap(([, line]) => {
      const h = line.match(HEADING);
      return h ? [h[2]] : [];
    });
    expect(headings).toContain(heading);
  });

  it('the README links every page a section moved to', () => {
    for (const page of new Set(MOVED_SECTIONS.map(([, p]) => p))) {
      expect(readme(), `README.md has no link to ${page}`).toMatch(new RegExp(`\\]\\(${page.replace(/[.]/g, '\\.')}[)#]`));
    }
  });
});

describe('the README task list', () => {
  /** The links of the list under the task-list heading. */
  function taskLinks(): string[] {
    const lines = readme().split('\n');
    const start = lines.indexOf(`## ${TASK_LIST_HEADING}`);
    expect(start, `README.md must hold a "## ${TASK_LIST_HEADING}" section`).toBeGreaterThan(-1);
    const end = lines.findIndex((l, i) => i > start && l.startsWith('## '));
    return lines.slice(start + 1, end === -1 ? undefined : end).flatMap(relativeLinks);
  }

  it('finds the first code line of a section, and none where the section has no code', () => {
    const secrets = path.join(REPO_ROOT, 'docs', 'managing-secrets.md');
    expect(firstCodeLineAt(secrets, 'move-secrets-to-another-machine')).toMatch(/^npx secretless-ai export /);
    expect(firstCodeLineAt(secrets, 'what-the-guard-cannot-see')).toBeNull();
    expect(firstCodeLineAt(secrets, 'no-such-heading')).toBeNull();
  });

  it('every task links to a section whose first code block runs a secretless-ai command', () => {
    const links = taskLinks();
    expect(links.length).toBeGreaterThan(3);
    const deadEnds: string[] = [];
    for (const target of links) {
      const { dest, anchor } = resolveLink(README_PATH, target);
      const first = fs.existsSync(dest) ? firstCodeLineAt(dest, anchor) : null;
      if (!first || !first.startsWith('npx secretless-ai ')) {
        deadEnds.push(`${target}: ${first === null ? 'no code block in that section' : `first code line is "${first}"`}`);
      }
    }
    expect(deadEnds).toEqual([]);
  });
});

describe('relative links in published markdown resolve', () => {
  const files = [...publishedMarkdown(), path.join(REPO_ROOT, 'CONTRIBUTING.md')];

  it('finds the README and the pages under docs/', () => {
    // Guard against the walk matching nothing, which would make the check below vacuous.
    expect(files).toContain(README_PATH);
    expect(files).toContain(path.join(REPO_ROOT, 'docs', 'scanning.md'));
  });

  it('every relative link names a file that exists and a heading that file has', () => {
    const broken: string[] = [];
    for (const file of files) {
      const where = path.relative(REPO_ROOT, file);
      for (const [n, line] of proseLines(fs.readFileSync(file, 'utf-8'))) {
        for (const target of relativeLinks(line)) {
          const { dest, anchor } = resolveLink(file, target);
          if (!fs.existsSync(dest)) {
            broken.push(`${where}:${n}: ${target} — no such file`);
            continue;
          }
          if (anchor && dest.endsWith('.md') && !anchorsOf(dest).has(anchor)) {
            broken.push(`${where}:${n}: ${target} — ${path.relative(REPO_ROOT, dest)} has no heading #${anchor}`);
          }
        }
      }
    }
    expect(broken).toEqual([]);
  });
});
