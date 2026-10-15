import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan, shellQuote } from './commands/core';
import { hasDisplayHazard, quotePathForDisplay } from './display-safe';

/**
 * What `scan` says about the paths it did not read, checked against what it
 * read.
 *
 * One tree holds a path for each way a path goes unread, and every file in it
 * carries a planted credential, so a finding shows a file was read and its
 * absence shows it was not. The report is then held to four rules: a file
 * listed as not opened yields no finding; a directory listed as not entered
 * yields none from inside it unless its reason says which files inside are
 * still read; every listed name prints through one rule, the same in the text
 * and in `--json`; and both list the same paths. The causes, Fix commands and
 * headings around those lists are held to what the scan did for the paths
 * under them.
 *
 * Planted values are assembled at run time, so the committed source never
 * carries a credential-shaped literal.
 */

const TOKEN = ['gh', 'p_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');
const AWS_KEY_ID = ['AK', 'IA', 'Q7XN3P2LMRT4VW8K'].join('');
function pemKey(): string {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey;
}

const JS = `const t = "${TOKEN}";\n`;
const JSON_CONFIG = `{"token":"${TOKEN}"}\n`;
const TXT = `aws_access_key_id = ${AWS_KEY_ID}\n`;

/**
 * The `--max-files` cap the tree is scanned with: one below the six files the
 * source walk accepts, so only the last of them in walk order, `zz/zz/capped.js`,
 * is dropped. The config and key walks accept fewer than five each, so the cap
 * stops no other walk.
 */
const CAP = 5;
const SOURCE_ELIGIBLE = 6;

type Entry =
  | { kind: 'file'; content: () => string | Buffer; mode?: number }
  | { kind: 'link'; target: string }
  | { kind: 'dir-mode'; mode: number };

/** Every path in the tree, by the way it goes unread (or, for a control, is read). */
const TREE: Record<string, { cell: string; entry: Entry }> = {
  'src/app.js': { cell: 'control: a source file that is read', entry: { kind: 'file', content: () => JS } },
  '.hidden/server.key': { cell: 'hidden directory', entry: { kind: 'file', content: pemKey } },
  '.hidden/config.json': { cell: 'hidden directory', entry: { kind: 'file', content: () => JSON_CONFIG } },
  '.hidden/app.js': { cell: 'hidden directory', entry: { kind: 'file', content: () => JS } },
  '.linked-hidden': { cell: 'hidden directory linked outside the root', entry: { kind: 'link', target: '<outside>' } },
  '.locked-hidden/config.json': { cell: 'hidden directory that cannot be listed', entry: { kind: 'file', content: () => JSON_CONFIG } },
  '.locked-hidden': { cell: 'hidden directory that cannot be listed', entry: { kind: 'dir-mode', mode: 0o000 } },
  '.secretlessignore': { cell: 'ignore rule (the file holding it)', entry: { kind: 'file', content: () => `# ${TXT}ignored-dir/\nignored.js\n` } },
  'ignored-dir/app.js': { cell: 'ignore rule', entry: { kind: 'file', content: () => JS } },
  'ignored-dir/config.json': { cell: 'ignore rule', entry: { kind: 'file', content: () => JSON_CONFIG } },
  'ignored.js': { cell: 'ignore rule', entry: { kind: 'file', content: () => JS } },
  'big.js': { cell: 'size cap', entry: { kind: 'file', content: () => `${JS}/*${'x'.repeat(1024 * 1024 + 16)}*/\n` } },
  'zz/zz/capped.js': { cell: '--max-files cap', entry: { kind: 'file', content: () => JS } },
  'image.png': {
    cell: 'binary file',
    entry: { kind: 'file', content: () => Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]), Buffer.from(TXT)]) },
  },
  'locked.js': { cell: 'unreadable mode', entry: { kind: 'file', content: () => JS, mode: 0o000 } },
  'locked-dir/app.js': { cell: 'unreadable mode (directory)', entry: { kind: 'file', content: () => JS } },
  'locked-dir/config.json': { cell: 'unreadable mode (directory)', entry: { kind: 'file', content: () => JSON_CONFIG } },
  'locked-dir': { cell: 'unreadable mode (directory)', entry: { kind: 'dir-mode', mode: 0o000 } },
  'nosearch/app.js': { cell: 'unsearchable directory', entry: { kind: 'file', content: () => JS } },
  'nosearch/config.json': { cell: 'unsearchable directory', entry: { kind: 'file', content: () => JSON_CONFIG } },
  'nosearch/server.key': { cell: 'unsearchable directory', entry: { kind: 'file', content: pemKey } },
  'nosearch/sub/app.js': { cell: 'unsearchable directory', entry: { kind: 'file', content: () => JS } },
  'nosearch': { cell: 'unsearchable directory', entry: { kind: 'dir-mode', mode: 0o600 } },
  'dangling.js': { cell: 'broken link', entry: { kind: 'link', target: 'missing-target.js' } },
  'loop-a.js': { cell: 'link loop', entry: { kind: 'link', target: 'loop-b.js' } },
  'loop-b.js': { cell: 'link loop', entry: { kind: 'link', target: 'loop-a.js' } },
  'into-nosearch.js': { cell: 'link whose target lies under an unsearchable directory', entry: { kind: 'link', target: path.join('nosearch', 'app.js') } },
  'outside-link': { cell: 'directory link outside the root', entry: { kind: 'link', target: '<outside>' } },
  'ctl\u001b[2Jname.txt': { cell: 'name with a control character', entry: { kind: 'file', content: () => TXT } },
  'back\\slash.txt': { cell: 'name with a backslash', entry: { kind: 'file', content: () => TXT } },
  'back\\slash.js': { cell: 'name with a backslash', entry: { kind: 'file', content: () => JS } },
  '.env.back\\slash': { cell: 'name with a backslash', entry: { kind: 'file', content: () => `GITHUB_TOKEN=${TOKEN}\n` } },
  'naïve-ü.txt': { cell: 'non-ASCII name', entry: { kind: 'file', content: () => TXT } },
  'values.toml': { cell: 'config file off the built-in list', entry: { kind: 'file', content: () => `aws_access_key_id = "${AWS_KEY_ID}"\n` } },
  'app.test.js': { cell: 'test file', entry: { kind: 'file', content: () => JS } },
  'test/app.js': { cell: 'test directory', entry: { kind: 'file', content: () => JS } },
  'node_modules/pkg/index.js': { cell: 'dependency directory', entry: { kind: 'file', content: () => JS } },
};

/**
 * Files the scan neither reads nor lists. Each is a defect in what the scan
 * reads, not in what it says, so it is left for a change to the walk and named
 * here so this test fails when that change lands:
 * - a config file inside a directory this user cannot search is dropped by an
 *   existence check that reads "cannot search" as "absent";
 * - a config file with a backslash in its name is opened under a path with `/`
 *   in place of the backslash, which does not exist, and is dropped the same way.
 */
const NEITHER_READ_NOR_LISTED = ['nosearch/config.json', '.env.back\\slash'];

const made: string[] = [];
function build(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'coverage-truth-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'coverage-truth-outside-'));
  made.push(root, outside);
  fs.writeFileSync(path.join(outside, 'config.json'), JSON_CONFIG);
  const entries = Object.entries(TREE);
  for (const [rel, { entry }] of entries) {
    const full = path.join(root, rel);
    if (entry.kind === 'file') {
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, entry.content());
    } else if (entry.kind === 'link') {
      fs.symlinkSync(entry.target === '<outside>' ? outside : entry.target, full);
    }
  }
  // Modes last: a directory without search permission cannot be filled.
  for (const [rel, { entry }] of entries) {
    if (entry.kind === 'file' && entry.mode !== undefined) fs.chmodSync(path.join(root, rel), entry.mode);
  }
  for (const [rel, { entry }] of entries) {
    if (entry.kind === 'dir-mode') fs.chmodSync(path.join(root, rel), entry.mode);
  }
  return root;
}

afterAll(() => {
  for (const dir of made) {
    for (const [rel, { entry }] of Object.entries(TREE)) {
      if (entry.kind === 'dir-mode') {
        try { fs.chmodSync(path.join(dir, rel), 0o755); } catch { /* not in this tree */ }
      }
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** Run from the scanned root, so a listed path prints as the path the JSON gives. */
async function run(root: string, json: boolean): Promise<{ out: string; code: number }> {
  const lines: string[] = [];
  vi.spyOn(process, 'cwd').mockReturnValue(root);
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  try {
    const code = await runScan(root, { json, maxFiles: CAP });
    // eslint-disable-next-line no-control-regex
    return { out: lines.join('\n').replace(/\x1b\[[0-9;]*m/g, ''), code };
  } finally {
    vi.restoreAllMocks();
  }
}

/** The one rule a listed name prints through, stated independently of the code under test. */
function rendered(rel: string): string {
  return hasDisplayHazard(rel) ? quotePathForDisplay(rel) : shellQuote(rel);
}

interface Doc {
  findings: Array<{ file: string; patternId: string }>;
  summary: { truncated: boolean; eligibleFiles: number; outOfRoot: number };
  unreadableFiles: string[];
  unreadableReasons?: Array<{ path: string; reason: string }>;
  outOfRootLinks: string[];
  oversizeFiles: Array<{ path: string }>;
  skippedUnsupportedFiles: Array<{ path: string; reason: string }>;
  notEnteredDirs: Array<{ path: string; reason: string }>;
  unscannedConfigFiles: string[];
}

/** The text report's coverage blocks: heading, listed lines, and the lines after them. */
interface Block { heading: string; items: string[]; rest: string[] }
function blocks(text: string): Block[] {
  return text.split(/\n\s*\n/).map((chunk) => {
    const lines = chunk.split('\n').filter((l) => l.trim() !== '');
    const items = lines.slice(1).filter((l) => /^ {4}\S/.test(l) && !/^ {4}… and \d+ more$/.test(l));
    const rest = lines.slice(1).filter((l) => !items.includes(l));
    return { heading: lines[0] ?? '', items, rest };
  });
}
function block(text: string, heading: RegExp): Block | undefined {
  return blocks(text).find((b) => heading.test(b.heading));
}

const HEADINGS = {
  unreadable: /^ {2}\d+ paths? could not be read/,
  outOfRoot: /outside the scan root/,
  oversize: /^ {2}\d+ files? skipped for size/,
  unscannedConfig: /^ {2}\d+ config files? not scanned/,
  dirs: /^ {2}\d+ director(y|ies) not entered/,
  files: /^ {2}\d+ files? not (opened|read for credentials)/,
};

/** The listed line for `rel`, or undefined: the rendered name, then the end, `: ` or ` (`. */
function lineFor(items: string[], rel: string): string | undefined {
  const head = `    ${rendered(rel)}`;
  return items.find((l) => l === head || l.startsWith(`${head}: `) || l.startsWith(`${head} (`));
}

const isKeyFile = (file: string) => /\.(pem|key|crt|p12|pfx|secretless-bundle)$/i.test(file);
const under = (file: string, dir: string) => file === dir || file.startsWith(`${dir}/`);

describe.skipIf(process.getuid?.() === 0)('every path scan lists as unread is a path it did not read, under a reason that holds for it', () => {
  let root: string;
  let text: string;
  let doc: Doc;

  beforeAll(async () => {
    root = build();
    text = (await run(root, false)).out;
    doc = JSON.parse((await run(root, true)).out) as Doc;
  });

  const findingFiles = () => new Set(doc.findings.map((f) => f.file));
  const unscannedConfigText = () => doc.skippedUnsupportedFiles.find((f) => doc.unscannedConfigFiles.includes(f.path))?.reason;
  const notOpenedFiles = () => [
    ...doc.skippedUnsupportedFiles.map((f) => f.path),
    ...doc.oversizeFiles.map((f) => f.path),
    ...doc.unscannedConfigFiles,
    ...doc.unreadableFiles,
  ];
  const notEnteredDirs = () => [...doc.notEnteredDirs.map((d) => d.path), ...doc.outOfRootLinks];

  it(`builds ${Object.keys(TREE).length} paths, one or more for each way a path goes unread`, () => {
    const cells = new Set(Object.values(TREE).map((t) => t.cell));
    for (const cell of [
      'hidden directory', 'ignore rule', 'size cap', '--max-files cap', 'binary file', 'unreadable mode',
      'unsearchable directory', 'broken link', 'link loop', 'link whose target lies under an unsearchable directory',
      'name with a control character', 'name with a backslash', 'non-ASCII name',
    ]) expect(cells, cell).toContain(cell);
    expect(Object.keys(TREE)).toHaveLength(37);
    // The control is read, so a missing finding below means the path, not the pattern.
    expect(findingFiles()).toContain('src/app.js');
  });

  it('yields no finding from a file it lists as not opened, and lists no file a finding came from', () => {
    const found = findingFiles();
    for (const p of notOpenedFiles()) {
      expect([...found].filter((f) => under(f, p)), `${p} is listed as not read`).toEqual([]);
    }
  });

  it('yields a finding from inside a directory it lists as not entered only when the reason says which files inside are still read', () => {
    const found = [...findingFiles()];
    for (const dir of notEnteredDirs()) {
      const inside = found.filter((f) => f.startsWith(`${dir}/`));
      const reason = doc.notEnteredDirs.find((d) => d.path === dir)?.reason ?? '';
      if (inside.length === 0) continue;
      expect(reason, `${dir}: findings from inside, ${inside.join(', ')}`).toMatch(/still read/);
      if (inside.some(isKeyFile)) expect(reason, dir).toMatch(/\bkey\b/);
      if (inside.some((f) => !isKeyFile(f))) expect(reason, dir).toMatch(/\bconfig\b/);
    }
  });

  it('says files inside a directory are still read only where a walk enters it', () => {
    const closed = new Set([...doc.outOfRootLinks, ...doc.unreadableFiles]);
    for (const d of doc.notEnteredDirs) {
      if (closed.has(d.path)) expect(d.reason, d.path).not.toMatch(/still read/);
    }
    // The three hidden directories, one per answer the filesystem gives.
    const reasonOf = (p: string) => doc.notEnteredDirs.find((d) => d.path === p)?.reason;
    expect(reasonOf('.hidden')).toMatch(/still read/);
    expect(reasonOf('.linked-hidden')).toMatch(/outside the scan root/);
    expect(reasonOf('.locked-hidden')).toMatch(/cannot open/);
  });

  it('prints every listed name through one rule, and the text lists exactly the paths --json lists', () => {
    const configNotListed = unscannedConfigText();
    const expected: Array<[keyof typeof HEADINGS, string[]]> = [
      ['unreadable', doc.unreadableFiles],
      ['outOfRoot', doc.outOfRootLinks],
      ['oversize', doc.oversizeFiles.map((f) => f.path)],
      ['unscannedConfig', doc.unscannedConfigFiles],
      ['dirs', doc.notEnteredDirs.map((d) => d.path)],
      // A config file off the list is listed once, in the block above.
      ['files', doc.skippedUnsupportedFiles.filter((f) => f.reason !== configNotListed).map((f) => f.path)],
    ];
    for (const [name, paths] of expected) {
      const b = block(text, HEADINGS[name]);
      expect(b, `${name} block`).toBeDefined();
      for (const p of paths) expect(lineFor(b!.items, p), `${name}: ${JSON.stringify(p)}`).toBeDefined();
      expect(b!.items, `${name}: no line beyond the --json list`).toHaveLength(paths.length);
    }
    // A listed reason prints as the --json gives it.
    const dirs = block(text, HEADINGS.dirs)!;
    for (const d of doc.notEnteredDirs) expect(dirs.items).toContain(`    ${rendered(d.path)}: ${d.reason}`);
    const files = block(text, HEADINGS.files)!;
    for (const f of doc.skippedUnsupportedFiles.filter((x) => x.reason !== configNotListed)) {
      expect(files.items).toContain(`    ${rendered(f.path)}: ${f.reason}`);
    }
    // The three hostile names are among them, each in its one rendering.
    for (const name of ['ctl\u001b[2Jname.txt', 'back\\slash.txt', 'naïve-ü.txt']) {
      expect(lineFor(files.items, name), name).toBeDefined();
    }
    expect(text).not.toContain('\u001b[2J');
  });

  it('gives each unreadable path the cause that holds for it, and names no cause it never lists', () => {
    const expected: Record<string, RegExp> = {
      'locked.js': /cannot read/,
      'locked-dir': /cannot list/,
      '.locked-hidden': /cannot list/,
      'nosearch/app.js': /cannot search/,
      'nosearch/server.key': /cannot search/,
      'nosearch/sub': /cannot search/,
      'loop-a.js': /loop/,
      'loop-b.js': /loop/,
      'into-nosearch.js': /cannot reach/,
    };
    expect([...doc.unreadableFiles].sort()).toEqual(Object.keys(expected).sort());
    const b = block(text, HEADINGS.unreadable)!;
    for (const [p, cause] of Object.entries(expected)) {
      const line = lineFor(b.items, p) ?? '';
      expect(line.slice(`    ${rendered(p)}`.length), `${p} in the text`).toMatch(cause);
      const json = doc.unreadableReasons?.find((r) => r.path === p);
      expect(json?.reason, `${p} in --json`).toMatch(cause);
      expect(line, p).toBe(`    ${rendered(p)}: ${json?.reason}`);
    }
    // `dangling.js` is a broken link: there is nothing behind it to read, and it is not listed.
    expect(doc.unreadableFiles).not.toContain('dangling.js');
    expect([b.heading, ...b.items, ...b.rest].join('\n')).not.toMatch(/broken/);
  });

  it('offers a chmod Fix only on a path chmod can change', () => {
    const b = block(text, HEADINGS.unreadable)!;
    for (const line of b.rest) {
      const m = /^ {2}Fix: +chmod \S+ (\S+)/.exec(line);
      if (!m) continue;
      const target = path.resolve(root, m[1]);
      // chmod follows a link and needs search permission on the parent: a path
      // stat cannot reach is a path chmod cannot change.
      expect(() => fs.statSync(target), `${m[1]} named by: ${line.trim()}`).not.toThrow();
    }
  });

  it('does not list a file it reads for its rules under a heading that says it was not opened', () => {
    const b = block(text, HEADINGS.files)!;
    expect(lineFor(b.items, '.secretlessignore')).toBeDefined();
    expect(b.heading).not.toMatch(/not opened/);
  });

  it('counts the out-of-root block by what it lists', () => {
    // Two links reach one directory outside the root, and one of them is listed.
    const b = block(text, HEADINGS.outOfRoot)!;
    expect(b.items).toHaveLength(1);
    const links = /^ {2}(\d+) symlinks? /.exec(b.heading);
    if (links) expect(Number(links[1]), b.heading).toBe(2);
    const dirs = /^ {2}(\d+) director(y|ies) outside the scan root/.exec(b.heading);
    if (dirs) expect(Number(dirs[1]), b.heading).toBe(1);
    expect(links ?? dirs, b.heading).not.toBeNull();
    expect(doc.summary.outOfRoot).toBe(1);
  });

  it('stops at the --max-files cap and says so, with no finding from the file past it', () => {
    expect(doc.summary.truncated).toBe(true);
    expect(doc.summary.eligibleFiles).toBe(SOURCE_ELIGIBLE);
    expect(findingFiles()).not.toContain('zz/zz/capped.js');
    expect(text).toContain(`Scan incomplete: stopped at the ${CAP}-file cap, so files were left unscanned.`);
  });

  it('reads or lists every planted file, apart from the files recorded as neither', () => {
    const found = findingFiles();
    const listed = [...notOpenedFiles(), ...notEnteredDirs()];
    const missing: string[] = [];
    for (const [rel, { entry }] of Object.entries(TREE)) {
      if (entry.kind !== 'file') continue;
      if (found.has(rel)) continue;
      if (listed.some((p) => under(rel, p))) continue;
      if (rel === 'zz/zz/capped.js' && doc.summary.truncated) continue;
      missing.push(rel);
    }
    expect(missing.sort()).toEqual([...NEITHER_READ_NOR_LISTED].sort());
  });
});
