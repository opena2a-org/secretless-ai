import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from './commands/core';

/**
 * What the scan did NOT look at, disclosed beside what it did.
 *
 * The defect this closes is not "a gap exists" — gaps are fine and declared.
 * It is that the summary ASSERTED full coverage while a gap existed, and on the
 * sharpest case it did so beside evidence pointing the other way:
 *
 *   findings: [".claude/settings.json", "src/app.ts"]
 *   summary : { truncated:false, unreadable:0, outOfRoot:0, oversize:0 }
 *
 * `.claude/agent.ts` — byte-identical to `src/app.ts` — was absent, because the
 * SOURCE walk blanket-prunes dot-directories while the config and key walks
 * deliberately do not (`scan.ts`, and the comment on the key walker says so
 * outright). A user reading a finding from inside `.claude/` alongside four
 * zeros concludes the directory was read. The disclosure has to sit where the
 * loss happens, or it endorses the wrong conclusion instead of qualifying it.
 *
 * These counters are NON-GATING by ruling: a declared boundary is not a broken
 * claim, and a count that is non-zero on every repository on earth cannot be an
 * exit condition.
 */

function tree(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'coverage-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

const TOKEN = ['ghp_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');

describe('the summary discloses what was not looked at', () => {
  afterEach(() => vi.restoreAllMocks());

  async function scanned(dir: string) {
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    const code = await runScan(dir, { json: true });
    return { doc: JSON.parse(lines.join('\n')), code };
  }

  it('names a pruned hidden directory instead of implying it was read', async () => {
    const dir = tree({
      'src/app.ts': `const t = "${TOKEN}";\n`,
      '.claude/agent.ts': `const t = "${TOKEN}";\n`,
      '.claude/settings.json': `{"env":{"GITHUB_TOKEN":"${TOKEN}"}}\n`,
    });
    const { doc } = await scanned(dir);

    // The pre-fix shape: a finding from inside `.claude/` and four zeros.
    const files = doc.findings.map((f: { file: string }) => f.file);
    expect(files).toContain('.claude/settings.json');
    expect(files).not.toContain('.claude/agent.ts');

    // The disclosure that stops that reading as full coverage.
    expect(doc.summary.notEntered).toBeGreaterThan(0);
    const dirs = doc.notEnteredDirs.map((d: { path: string }) => d.path);
    expect(dirs).toContain('.claude');
    const claude = doc.notEnteredDirs.find((d: { path: string }) => d.path === '.claude');
    expect(claude.reason).toMatch(/hidden/);
  });

  it('CONTROL: the missed file IS detectable — the gap is coverage, not the pattern', async () => {
    const dir = tree({ '.claude/agent.ts': `const t = "${TOKEN}";\n` });
    const { doc } = await scanned(path.join(dir, '.claude'));
    expect(doc.findings.length).toBeGreaterThan(0);
  });

  it('CONTROL: a tree with nothing to skip reports zero, so the counter is not a constant', async () => {
    const dir = tree({ 'src/app.ts': 'export const x = 1;\n' });
    const { doc, code } = await scanned(dir);
    expect(doc.summary.notEntered).toBe(0);
    expect(doc.summary.skippedUnsupported).toBe(0);
    expect(code).toBe(0);
  });

  it('counts a file it enumerated but did not open, with the reason', async () => {
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      'notes.md': `a token in prose: ${TOKEN}\n`,
      'logo.png': 'not really a png\n',
    });
    const { doc } = await scanned(dir);
    expect(doc.summary.skippedUnsupported).toBeGreaterThanOrEqual(2);
    const reasons = doc.skippedUnsupportedFiles.map((f: { reason: string }) => f.reason);
    expect(reasons.some((r: string) => /unsupported/.test(r))).toBe(true);
  });

  /**
   * The ruling that governs this field: a declared boundary is not a failure of
   * a claim the scanner made. Every repository contains a `.md` or a lockfile,
   * so a gating counter would be non-zero everywhere — not a signal, a constant,
   * and the largest breaking change in the release that is about honesty.
   */
  it('is NON-GATING: a clean tree with skips still exits 0', async () => {
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      'README.md': 'no credentials here\n',
      '.github/workflows/ci.yml': 'name: ci\n',
      'node_modules/pkg/index.js': 'module.exports = 1;\n',
    });
    const { doc, code } = await scanned(dir);
    expect(doc.summary.total).toBe(0);
    expect(doc.summary.notEntered).toBeGreaterThan(0);
    expect(doc.summary.skippedUnsupported).toBeGreaterThan(0);
    expect(code, 'a declared boundary must not gate CI').toBe(0);
  });

  it('CONTROL: the gaps that ARE broken claims still gate', async () => {
    // `unreadable` is the other class — we said we would read it and did not.
    // Without this the test above would pass against a build where nothing
    // gates at all.
    const dir = tree({ 'src/app.ts': `const t = "${TOKEN}";\n` });
    const { code } = await scanned(dir);
    expect(code).toBe(1);
  });

  it('reports `.git` as git metadata, not as build output', async () => {
    // It sits in the build-output set, so without an explicit arm the
    // disclosure named it wrongly. The set that skips is unchanged; a reason a
    // user cannot trust is worse than a count.
    const dir = tree({ 'src/app.ts': 'export const x = 1;\n', '.git/config': '[core]\n' });
    const { doc } = await scanned(dir);
    const git = doc.notEnteredDirs.find((d: { path: string }) => d.path === '.git');
    expect(git).toBeDefined();
    expect(git.reason).toMatch(/git metadata/);
  });

  it('counts a pruned directory ONCE, not once per walker', async () => {
    // Three walks share the traversal and all three prune `node_modules`. Only
    // the source walk discloses; if another opts in, this doubles.
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      'node_modules/pkg/index.js': 'module.exports = 1;\n',
    });
    const { doc } = await scanned(dir);
    const hits = doc.notEnteredDirs.filter((d: { path: string }) => d.path === 'node_modules');
    expect(hits).toHaveLength(1);
    expect(doc.summary.notEntered).toBe(1);
  });
});

describe('coverage-warning paths are printed so they run where they are pasted (#120)', () => {
  // The scan also reads the global configs under HOME (`~/.claude/CLAUDE.md`,
  // `~/.claude.json`, ...) before the tree, and the 8-byte cap below skips
  // every one that exists. On a machine that has them, `Verify:` named the
  // first of those instead of the fixture. The list is built from HOME when
  // the scanner loads, so each test loads it again under an empty HOME.
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'coverage-home-'));
    vi.stubEnv('HOME', home);
    vi.resetModules();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    fs.rmSync(home, { recursive: true, force: true });
  });

  // A file over the size cap is the warning that prints a path, a `Verify:`
  // and a `Fix:`; a tiny cap produces it without writing megabytes.
  async function humanOutput(dir: string, cwd: string): Promise<string> {
    const core = await import('./commands/core.js');
    const lines: string[] = [];
    vi.spyOn(process, 'cwd').mockReturnValue(cwd);
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    await core.runScan(dir, { maxFileSizeBytes: 8 });
    return lines.join('\n');
  }

  it('prints absolute paths when run from the filesystem root', async () => {
    // From `/` the cwd-relative form of `/tmp/x/big.js` is `tmp/x/big.js`:
    // runnable there, but it reads as a path under the current directory.
    const dir = tree({ 'big.js': 'export const x = 1;\n' });
    const big = path.join(dir, 'big.js');
    const out = await humanOutput(dir, path.parse(dir).root);

    expect(out).toContain(`Verify: head -c 4096 ${big}`);
    expect(out).toContain(`npx secretless-ai scan ${dir} --max-file-size`);
    expect(out).not.toContain(` ${path.relative(path.parse(dir).root, big)}`);
  });

  it('CONTROL: from a parent directory the path stays relative', async () => {
    const dir = tree({ 'big.js': 'export const x = 1;\n' });
    const out = await humanOutput(dir, path.dirname(dir));

    expect(out).toContain(`Verify: head -c 4096 ${path.join(path.basename(dir), 'big.js')}`);
  });
});

/**
 * The human report, on a tree where the ONLY boundary is a file.
 *
 * The file-count line used to live inside the directory block, so it printed
 * only when a directory was also pruned. A scratch directory holding one
 * `notes.txt` with a planted AWS access key id read "No hardcoded credentials
 * found." with nothing beside it: the key was never opened, and the report did
 * not say so. The JSON summary carried the count all along; the human report,
 * which is what a person reads, dropped it.
 */
describe('the human report names a file it did not open', () => {
  afterEach(() => vi.restoreAllMocks());

  // Assembled from parts so the committed source never carries the key shape.
  const AWS_KEY_ID = ['AK', 'IA', 'Q7XN3P2LMRT4VW8K'].join('');

  async function report(target: string) {
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runScan(target);
    // eslint-disable-next-line no-control-regex
    return { text: lines.join('\n').replace(/\x1b\[[0-9;]*m/g, ''), code };
  }

  it('discloses the unopened file and the command that scans it, with no pruned directory', async () => {
    const dir = tree({ 'notes.txt': `aws_access_key_id = ${AWS_KEY_ID}\n` });
    const { text, code } = await report(dir);

    expect(text).toContain('No hardcoded credentials found.');
    expect(text).toMatch(/1 file not opened — declared boundaries, not findings\./);
    expect(text).toMatch(/notes\.txt — unsupported file type/);
    const scanOne = /Scan one: npx secretless-ai scan (\S+)/.exec(text.slice(text.indexOf('file not opened')));
    expect(scanOne).not.toBeNull();
    expect(path.basename(scanOne![1])).toBe('notes.txt');
    expect(code, 'a declared boundary must not gate CI').toBe(0);
  });

  it('CONTROL: the command it prints finds the planted key', async () => {
    const dir = tree({ 'notes.txt': `aws_access_key_id = ${AWS_KEY_ID}\n` });
    const { text, code } = await report(path.join(dir, 'notes.txt'));
    expect(text).toContain('AWS Access Key');
    expect(text).toContain('notes.txt:1');
    expect(code).toBe(1);
  });

  it('prints a control character in a file name in visible form, never raw', async () => {
    const dir = tree({ 'src/app.ts': 'export const x = 1;\n' });
    const hostile = 'a\u001b[2Jb.txt';
    fs.writeFileSync(path.join(dir, hostile), 'nothing here\n');
    const { text } = await report(dir);
    expect(text).not.toContain('\u001b[2J');
    expect(text).toContain('a\\x1b[2Jb.txt');
    // No runnable command is offered for a name the terminal cannot show as typed.
    expect(text).not.toMatch(/Scan one: npx secretless-ai scan .*a\\x1b/);
  });

  it('prints a control character in a skipped directory name in visible form, never raw', async () => {
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      'a\u001b[2Jb/.cache/app.ts': 'export const y = 2;\n',
    });
    const { text } = await report(dir);
    expect(text).not.toContain('\u001b[2J');
    expect(text).toMatch(/director(y|ies) not entered/);
    expect(text).toContain('a\\x1b[2Jb/.cache');
    // No runnable command is offered for a name the terminal cannot show as typed.
    expect(text).not.toMatch(/Scan one: npx secretless-ai scan .*a\\x1b/);
  });

  it('CONTROL: an ordinary skipped directory is still offered as the command', async () => {
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      'b/.cache/app.ts': 'export const y = 2;\n',
    });
    const { text } = await report(dir);
    const block = text.slice(text.indexOf('not entered'));
    const scanOne = /Scan one: npx secretless-ai scan (\S+)/.exec(block);
    expect(scanOne).not.toBeNull();
    expect(scanOne![1].endsWith(path.join('b', '.cache'))).toBe(true);
  });

  it('CONTROL: a tree with nothing skipped prints no file block', async () => {
    const dir = tree({ 'src/app.ts': 'export const x = 1;\n' });
    const { text } = await report(dir);
    expect(text).not.toMatch(/not opened/);
  });

  it('does not call a hidden directory unentered while reporting a finding from inside it', async () => {
    const dir = tree({ '.github/workflows/config.yml': `aws_access_key_id: ${AWS_KEY_ID}\n` });
    const { text, code } = await report(dir);

    expect(text).toContain('.github/workflows/config.yml');
    expect(code).toBe(1);
    expect(text).toMatch(/1 directory not entered for source files — declared boundaries, not findings\./);
    expect(text).not.toMatch(/director(y|ies) not entered —/);
    expect(text).toMatch(/\.github — hidden directory; key files and config files recognized by name are still scanned/);
  });
});
