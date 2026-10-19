import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan, shellQuote } from './commands/core';
import { SOURCE_SKIP_REASONS } from './scan';

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
 * SOURCE walk blanket-pruned dot-directories while the config and key walks
 * deliberately did not. The source walk now enters them and prunes only the
 * hidden caches, build output and worktree directories named in `scan.ts`
 * (#144). A user reading a finding from inside `.claude/` alongside four
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

interface Finding { file: string; severity: string; confidenceTier: string }

describe('the summary discloses what was not looked at', () => {
  afterEach(() => vi.restoreAllMocks());

  async function scanned(dir: string) {
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    const code = await runScan(dir, { json: true });
    return { doc: JSON.parse(lines.join('\n')), code };
  }

  it('reads a source file in .claude/ like its byte-identical copy in src/, and does not list .claude (#144)', async () => {
    const dir = tree({
      'src/app.ts': `const t = "${TOKEN}";\n`,
      '.claude/agent.ts': `const t = "${TOKEN}";\n`,
      '.claude/settings.json': `{"env":{"GITHUB_TOKEN":"${TOKEN}"}}\n`,
    });
    const { doc, code } = await scanned(dir);

    // The pre-fix shape: a finding from inside `.claude/`, `.claude/agent.ts`
    // absent, and `.claude` listed as a directory not entered.
    const byFile = new Map<string, Finding>(doc.findings.map((f: Finding) => [f.file, f]));
    expect([...byFile.keys()].sort()).toEqual(['.claude/agent.ts', '.claude/settings.json', 'src/app.ts']);
    // A source file in a dot-directory is a source file: the same severity
    // and confidence tier as the copy in `src/`. The settings file is still a
    // config file.
    expect(byFile.get('.claude/agent.ts')!.severity).toBe('high');
    expect(byFile.get('.claude/agent.ts')!.confidenceTier).toBe(byFile.get('src/app.ts')!.confidenceTier);
    expect(byFile.get('.claude/settings.json')!.severity).toBe('critical');
    expect(doc.notEnteredDirs.map((d: { path: string }) => d.path)).not.toContain('.claude');
    expect(doc.summary.notEntered).toBe(0);
    expect(code).toBe(1);
  });

  it('CONTROL: the missed file IS detectable — the gap is coverage, not the pattern', async () => {
    const dir = tree({ '.claude/agent.ts': `const t = "${TOKEN}";\n` });
    const { doc } = await scanned(path.join(dir, '.claude'));
    expect(doc.findings.length).toBeGreaterThan(0);
  });

  it('gives the ignore rule as the reason for a hidden directory .secretlessignore covers', async () => {
    const dir = tree({
      '.github/workflows/config.yml': 'name: ci\n',
      '.secretlessignore': '.github/\n',
    });
    const { doc } = await scanned(dir);
    const github = doc.notEnteredDirs.find((d: { path: string }) => d.path === '.github');
    expect(github.reason).toBe('ignore rule (--no-ignore)');
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

  it('does not count a file the key walk opened as enumerated but not opened (#341)', async () => {
    // The bundle was a finding and also one of `skippedUnsupported`; the
    // certificate was read for a private key and listed as unopened too.
    const dir = tree({
      't.secretless-bundle': 'x\n',
      'cert.pem': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
    });
    const { doc, code } = await scanned(dir);
    expect(doc.summary.high).toBe(1);
    expect(doc.findings.map((f: { file: string }) => f.file)).toEqual(['t.secretless-bundle']);
    expect(doc.summary.skippedUnsupported).toBe(0);
    expect(doc.skippedUnsupportedFiles).toEqual([]);
    expect(code).toBe(1);
  });

  it('CONTROL: a key file the test-file rule keeps from the key walk is still counted', async () => {
    const dir = tree({ 'backup.test.secretless-bundle': 'x\n' });
    const { doc } = await scanned(dir);
    expect(doc.summary.high).toBe(0);
    expect(doc.summary.skippedUnsupported).toBe(1);
    expect(doc.skippedUnsupportedFiles).toEqual([
      { path: 'backup.test.secretless-bundle', reason: 'test file (--include-tests)' },
    ]);
  });
});

describe('the source walk enters dot-directories and prunes only hidden caches, build output and worktrees (#144)', () => {
  afterEach(() => vi.restoreAllMocks());

  const PLANTED = `const t = "${TOKEN}";\n`;

  async function scanned(dir: string, options?: Parameters<typeof runScan>[1]) {
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    const code = await runScan(dir, { ...options, json: true });
    return { doc: JSON.parse(lines.join('\n')), code };
  }

  it('reports a source file under .github/', async () => {
    const dir = tree({ '.github/scripts/x.js': PLANTED });
    const { doc, code } = await scanned(dir);
    expect(doc.findings.map((f: Finding) => [f.file, f.severity])).toEqual([['.github/scripts/x.js', 'high']]);
    expect(doc.summary.notEntered).toBe(0);
    expect(code).toBe(1);
  });

  it('reads a config-format file in a dot-directory with --include-config, and counts it as unscanned without', async () => {
    const dir = tree({
      'src/values.yaml': `token: ${TOKEN}\n`,
      '.claude/values.yaml': `token: ${TOKEN}\n`,
    });
    const without = await scanned(dir);
    expect(without.doc.findings).toEqual([]);
    expect(without.doc.summary.unscannedConfig).toBe(2);
    expect([...without.doc.unscannedConfigFiles].sort()).toEqual(['.claude/values.yaml', 'src/values.yaml']);

    const withFlag = await scanned(dir, { includeConfig: true });
    expect(withFlag.doc.findings.map((f: Finding) => f.file).sort()).toEqual(['.claude/values.yaml', 'src/values.yaml']);
    expect(withFlag.doc.summary.unscannedConfig).toBe(0);
  });

  it('leaves a source file in a pruned directory unreported, and lists the directory with its reason', async () => {
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      '.venv/x.py': PLANTED,
      '.next/x.js': PLANTED,
      '.worktrees/x/y.ts': PLANTED,
      '.yarn/cache/x.js': PLANTED,
      '.git/x.js': PLANTED,
    });
    const { doc, code } = await scanned(dir);
    expect(doc.findings).toEqual([]);
    expect(code).toBe(0);
    const reasons = Object.fromEntries(doc.notEnteredDirs.map((d: { path: string; reason: string }) => [d.path, d.reason]));
    expect(reasons).toEqual({
      '.git': SOURCE_SKIP_REASONS.gitMetadata,
      '.next': SOURCE_SKIP_REASONS.buildOutput,
      '.venv': SOURCE_SKIP_REASONS.buildOutput,
      '.worktrees': SOURCE_SKIP_REASONS.worktrees,
      '.yarn': SOURCE_SKIP_REASONS.hiddenCache,
    });
    // Nothing under `.git` is named in any list.
    expect(JSON.stringify(doc)).not.toContain('.git/x.js');
  });

  it('CONTROL: the planted value in each pruned directory is found when that directory is named', async () => {
    const dir = tree({ '.worktrees/x/y.ts': PLANTED, '.yarn/cache/x.js': PLANTED });
    for (const sub of ['.worktrees', '.yarn']) {
      const { doc } = await scanned(path.join(dir, sub));
      expect(doc.findings.length, sub).toBe(1);
    }
  });

  it('lists a dot-directory linked outside the root as a link not followed, not as a directory not entered', async () => {
    const outside = tree({ 'agent.ts': PLANTED });
    const dir = tree({ 'src/app.ts': 'export const x = 1;\n' });
    fs.symlinkSync(outside, path.join(dir, '.claude'), 'dir');
    const { doc, code } = await scanned(dir);
    expect(doc.findings).toEqual([]);
    expect(doc.outOfRootLinks).toEqual(['.claude']);
    expect(doc.notEnteredDirs).toEqual([]);
    expect(code).toBe(0);
  });

  it.skipIf(process.getuid?.() === 0)('lists a dot-directory this user cannot open as unreadable, not as a directory not entered', async () => {
    const dir = tree({ 'src/app.ts': 'export const x = 1;\n', '.locked/agent.ts': PLANTED });
    const locked = path.join(dir, '.locked');
    fs.chmodSync(locked, 0o000);
    try {
      const { doc, code } = await scanned(dir);
      expect(doc.unreadableFiles).toEqual(['.locked']);
      expect(doc.notEnteredDirs).toEqual([]);
      expect(code).toBe(1);
    } finally {
      fs.chmodSync(locked, 0o755);
    }
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
    // Quoted as the report quotes it: a temporary directory whose path holds a
    // space prints inside single quotes.
    const dir = tree({ 'big.js': 'export const x = 1;\n' });
    const big = path.join(dir, 'big.js');
    const out = await humanOutput(dir, path.parse(dir).root);

    expect(out).toContain(`Verify: head -c 4096 ${shellQuote(big)}`);
    expect(out).toContain(`npx secretless-ai scan ${shellQuote(dir)} --max-file-size`);
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

  // Run from the directory above the scanned tree, so a listed path reads
  // `<tree>/<name>` whatever the temporary directory's own path holds. From
  // anywhere else the path is absolute, and under a TMPDIR with a space in it an
  // absolute path prints shell-quoted, which no pattern below expects.
  async function report(target: string, options?: Parameters<typeof runScan>[1]) {
    const root = fs.statSync(target).isDirectory() ? target : path.dirname(target);
    vi.spyOn(process, 'cwd').mockReturnValue(path.dirname(root));
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runScan(target, options);
    // eslint-disable-next-line no-control-regex
    return { text: lines.join('\n').replace(/\x1b\[[0-9;]*m/g, ''), code };
  }

  it('discloses the unopened file and the command that scans it, with no pruned directory', async () => {
    const dir = tree({ 'notes.txt': `aws_access_key_id = ${AWS_KEY_ID}\n` });
    const { text, code } = await report(dir);

    expect(text).toContain('No hardcoded credentials found.');
    expect(text).toMatch(/1 file not read for credentials: declared boundaries, not findings\./);
    expect(text).toMatch(/notes\.txt: unsupported file type/);
    const scanOne = /Scan one: npx secretless-ai scan (\S+)/.exec(text.slice(text.indexOf('file not read for credentials')));
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
    expect(text).toContain('a\\e[2Jb.txt');
    // No runnable command is offered for a name the terminal cannot show as typed.
    expect(text).not.toMatch(/Scan one: npx secretless-ai scan .*a\\e/);
  });

  it('prints a control character in a skipped directory name in visible form, never raw', async () => {
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      'a\u001b[2Jb/.cache/app.ts': 'export const y = 2;\n',
    });
    const { text } = await report(dir);
    expect(text).not.toContain('\u001b[2J');
    expect(text).toMatch(/director(y|ies) not entered/);
    expect(text).toContain('a\\e[2Jb/.cache');
    // No runnable command is offered for a name the terminal cannot show as typed.
    expect(text).not.toMatch(/Scan one: npx secretless-ai scan .*a\\e/);
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
    expect(text).not.toMatch(/not read for credentials/);
  });

  it('does not call a hidden cache directory unentered while reporting a finding from inside it', async () => {
    const dir = tree({ '.cache/workflows/config.yml': `aws_access_key_id: ${AWS_KEY_ID}\n` });
    const { text, code } = await report(dir);

    expect(text).toContain('.cache/workflows/config.yml');
    expect(code).toBe(1);
    expect(text).toMatch(/1 directory not entered for source files: declared boundaries, not findings\./);
    expect(text).not.toMatch(/director(y|ies) not entered[:,]/);
    expect(text).toMatch(/\.cache: hidden cache or build output; config and key files inside are still read$/m);
  });

  it('CONTROL: a dot-directory outside the pruned set is entered, so the report lists no directory', async () => {
    const dir = tree({ '.github/workflows/config.yml': `aws_access_key_id: ${AWS_KEY_ID}\n` });
    const { text, code } = await report(dir);

    expect(text).toContain('.github/workflows/config.yml');
    expect(code).toBe(1);
    expect(text).not.toMatch(/not entered for source files/);
  });

  it('does not call a key file uncovered while reporting a finding from it', async () => {
    // The source walk does not read a `.crt` or an export bundle; the key walk
    // checks both and reports what they hold, so neither is listed as not
    // opened (#341). Generated at run time so the committed source never
    // carries a private key.
    const { privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const dir = tree({
      'app.js': 'const a = 1;\n',
      'server.crt': privateKey,
      'backup.secretless-bundle': 'not a real bundle\n',
    });
    const { text, code } = await report(dir);

    expect(text).toContain('PEM Private Key');
    expect(text).toMatch(/server\.crt:1$/m);
    expect(text).toContain('Secretless Encrypted Bundle');
    expect(text).toMatch(/backup\.secretless-bundle:1$/m);
    expect(code).toBe(1);
    expect(text).not.toMatch(/not read for credentials/);
    expect(text).not.toMatch(/unsupported file type/);
    expect(text).not.toContain('Scan one:');
    expect(text).not.toMatch(/not covered by the scan result/);
  });

  // Generated at run time so the committed source never carries a private key.
  function pemKey(): string {
    return crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    }).privateKey;
  }

  it('lists a key file an ignore rule keeps from every walk with that rule, not as an unsupported file type', async () => {
    // The key walk reads `kept.pem` and reports what it holds. It applies the
    // ignore rule too, so no walk opens `ignored.pem`, and the flag that would
    // is --no-ignore: "unsupported file type" named a type the key walk reads.
    const dir = tree({
      'app.js': 'const a = 1;\n',
      'ignored.pem': pemKey(),
      'kept.pem': pemKey(),
      '.secretlessignore': 'ignored.pem\n',
    });
    const { text, code } = await report(dir);

    expect(text).toMatch(/kept\.pem:1$/m);
    expect(text).not.toMatch(/ignored\.pem:1$/m);
    expect(code).toBe(1);
    expect(text).toMatch(/ignored\.pem: ignore rule \(--no-ignore\)$/m);
    expect(text).not.toMatch(/kept\.pem: /m);
  });

  it('CONTROL: --no-ignore, the flag that reason names, reads that key file', async () => {
    const dir = tree({ 'ignored.pem': pemKey(), '.secretlessignore': 'ignored.pem\n' });
    const { text, code } = await report(dir, { noIgnore: true });
    expect(text).toMatch(/ignored\.pem:1$/m);
    expect(code).toBe(1);
  });

  it('lists a key file the test-file rule keeps from every walk with that rule', async () => {
    const dir = tree({ 'app.js': 'const a = 1;\n', 'server.test.pem': pemKey() });
    const { text, code } = await report(dir);
    expect(text).toMatch(/server\.test\.pem: test file \(--include-tests\)$/m);
    expect(text).not.toMatch(/server\.test\.pem:1$/m);
    expect(code).toBe(0);
  });

  it('CONTROL: --include-tests, the flag that reason names, reads that key file', async () => {
    const dir = tree({ 'server.test.pem': pemKey() });
    const { text, code } = await report(dir, { includeTests: true });
    expect(text).toMatch(/server\.test\.pem:1$/m);
    expect(code).toBe(1);
  });

  it('lists a file of a type no walk reads as an unsupported file type, even when an ignore or test-file rule covers it', async () => {
    // The ignore-rule and test-file reasons are for key files, which the flag
    // they name reads. `--no-ignore` and `--include-tests` read neither of
    // these, and an ignore-rule reason would count `ignored.txt` as a path the
    // tree's own ignore file kept from the scan.
    const dir = tree({
      'app.js': 'const a = 1;\n',
      'ignored.txt': 'x\n',
      'notes.test.txt': 'x\n',
      '.secretlessignore': 'ignored.txt\n',
    });
    const { text, code } = await report(dir);

    expect(text).toMatch(/ignored\.txt: unsupported file type$/m);
    expect(text).toMatch(/notes\.test\.txt: unsupported file type$/m);
    expect(text).not.toMatch(/ignore rule \(--no-ignore\)|test file \(--include-tests\)/);
    expect(code).toBe(0);
  });

  it('lists a config file off the built-in list once, under the heading that says it is not known to be clean', async () => {
    // It was also listed under "files not opened: declared boundaries", with a
    // second `Scan one:` line for it.
    const dir = tree({ 'config.json': '{}\n', 'secrets.json': '{}\n', 'notes.txt': 'x\n' });
    const { text, code } = await report(dir);
    const base = path.basename(dir);

    expect(code).toBe(0);
    expect(text).toContain('1 config file not scanned: its name is not on the built-in config list, so not known to be clean.');
    expect(text).toContain(`\n    ${base}/secrets.json\n`);
    expect(text).toContain(`Scan one: npx secretless-ai scan ${base}/secrets.json`);
    expect(text.match(/secrets\.json/g)).toHaveLength(2);
    expect(text).toContain('1 file not read for credentials: declared boundaries, not findings.');
    expect(text).toMatch(/notes\.txt: unsupported file type$/m);
    expect(text).toContain(`Scan one: npx secretless-ai scan ${base}/notes.txt`);
  });

  it('CONTROL: a tree whose only unopened file is such a config file prints no "not read for credentials" block', async () => {
    const dir = tree({ 'config.json': '{}\n', 'secrets.json': '{}\n' });
    const { text } = await report(dir);
    expect(text).toContain('1 config file not scanned');
    expect(text).not.toMatch(/not read for credentials/);
    expect(text.match(/Scan one:/g)).toHaveLength(1);
  });

  it('names the other unopened files and offers one when config files sort ahead of them', async () => {
    // Twenty-one config files sort ahead of the two text files. With one
    // twenty-entry sample for both, the config files filled it, and the
    // heading for the text files printed with no name and no `Scan one:`.
    const files: Record<string, string> = { 'z1.txt': 'x\n', 'z2.txt': 'x\n' };
    for (let i = 0; i < 21; i++) files[`c${String(i).padStart(2, '0')}.json`] = '{}\n';
    const dir = tree(files);
    const base = path.basename(dir);
    const { text } = await report(dir);

    expect(text).toContain('21 config files not scanned');
    expect(text).not.toMatch(/c\d\d\.json: config file not on the built-in list/);
    const block = text.slice(text.indexOf('2 files not read for credentials'));
    expect(block.split('\n\n')[0].split('\n')).toEqual([
      '2 files not read for credentials: declared boundaries, not findings.',
      `    ${base}/z1.txt: unsupported file type`,
      `    ${base}/z2.txt: unsupported file type`,
      `  Scan one: npx secretless-ai scan ${base}/z1.txt`,
    ]);
  });

  it('samples the config files and the other unopened files apart, twenty of each, in --json too', async () => {
    const configs = Array.from({ length: 25 }, (_, i) => `c${String(i).padStart(2, '0')}.json`);
    const others = Array.from({ length: 25 }, (_, i) => `z${String(i).padStart(2, '0')}.txt`);
    const files: Record<string, string> = {};
    for (const f of configs) files[f] = '{}\n';
    for (const f of others) files[f] = 'x\n';
    const dir = tree(files);
    const base = path.basename(dir);

    const { text: json } = await report(dir, { json: true });
    const doc = JSON.parse(json);
    expect(doc.summary.skippedUnsupported).toBe(50);
    expect(doc.summary.unscannedConfig).toBe(25);
    const configNotListed = SOURCE_SKIP_REASONS.configNotListed;
    const sampled = doc.skippedUnsupportedFiles as Array<{ path: string; reason: string }>;
    expect(sampled.filter((f) => f.reason === configNotListed).map((f) => f.path)).toEqual(configs.slice(0, 20));
    expect(sampled.filter((f) => f.reason !== configNotListed).map((f) => f.path)).toEqual(others.slice(0, 20));

    vi.restoreAllMocks();
    const { text } = await report(dir);
    const block = text.slice(text.indexOf('25 files not read for credentials')).split('\n\n')[0].split('\n');
    expect(block.slice(1, 9)).toEqual(others.slice(0, 8).map((f) => `    ${base}/${f}: unsupported file type`));
    expect(block.slice(9)).toEqual(['    … and 17 more', `  Scan one: npx secretless-ai scan ${base}/z00.txt`]);
  });

  it('gives the ignore rule, not "still scanned", for a hidden directory an ignore rule covers', async () => {
    // `.golden/` is on the default ignore list, which the key and config walks
    // honor too: no walk enters it, so its config file is not read.
    const dir = tree({
      '.golden/config.yml': `aws_access_key_id: ${AWS_KEY_ID}\n`,
      'src/app.ts': 'export const x = 1;\n',
    });
    const { text, code } = await report(dir);

    expect(text).toContain('No hardcoded credentials found.');
    expect(code).toBe(0);
    expect(text).toMatch(/\.golden: ignore rule \(--no-ignore\)/);
    expect(text).not.toMatch(/still scanned/);
  });

  it('CONTROL: the command it prints for that directory finds the planted key', async () => {
    const dir = tree({ '.golden/config.yml': `aws_access_key_id: ${AWS_KEY_ID}\n` });
    const { text, code } = await report(path.join(dir, '.golden'));
    expect(text).toContain('config.yml:1');
    expect(code).toBe(1);
  });

  it('does not say "still scanned" for a hidden cache directory linked outside the root', async () => {
    // No walk follows a directory link out of the root, so the key and config
    // walks never read the config file behind `.cache`.
    const outside = tree({ 'config.json': `{"env":{"GITHUB_TOKEN":"${TOKEN}"}}\n` });
    const dir = tree({ 'src/app.ts': 'export const x = 1;\n' });
    fs.symlinkSync(outside, path.join(dir, '.cache'), 'dir');
    const { text, code } = await report(dir);

    expect(text).toContain('No hardcoded credentials found.');
    expect(text).toMatch(/1 directory outside the scan root is linked from inside it, so not followed\. One link to each:/);
    expect(code).toBe(0);
    expect(text).toMatch(/\.cache: hidden directory linked outside the scan root; nothing inside is read$/m);
    expect(text).not.toMatch(/still scanned/);
  });

  it.skipIf(process.getuid?.() === 0)('does not say "still scanned" for a hidden cache directory that cannot be read', async () => {
    const dir = tree({
      'src/app.ts': 'export const x = 1;\n',
      '.cache/config.yml': `aws_access_key_id: ${AWS_KEY_ID}\n`,
    });
    const locked = path.join(dir, '.cache');
    fs.chmodSync(locked, 0o000);
    try {
      const { text } = await report(dir);
      expect(text).toMatch(/1 path could not be read, so not known to be clean\./);
      expect(text).toMatch(/\.cache: hidden directory this user cannot open; nothing inside is read$/m);
      expect(text).not.toMatch(/still scanned/);
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });

  // The block's `Scan one:` line named the first listed directory, which on a
  // repository is `.git`, so it sent the user to a scan of git metadata (#399).
  // Each directory a user can act on sits under `x/`, so the walk lists it
  // after `.git` and `node_modules` and the order alone cannot pick it.
  function notEnteredBlock(text: string): string {
    const at = text.indexOf('not entered for source files');
    expect(at, text).toBeGreaterThan(-1);
    return text.slice(text.lastIndexOf('\n', at) + 1).split('\n\n')[0];
  }

  const NOT_OFFERED = {
    '.git/HEAD': 'ref: refs/heads/main\n',
    'node_modules/pkg/index.js': 'module.exports = {};\n',
    'dist/app.js': 'module.exports = {};\n',
    'src/app.ts': 'export const x = 1;\n',
  };

  it.each([
    ['a test directory', 'x/tests', SOURCE_SKIP_REASONS.testDir],
    ['a hidden cache directory', 'x/.cache', SOURCE_SKIP_REASONS.hiddenCache],
    ['a worktree directory', 'x/.worktrees', SOURCE_SKIP_REASONS.worktrees],
    ['an ignore-rule match', 'x/.golden', SOURCE_SKIP_REASONS.ignoreRule],
  ])('names %s in Scan one:, not .git or a dependency or build directory (#399)', async (_label, offered, reason) => {
    const dir = tree({ ...NOT_OFFERED, [`${offered}/a.ts`]: 'export {};\n' });
    const { text } = await report(dir);
    const block = notEnteredBlock(text);
    const base = path.basename(dir);

    expect(block).toContain(`${base}/.git: ${SOURCE_SKIP_REASONS.gitMetadata}`);
    expect(block).toContain(`${base}/node_modules: ${SOURCE_SKIP_REASONS.buildOutput}`);
    expect(block).toContain(`${base}/dist: ${SOURCE_SKIP_REASONS.buildOutput}`);
    expect(block).toContain(`${base}/${offered}: ${reason}`);
    const scanOne = block.split('\n').filter((l) => l.trimStart().startsWith('Scan one:'));
    expect(scanOne).toEqual([`  Scan one: npx secretless-ai scan ${base}/${offered}`]);
  });

  it('prints no Scan one: when only .git and dependency or build directories are listed (#399)', async () => {
    const dir = tree(NOT_OFFERED);
    const { text, code } = await report(dir);
    const block = notEnteredBlock(text);

    expect(block).toMatch(/^ {2}3 directories not entered for source files: declared boundaries, not findings\./);
    expect(block).toContain(`${path.basename(dir)}/.git: ${SOURCE_SKIP_REASONS.gitMetadata}`);
    expect(text).not.toContain('Scan one:');
    expect(code).toBe(0);
  });

  it('does not offer a hidden directory whose reason says nothing inside is read (#399)', async () => {
    const outside = tree({ 'a.ts': 'export {};\n' });
    const dir = tree(NOT_OFFERED);
    fs.symlinkSync(outside, path.join(dir, '.cache'), 'dir');
    const { text } = await report(dir);
    const block = notEnteredBlock(text);

    expect(block).toMatch(/\.cache: hidden directory linked outside the scan root; nothing inside is read$/m);
    expect(block).not.toContain('Scan one:');
  });

  it.skipIf(process.getuid?.() === 0)('does not offer a hidden directory this user cannot open (#399)', async () => {
    const dir = tree({ ...NOT_OFFERED, '.cache/a.ts': 'export {};\n' });
    const locked = path.join(dir, '.cache');
    fs.chmodSync(locked, 0o000);
    try {
      const { text } = await report(dir);
      const block = notEnteredBlock(text);
      expect(block).toMatch(/\.cache: hidden directory this user cannot open; nothing inside is read$/m);
      expect(block).not.toContain('Scan one:');
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });

  // The files block's `Scan one:` line named the first listed file, which on a
  // tree holding a `.git` file (as a linked worktree checkout does) and
  // `.gitignore` was `.git`, so it sent the user to a scan of git metadata
  // (#405). `a/.gitignore` shows the name is matched in any directory.
  function notReadBlock(text: string): string {
    const at = text.indexOf('not read for credentials');
    expect(at, text).toBeGreaterThan(-1);
    return text.slice(text.lastIndexOf('\n', at) + 1).split('\n\n')[0];
  }

  const GIT_FILES = {
    '.git': 'gitdir: /somewhere/.git/worktrees/x\n',
    '.gitignore': 'node_modules/\n',
    'a/.gitignore': 'dist/\n',
    'src/app.ts': 'export const x = 1;\n',
  };

  it('prints no Scan one: when only .git and .gitignore files are listed (#405)', async () => {
    const dir = tree(GIT_FILES);
    const { text, code } = await report(dir);
    const block = notReadBlock(text);
    const base = path.basename(dir);

    expect(block).toMatch(/^ {2}3 files not read for credentials: declared boundaries, not findings\./);
    expect(block).toContain(`${base}/.git: ${SOURCE_SKIP_REASONS.unsupportedType}`);
    expect(block).toContain(`${base}/.gitignore: ${SOURCE_SKIP_REASONS.unsupportedType}`);
    expect(block).toContain(`${base}/a/.gitignore: ${SOURCE_SKIP_REASONS.unsupportedType}`);
    expect(text).not.toContain('Scan one:');
    expect(code).toBe(0);
  });

  it('names a listed file other than .git or .gitignore in Scan one: (#405)', async () => {
    const dir = tree({ ...GIT_FILES, 'x/notes.txt': 'nothing here\n' });
    const { text } = await report(dir);
    const block = notReadBlock(text);
    const base = path.basename(dir);

    expect(block).toContain(`${base}/.git: ${SOURCE_SKIP_REASONS.unsupportedType}`);
    expect(block).toContain(`${base}/x/notes.txt: ${SOURCE_SKIP_REASONS.unsupportedType}`);
    const scanOne = block.split('\n').filter((l) => l.trimStart().startsWith('Scan one:'));
    expect(scanOne).toEqual([`  Scan one: npx secretless-ai scan ${base}/x/notes.txt`]);
  });

  // With `.git` and `.gitignore` passed over, the line named the next listed
  // file, `.secretlessignore` (the scanner's own ignore file) or
  // `.gitattributes` (#408). `a/.npmignore` shows an ignore file is matched
  // by its name in any directory.
  it.each([
    ['.secretlessignore', 'dist/\n'],
    ['.gitattributes', '* text=auto\n'],
    ['a/.npmignore', 'test/\n'],
  ])('prints no Scan one: when %s is listed beside .git and .gitignore (#408)', async (name, content) => {
    const dir = tree({
      '.git': 'gitdir: /somewhere/.git/worktrees/x\n',
      '.gitignore': 'node_modules/\n',
      [name]: content,
      'src/app.ts': 'export const x = 1;\n',
    });
    const { text, code } = await report(dir);
    const block = notReadBlock(text);
    const base = path.basename(dir);

    expect(block).toMatch(/^ {2}3 files not read for credentials: declared boundaries, not findings\./);
    expect(block).toContain(`${base}/${name}: ${SOURCE_SKIP_REASONS.unsupportedType}`);
    expect(text).not.toContain('Scan one:');
    expect(code).toBe(0);
  });

  it('passes over git metadata and ignore files and names .gitmodules in Scan one: (#408)', async () => {
    const dir = tree({
      '.dockerignore': 'node_modules\n',
      '.eslintignore': 'dist/\n',
      '.git': 'gitdir: /somewhere/.git/worktrees/x\n',
      '.gitattributes': '* text=auto\n',
      '.gitignore': 'node_modules/\n',
      '.gitkeep': '',
      '.gitmodules': '[submodule "x"]\n\tpath = x\n\turl = ../x.git\n',
      '.secretlessignore': 'dist/\n',
    });
    const { text } = await report(dir);
    const block = notReadBlock(text);
    const base = path.basename(dir);

    expect(block).toMatch(/^ {2}8 files not read for credentials: declared boundaries, not findings\./);
    // Every file listed before `.gitmodules` is passed over.
    const listedNames = block.split('\n').slice(1, 9).map((l) => l.trim().split(': ')[0]);
    expect(listedNames).toEqual(
      ['.dockerignore', '.eslintignore', '.git', '.gitattributes', '.gitignore', '.gitkeep', '.gitmodules', '.secretlessignore']
        .map((n) => `${base}/${n}`),
    );
    const scanOne = block.split('\n').filter((l) => l.trimStart().startsWith('Scan one:'));
    expect(scanOne).toEqual([`  Scan one: npx secretless-ai scan ${base}/.gitmodules`]);
  });
});
