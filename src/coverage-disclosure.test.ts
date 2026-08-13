import { describe, it, expect, vi, afterEach } from 'vitest';
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
