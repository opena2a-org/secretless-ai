import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * `init` writes two scripts Claude Code executes: the PreToolUse guard and the
 * PostToolUse output check. `status` derived `✓ Claude Code hook installed`
 * from the guard's existence and its wiring and never read the output check,
 * so a guard edited to allow every read still reported installed. `init` then
 * restored an edited guard under the label `(refreshed to current version)`,
 * a cause it never checked, and the edit left no trace. Each script is now
 * compared, byte for byte, with the text this version writes.
 *
 * The transcript and watcher modules are mocked and HOME is a scratch
 * directory, so the assertions are about the files written here.
 */

vi.mock('./transcript', () => ({
  discoverTranscripts: () => [],
  scanTranscriptFile: () => ({ findings: [], redacted: '' }),
}));

vi.mock('./watch', () => ({ isWatchRunning: () => false }));

import { init, managedHookState } from './init';
import { status } from './status';
import { runInit, runStatus, STATUS_ALIGN_MAX } from './commands/core';
import { VERSION } from './commands/utils';

const GUARD = '.claude/hooks/secretless-guard.sh';
const OUTPUT_CHECK = '.claude/hooks/secretless-output-check.cjs';

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const sha256 = (bytes: Buffer): string => crypto.createHash('sha256').update(bytes).digest('hex');

/**
 * A ⚠ row and its action, as `status` lays them out: the action in the column
 * after the label, or on the line under it for a row wider than that column
 * is kept (#471).
 */
const warningRow = (label: string, action: string): RegExp =>
  `⚠ ${label}`.length <= STATUS_ALIGN_MAX
    ? new RegExp(`^  ⚠ ${escapeRe(label)} +→ ${escapeRe(action)}$`, 'm')
    : new RegExp(`^  ⚠ ${escapeRe(label)}\\n {4}→ ${escapeRe(action)}$`, 'm');

/** One line, `exit 0`, inserted after the shebang: the guard then allows every call. */
function weakenGuard(file: string): void {
  const text = fs.readFileSync(file, 'utf-8');
  const end = text.indexOf('\n') + 1;
  fs.writeFileSync(file, `${text.slice(0, end)}exit 0\n${text.slice(end)}`);
}

/** The output check with the first entry of its PATTERNS removed. */
function dropOnePattern(file: string): void {
  const text = fs.readFileSync(file, 'utf-8');
  const line = text.match(/^const PATTERNS = (.*);$/m);
  expect(line, 'the output check carries no PATTERNS line').not.toBeNull();
  const patterns = JSON.parse(line![1]) as unknown[];
  expect(patterns.length).toBeGreaterThan(1);
  // A function replacement, because a pattern source may hold `$&` or `$1`.
  fs.writeFileSync(file, text.replace(line![0], () => `const PATTERNS = ${JSON.stringify(patterns.slice(1))};`));
}

let root: string;
let home: string;
let project: string;
let savedHome: string | undefined;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-managed-hooks-'));
  home = path.join(root, 'home');
  project = path.join(root, 'project');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  savedHome = process.env.HOME;
  process.env.HOME = home;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  vi.restoreAllMocks();
  fs.rmSync(root, { recursive: true, force: true });
});

/** What a command prints through console.log, one entry per line. */
async function printed(run: () => number | Promise<number>): Promise<{ code: number; lines: string[] }> {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
    lines.push(...a.map(String).join(' ').split('\n'));
  });
  try {
    return { code: await run(), lines };
  } finally {
    vi.restoreAllMocks();
  }
}

const statusText = async (dir: string): Promise<string> =>
  (await printed(() => runStatus(dir))).lines.join('\n');

const statusJson = async (dir: string): Promise<any> =>
  JSON.parse((await printed(() => runStatus(dir, { json: true }))).lines.join('\n'));

describe('status compares the guard script with the one this version writes', () => {
  it('a guard with one inserted line reads differs, and no ✓ guard row is printed', async () => {
    init(project);
    const before = await statusJson(project);
    expect(before.guardScript).toBe('current');

    weakenGuard(path.join(project, GUARD));

    const s = await status(project, { homeDir: home });
    expect(s.guardScript).toBe('differs');

    const text = await statusText(project);
    expect(text).not.toMatch(/✓ Claude Code hook installed/);
    expect(text).toMatch(warningRow(
      `Claude Code guard script differs from the one secretless-ai ${VERSION} writes: ${GUARD}`,
      'secretless-ai init',
    ));
    expect(text).toMatch(/^ {2}Protected \(\d+ observations need attention\)$/m);

    // What a CI consumer gates on keeps its meaning, and the row is one more warning.
    const after = await statusJson(project);
    expect(after.guardScript).toBe('differs');
    expect(after.isProtected).toBe(true);
    expect(after.enforcement).toBe('hook');
    expect(after.hookInstalled).toBe(true);
    expect(after.hookWired).toBe(true);
    expect(after.summary.warnings).toBe(before.summary.warnings + 1);
  });

  it('a freshly generated guard and output check read current, in a second project with a rules file too', async () => {
    // The second project's guard carries its own rules, so a comparison that
    // loaded the rules some other way than init does would read differs there.
    const second = path.join(root, 'second');
    fs.mkdirSync(second);
    fs.writeFileSync(path.join(second, '.secretless-rules.yaml'), 'files:\n  - "*.vaultdata"\n');

    for (const dir of [project, second]) {
      init(dir);
      expect(managedHookState(path.join(dir, GUARD))).toBe('current');
      expect(managedHookState(path.join(dir, OUTPUT_CHECK))).toBe('current');

      const s = await status(dir, { homeDir: home });
      expect(s.guardScript).toBe('current');
      expect(s.outputCheck).toBe('current');

      const text = await statusText(dir);
      expect(text).toMatch(/^ {2}✓ Claude Code hook installed \(\.claude\/settings\.json/m);
      expect(text).toMatch(/^ {2}✓ Output check hook installed \(PostToolUse\)$/m);
      expect(text).not.toContain('differs from the one');
    }

    // The rules file is what separates the two guards.
    expect(fs.readFileSync(path.join(second, GUARD), 'utf-8')).toContain('vaultdata');
    expect(fs.readFileSync(path.join(project, GUARD), 'utf-8')).not.toContain('vaultdata');
    expect(fs.readFileSync(path.join(second, OUTPUT_CHECK)).equals(fs.readFileSync(path.join(project, OUTPUT_CHECK)))).toBe(true);
  });

  it('a rules file that cannot be loaded reads unreadable, never current', async () => {
    init(project);
    // A pattern character the loader refuses, written after init.
    fs.writeFileSync(path.join(project, '.secretless-rules.yaml'), 'files:\n  - "creds;rm"\n');

    expect(managedHookState(path.join(project, GUARD))).toBe('unreadable');
    expect((await status(project, { homeDir: home })).guardScript).toBe('unreadable');

    const text = await statusText(project);
    expect(text).not.toMatch(/✓ Claude Code hook installed/);
    // Wider than the column, so the action is on the line under it (#471).
    expect(text).toMatch(/^ {2}⚠ Claude Code guard script could not be compared: Invalid patterns in \.secretless-rules\.yaml .*\n {4}→ secretless-ai init$/m);
  });

  it('rules added after init make the guard differ until init runs again', async () => {
    init(project);
    fs.writeFileSync(path.join(project, '.secretless-rules.yaml'), 'files:\n  - "*.vaultdata"\n');
    expect(managedHookState(path.join(project, GUARD))).toBe('differs');

    init(project);
    expect(managedHookState(path.join(project, GUARD))).toBe('current');
  });

  it('a guard that is not there reads missing', () => {
    expect(managedHookState(path.join(project, GUARD))).toBe('missing');
    expect(managedHookState(path.join(project, OUTPUT_CHECK))).toBe('missing');
  });

  it('applies the same states to the guard the user-level settings run', async () => {
    init(home);
    // Run the guard in the home directory from every project.
    const userSettingsPath = path.join(home, '.claude', 'settings.json');
    const settings = JSON.parse(fs.readFileSync(userSettingsPath, 'utf-8'));
    settings.hooks.PreToolUse[0].hooks[0].command = '"$HOME"/.claude/hooks/secretless-guard.sh';
    fs.writeFileSync(userSettingsPath, JSON.stringify(settings, null, 2));

    let s = await status(project, { homeDir: home });
    expect(s.userSettings!.guardReachable).toBe(true);
    expect(s.userSettings!.guardScript).toBe('current');
    expect(await statusText(project)).toMatch(/^ {2}✓ Claude Code hook installed at user level/m);

    weakenGuard(path.join(home, GUARD));

    s = await status(project, { homeDir: home });
    expect(s.userSettings!.guardScript).toBe('differs');
    expect(s.enforcement).toBe('hook');
    const text = await statusText(project);
    expect(text).not.toMatch(/✓ Claude Code hook installed/);
    expect(text).toMatch(warningRow(
      `Claude Code guard script differs from the one secretless-ai ${VERSION} writes: ~/${GUARD}`,
      'secretless-ai init ~',
    ));
  });
});

describe('status reads the output check', () => {
  it('an output check with one pattern removed reads differs, with a row naming the file', async () => {
    init(project);
    dropOnePattern(path.join(project, OUTPUT_CHECK));

    const s = await status(project, { homeDir: home });
    expect(s.outputCheck).toBe('differs');
    expect(s.guardScript).toBe('current');

    const text = await statusText(project);
    expect(text).not.toContain('✓ Output check hook installed');
    expect(text).toMatch(warningRow(
      `Output check hook differs from the one secretless-ai ${VERSION} writes (its credential patterns may be out of date): ${OUTPUT_CHECK}`,
      'secretless-ai init',
    ));
    // The guard row reads the guard, which is unchanged.
    expect(text).toMatch(/^ {2}✓ Claude Code hook installed \(/m);
    expect((await statusJson(project)).outputCheck).toBe('differs');
  });

  it('settings that run no output check get the not-installed row', async () => {
    init(project);
    const settingsPath = path.join(project, '.claude', 'settings.json');
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    delete settings.hooks.PostToolUse;
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));

    expect((await status(project, { homeDir: home })).outputCheck).toBe('missing');
    const text = await statusText(project);
    expect(text).not.toContain('✓ Output check hook installed');
    expect(text).toMatch(warningRow('Output check hook not installed', 'secretless-ai init'));
  });
});

describe('init replaces a generated hook that differs, says so and keeps a copy', () => {
  const replacedDir = (): string => path.join(home, '.secretless-ai', 'replaced');

  /** The three lines init prints for a replaced hook, from the `~` line on. */
  function reportFor(lines: string[], file: string): string[] {
    const at = lines.findIndex(l => l.startsWith(`    ~ ${file} `));
    expect(at, `init printed no ~ line for ${file}`).toBeGreaterThanOrEqual(0);
    return lines.slice(at, at + 3);
  }

  for (const { file, name, edit } of [
    { file: GUARD, name: 'guard', edit: weakenGuard },
    { file: OUTPUT_CHECK, name: 'output check', edit: dropOnePattern },
  ]) it(`the ${name}: three lines, and a 0600 copy of the replaced bytes in a 0700 directory`, async () => {
    init(project);
    const target = path.join(project, file);
    const fresh = fs.readFileSync(target);
    edit(target);
    const digest = sha256(fs.readFileSync(target));

    const { code, lines } = await printed(() => runInit(project));
    expect(code).toBe(0);
    expect(lines.join('\n')).not.toContain('refreshed to current version');

    const [replaced, previous, gitLog] = reportFor(lines, file);
    expect(replaced).toBe(`    ~ ${file} (replaced: it differed from the ${name} secretless-ai ${VERSION} writes)`);
    const copyLine = previous.match(
      new RegExp(`^ {6}previous copy: ~/\\.secretless-ai/replaced/(\\d{8}T\\d{6}Z-${escapeRe(path.basename(file))}) \\(sha256 ([0-9a-f]{12})\\)$`),
    );
    expect(copyLine, previous).not.toBeNull();
    expect(copyLine![2]).toBe(digest.slice(0, 12));
    expect(gitLog).toBe(`      if you did not change this file: git log -p -- ${file}`);

    // The control is restored, and the replaced bytes are kept.
    expect(fs.readFileSync(target).equals(fresh)).toBe(true);
    expect(fs.readdirSync(replacedDir())).toEqual([copyLine![1]]);
    const copy = path.join(replacedDir(), copyLine![1]);
    expect(sha256(fs.readFileSync(copy))).toBe(digest);
    expect(fs.statSync(replacedDir()).mode & 0o777).toBe(0o700);
    expect(fs.statSync(copy).mode & 0o777).toBe(0o600);
  });

  it('when the copy cannot be written, it says so and restores the guard anyway', async () => {
    init(project);
    const target = path.join(project, GUARD);
    const fresh = fs.readFileSync(target);
    weakenGuard(target);
    const digest = sha256(fs.readFileSync(target));
    // A file where the directory would go.
    fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
    fs.writeFileSync(replacedDir(), '');

    const { code, lines } = await printed(() => runInit(project));
    expect(code).toBe(0);

    const [replaced, previous] = reportFor(lines, GUARD);
    expect(replaced).toContain('(replaced: it differed from the guard');
    expect(previous).toMatch(new RegExp(`^ {6}previous copy not kept: .+ \\(sha256 ${digest.slice(0, 12)}\\)$`));
    expect(fs.readFileSync(target).equals(fresh)).toBe(true);
  });

  it('a current hook is not replaced and nothing is copied', async () => {
    init(project);

    const { lines } = await printed(() => runInit(project));
    expect(lines.join('\n')).not.toContain('replaced:');
    expect(fs.existsSync(replacedDir())).toBe(false);
  });
});
