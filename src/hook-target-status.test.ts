import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * The Stop hook and the pre-commit hook name the node binary and CLI file of
 * the copy that installed them. Once that copy is gone, `status` printed
 * `✓ Stop hook installed` and `hook status` printed `Pre-commit hook:
 * installed` while every turn's cleaner and every commit failed. They now
 * name the missing file and the command that reinstalls the hook.
 *
 * The transcript and watcher modules are mocked so the assertions are about
 * the settings files, not about whatever is in the operator's home directory.
 */

vi.mock('./transcript', () => ({
  discoverTranscripts: () => [],
  scanTranscriptFile: () => ({ findings: [], redacted: '' }),
}));

vi.mock('./watch', () => ({ isWatchRunning: () => false }));

import { status, USER_SETTINGS_PATH } from './status';
import { runStatus } from './commands/core';
import { runHook } from './commands/git';

const quote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

/** What the Stop hook runs after the prefix. */
const STOP_TAIL = ' clean --last || echo "secretless-ai clean --last failed (exit $?)" >&2 || true';

/** A copy laid out like an installed package: package.json and dist/cli.js. */
function fakeCopy(root: string): string {
  fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'secretless-ai', version: '0.0.0' }));
  const script = path.join(root, 'dist', 'cli.js');
  fs.writeFileSync(script, '');
  return script;
}

/** The Stop hook command an `init` run from that copy wrote. */
function stopCommandFor(script: string): string {
  return `${quote(process.execPath)} ${quote(script)}${STOP_TAIL}`;
}

function writeStopHook(dir: string, command: string): void {
  fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), JSON.stringify({
    hooks: { Stop: [{ matcher: '', hooks: [{ type: 'command', command }] }] },
  }));
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

describe('status reports a Stop hook whose CLI file is gone', () => {
  let root: string;
  let home: string;
  let project: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-target-status-'));
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

  function capture(): string[] {
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    return lines;
  }

  it('in the project settings: installed, and the missing file named', async () => {
    const copyDir = path.join(root, 'cli-copy');
    const script = fakeCopy(copyDir);
    writeStopHook(project, stopCommandFor(script));

    let s = await status(project, { homeDir: home });
    expect(s.transcriptProtection.stopHookInstalled).toBe(true);
    expect(s.transcriptProtection.stopHookTargetMissing).toBeNull();

    fs.rmSync(copyDir, { recursive: true });
    s = await status(project, { homeDir: home });
    expect(s.transcriptProtection.stopHookInstalled).toBe(true);
    expect(s.transcriptProtection.stopHookScope).toBe('project');
    expect(s.transcriptProtection.stopHookTargetMissing).toBe(script);
  });

  it('in the user-level settings: installed, and the missing file named in both places', async () => {
    const script = path.join(root, 'gone', 'dist', 'cli.js');
    writeStopHook(home, stopCommandFor(script));

    const s = await status(project, { homeDir: home });
    expect(s.transcriptProtection.stopHookInstalled).toBe(true);
    expect(s.transcriptProtection.stopHookScope).toBe('user');
    expect(s.transcriptProtection.stopHookTargetMissing).toBe(script);
    expect(s.userSettings!.stopHookInstalled).toBe(true);
    expect(s.userSettings!.stopHookTargetMissing).toBe(script);
  });

  it('a Stop hook in the npx form has no file to miss', async () => {
    writeStopHook(project, `npm_config_offline=true npx --yes secretless-ai@0.23.1${STOP_TAIL}`);
    const s = await status(project, { homeDir: home });
    expect(s.transcriptProtection.stopHookInstalled).toBe(true);
    expect(s.transcriptProtection.stopHookTargetMissing).toBeNull();
  });

  it('prints a warning row naming the file and the fix, never the ✓ row', async () => {
    const script = path.join(root, 'gone', 'dist', 'cli.js');
    writeStopHook(project, stopCommandFor(script));
    const lines = capture();

    await runStatus(project);
    const out = lines.join('\n');

    expect(out).not.toContain('✓ Stop hook installed');
    expect(out).toMatch(new RegExp(`⚠ Stop hook installed, target missing: ${escapeRe(script)} \\(transcripts unredacted\\) +→ npx secretless-ai init`));
  });

  it('prints the user-level row with the fix that reaches the user-level file', async () => {
    const script = path.join(root, 'gone', 'dist', 'cli.js');
    writeStopHook(home, stopCommandFor(script));
    const lines = capture();

    await runStatus(project);
    const out = lines.join('\n');

    expect(out).not.toContain('✓ Stop hook installed');
    expect(out).toMatch(new RegExp(`⚠ Stop hook installed at user level \\(${escapeRe(USER_SETTINGS_PATH)}\\), target missing: ${escapeRe(script)} \\(transcripts unredacted\\) +→ npx secretless-ai init ~`));
  });

  it('carries the file in --json and counts the row as one more warning', async () => {
    const copyDir = path.join(root, 'cli-copy');
    const script = fakeCopy(copyDir);
    writeStopHook(project, stopCommandFor(script));

    const json = async (): Promise<any> => {
      const lines = capture();
      await runStatus(project, { json: true });
      vi.restoreAllMocks();
      return JSON.parse(lines.join('\n'));
    };

    const before = await json();
    expect(before.transcriptProtection.stopHookTargetMissing).toBeNull();

    fs.rmSync(copyDir, { recursive: true });
    const after = await json();
    expect(after.transcriptProtection.stopHookInstalled).toBe(true);
    expect(after.transcriptProtection.stopHookTargetMissing).toBe(script);
    expect(after.summary.warnings).toBe(before.summary.warnings + 1);
  });
});

describe('hook status reports a pre-commit hook whose CLI file is gone', () => {
  let root: string;

  beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-target-precommit-')); });
  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(root, { recursive: true, force: true });
  });

  function repoWithHook(script: string): string {
    const repo = path.join(root, 'repo');
    fs.mkdirSync(path.join(repo, '.git', 'hooks'), { recursive: true });
    // What `hook install` run from that copy wrote.
    fs.writeFileSync(
      path.join(repo, '.git', 'hooks', 'pre-commit'),
      `#!/bin/sh\n# secretless-ai pre-commit hook\n\n${quote(process.execPath)} ${quote(script)} scan-staged\n`,
      { mode: 0o755 },
    );
    return repo;
  }

  function hookStatus(repo: string): { code: number; out: string } {
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    const code = runHook(['status'], repo);
    vi.restoreAllMocks();
    return { code, out: lines.join('\n') };
  }

  it('says installed while the copy is there', () => {
    const repo = repoWithHook(fakeCopy(path.join(root, 'cli-copy')));
    const { code, out } = hookStatus(repo);
    expect(code).toBe(0);
    expect(out).toMatch(/Pre-commit hook: installed$/m);
    expect(out).not.toContain('target missing');
  });

  it('names the missing file, how to see it, and the command that reinstalls the hook', () => {
    const copyDir = path.join(root, 'cli-copy');
    const script = fakeCopy(copyDir);
    const repo = repoWithHook(script);
    fs.rmSync(copyDir, { recursive: true });

    const { code, out } = hookStatus(repo);
    expect(code).toBe(0);
    expect(out).not.toMatch(/Pre-commit hook: installed$/m);
    expect(out).toContain(`Pre-commit hook: installed, target missing: ${script}`);
    expect(out).toContain(`Verify: ls -l ${script}`);
    expect(out).toContain('Fix:    npx secretless-ai hook install');
  });
});
