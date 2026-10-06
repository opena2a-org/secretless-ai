import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * `init` run once from the home directory writes `~/.claude/settings.json`,
 * which Claude Code applies in every project. `status` read only the project's
 * own `.claude/settings.json`, so from any other project it reported
 * "Not protected" while the user-level deny patterns and Stop hook were in
 * effect there (#188).
 *
 * The transcript and watcher modules are mocked so the assertions are about
 * the settings scopes, not about whatever is in the operator's home directory.
 */

vi.mock('./transcript', () => ({
  discoverTranscripts: () => [],
  scanTranscriptFile: () => ({ findings: [], redacted: '' }),
}));

vi.mock('./watch', () => ({ isWatchRunning: () => false }));

import { status, USER_SETTINGS_PATH } from './status';
import { init } from './init';
import { runStatus } from './commands/core';

function writeUserSettings(home: string, settings: unknown): void {
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(home, '.claude', 'settings.json'), typeof settings === 'string' ? settings : JSON.stringify(settings));
}

describe('status reads user-level settings as a second scope', () => {
  let root: string;
  let home: string;
  let project: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-uscope-'));
    home = path.join(root, 'home');
    project = path.join(home, 'some', 'project');
    fs.mkdirSync(project, { recursive: true });
  });
  afterEach(() => { fs.rmSync(root, { recursive: true, force: true }); });

  it('reports a project covered by user-level hooks as protected, and says by which scope', async () => {
    init(home); // `secretless-ai init` run once from ~

    const s = await status(project, { homeDir: home });

    expect(s.hookInstalled).toBe(false); // the project has no install of its own
    expect(s.isProtected).toBe(true);
    expect(s.protectionScope).toBe('user');
    expect(s.userSettings).not.toBeNull();
    expect(s.userSettings!.path).toBe(USER_SETTINGS_PATH);
    expect(s.userSettings!.coversProject).toBe(true);
    expect(s.userSettings!.denyRuleCount).toBeGreaterThan(0);
    expect(s.transcriptProtection.stopHookInstalled).toBe(true);
    expect(s.transcriptProtection.stopHookScope).toBe('user');
  });

  it('does not claim the user-level guard runs where its script path resolves to nothing', async () => {
    // `init` wires the guard as "$CLAUDE_PROJECT_DIR"/.claude/hooks/..., so
    // from the user-level file it looks in THIS project, which has no script.
    init(home);

    const s = await status(project, { homeDir: home });

    expect(s.userSettings!.guardWired).toBe(true);
    expect(s.userSettings!.guardReachable).toBe(false);
  });

  it('counts a user-level guard that names a script under $HOME as running here', async () => {
    const script = path.join(home, '.claude', 'hooks', 'secretless-guard.sh');
    fs.mkdirSync(path.dirname(script), { recursive: true });
    fs.writeFileSync(script, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    writeUserSettings(home, {
      hooks: { PreToolUse: [{ matcher: 'Read', hooks: [{ type: 'command', command: '"$HOME"/.claude/hooks/secretless-guard.sh' }] }] },
    });

    const s = await status(project, { homeDir: home });

    expect(s.userSettings!.guardReachable).toBe(true);
    expect(s.isProtected).toBe(true);
    expect(s.protectionScope).toBe('user');
  });

  it('reserves not-protected for when neither scope has the hooks', async () => {
    const s = await status(project, { homeDir: home });

    expect(s.isProtected).toBe(false);
    expect(s.protectionScope).toBeNull();
    expect(s.userSettings).toBeNull();
  });

  it('does not count user-level deny rules that Secretless did not install', async () => {
    writeUserSettings(home, { permissions: { deny: ['Bash(rm -rf *)'] } });

    const s = await status(project, { homeDir: home });

    expect(s.userSettings!.secretlessInstalled).toBe(false);
    expect(s.userSettings!.coversProject).toBe(false);
    expect(s.isProtected).toBe(false);
  });

  it('does not claim coverage from a user-level file that does not parse', async () => {
    writeUserSettings(home, '{ "hooks": { "Stop": [ secretless-ai ] }');

    const s = await status(project, { homeDir: home });

    expect(s.userSettings!.unreadable).toBeDefined();
    expect(s.userSettings!.denyRuleCount).toBeNull();
    expect(s.userSettings!.coversProject).toBe(false);
    expect(s.isProtected).toBe(false);
  });

  it('prefers the project scope when both scopes are installed', async () => {
    init(home);
    init(project);

    const s = await status(project, { homeDir: home });

    expect(s.isProtected).toBe(true);
    expect(s.protectionScope).toBe('project');
    expect(s.transcriptProtection.stopHookScope).toBe('project');
  });

  it('reads the home directory settings once when status runs from home', async () => {
    init(home);

    const s = await status(home, { homeDir: home });

    expect(s.userSettings).toBeNull();
    expect(s.protectionScope).toBe('project');
  });
});

describe('status output for a project covered only by user-level hooks', () => {
  let root: string;
  let home: string;
  let project: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-uscope-'));
    home = path.join(root, 'home');
    project = path.join(home, 'some', 'project');
    fs.mkdirSync(project, { recursive: true });
    init(home);
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

  it('names the user-level scope instead of printing Not protected', async () => {
    const lines = capture();

    await runStatus(project);
    const out = lines.join('\n');

    expect(out).not.toContain('Not protected');
    expect(out).toContain(`User-level deny patterns apply (${USER_SETTINGS_PATH}`);
    expect(out).toContain(`Stop hook installed at user level (${USER_SETTINGS_PATH}`);
    expect(out).toContain(`Protected by user-level settings in ${USER_SETTINGS_PATH}`);
    // The guard is wired but does not run here; that stays a warning with a fix.
    expect(out).toMatch(/⚠ Claude Code hook not installed in this project .*→ secretless-ai init/);
  });

  it('carries the scope in --json', async () => {
    const lines = capture();

    await runStatus(project, { json: true });
    const doc = JSON.parse(lines.join('\n'));

    expect(doc.isProtected).toBe(true);
    expect(doc.protectionScope).toBe('user');
    expect(doc.hookInstalled).toBe(false);
    expect(doc.userSettings.coversProject).toBe(true);
    expect(doc.userSettings.unreadable).toBeNull();
    expect(doc.transcriptProtection.stopHookScope).toBe('user');
    expect(doc.summary.verdict).not.toBe('not-protected');
  });
});
