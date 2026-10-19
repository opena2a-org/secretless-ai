/**
 * `init` registers the prompt check as a Claude Code UserPromptSubmit hook,
 * `status` reports it, and `init` then offers the transcript watcher (#237).
 *
 * HOME points at a scratch directory, so `status` reads a user-level settings
 * file the test wrote and `init` never touches the real home of whoever runs
 * the suite.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { init } from './init';
import { commandPrefixForHooks } from './hook-prefix';
import { status } from './status';
import { runInit } from './commands/core';
import { offerTranscriptWatcher } from './commands/transcript';
import type { InstallWatcherResult } from './watch';

const PROMPT_CHECK = `${commandPrefixForHooks()} hook --check-prompt`;
const SETTINGS = path.join('.claude', 'settings.json');

let dir: string;
let home: string;
let savedHome: string | undefined;

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-prompt-hook-'));
}

function settingsOf(project: string): any {
  return JSON.parse(fs.readFileSync(path.join(project, SETTINGS), 'utf-8'));
}

function writeSettings(project: string, settings: unknown): void {
  fs.mkdirSync(path.join(project, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(project, SETTINGS), JSON.stringify(settings, null, 2) + '\n');
}

function promptCommands(settings: any): string[] {
  return (settings.hooks?.UserPromptSubmit ?? []).flatMap((h: any) => h.hooks.map((hh: any) => hh.command));
}

/** Everything `fn` prints through console.log, in order. */
async function printed(fn: () => unknown): Promise<string[]> {
  const lines: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { lines.push(args.map(String).join(' ')); });
  try {
    await fn();
  } finally {
    log.mockRestore();
  }
  return lines;
}

beforeEach(() => {
  dir = tmpDir();
  home = tmpDir();
  savedHome = process.env.HOME;
  process.env.HOME = home;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(home, { recursive: true, force: true });
});

describe('init registers the prompt check as a UserPromptSubmit hook (#237)', () => {
  it('writes the pinned prefix before hook --check-prompt, once, and reports it added the first time', () => {
    const first = init(dir);
    expect(first.promptCheckAdded).toBe(true);
    expect(first.filesCreated).toContain('.claude/settings.json');
    expect(settingsOf(dir).hooks.UserPromptSubmit).toEqual([
      { matcher: '', hooks: [{ type: 'command', command: PROMPT_CHECK }] },
    ]);

    const again = init(dir);
    expect(again.promptCheckAdded).toBe(false);
    expect(again.filesModified).not.toContain('.claude/settings.json');
    expect(promptCommands(settingsOf(dir))).toEqual([PROMPT_CHECK]);
  });

  it('adds the check to an install made before it existed, and lists settings.json as modified', () => {
    init(dir);
    const settings = settingsOf(dir);
    delete settings.hooks.UserPromptSubmit;
    writeSettings(dir, settings);

    const result = init(dir);
    expect(result.promptCheckAdded).toBe(true);
    expect(result.filesModified).toContain('.claude/settings.json');
    expect(promptCommands(settingsOf(dir))).toEqual([PROMPT_CHECK]);
  });

  it("replaces an unpinned prompt-check command an earlier init wrote, and keeps the user's own hook", () => {
    writeSettings(dir, {
      hooks: {
        UserPromptSubmit: [
          { matcher: '', hooks: [{ type: 'command', command: 'npx secretless-ai hook --check-prompt' }] },
          { matcher: '', hooks: [{ type: 'command', command: '/usr/local/bin/my-own-prompt-hook' }] },
        ],
      },
    });

    const result = init(dir);
    expect(result.promptCheckAdded).toBe(false);
    expect(result.filesModified).toContain('.claude/settings.json');
    expect(promptCommands(settingsOf(dir))).toEqual([PROMPT_CHECK, '/usr/local/bin/my-own-prompt-hook']);
  });

  it('runInit names the added check when it is the only change to settings.json', async () => {
    init(dir);
    const settings = settingsOf(dir);
    delete settings.hooks.UserPromptSubmit;
    writeSettings(dir, settings);

    const lines = await printed(() => runInit(dir));
    expect(lines.map((l) => l.trim())).toContain('~ .claude/settings.json (added the prompt check hook)');
  });
});

describe('status reports the prompt check (#237)', () => {
  it('as installed at project scope after init, and not installed before', async () => {
    const before = await status(dir);
    expect(before.transcriptProtection.promptCheckInstalled).toBe(false);
    expect(before.transcriptProtection.promptCheckScope).toBeNull();

    init(dir);
    const after = await status(dir);
    expect(after.transcriptProtection.promptCheckInstalled).toBe(true);
    expect(after.transcriptProtection.promptCheckScope).toBe('project');
  });

  it('as installed at user scope from ~/.claude/settings.json', async () => {
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify({
      hooks: { UserPromptSubmit: [{ matcher: '', hooks: [{ type: 'command', command: PROMPT_CHECK }] }] },
    }));

    const result = await status(dir);
    expect(result.transcriptProtection.promptCheckInstalled).toBe(true);
    expect(result.transcriptProtection.promptCheckScope).toBe('user');
    expect(result.userSettings?.promptCheckInstalled).toBe(true);
    expect(result.userSettings?.secretlessInstalled).toBe(true);
  });
});

describe('init offers the transcript watcher (#237)', () => {
  const running: InstallWatcherResult = {
    running: true, alreadyRunning: false, pid: 4242, dirs: ['/srv/claude/projects'], launchAgent: true,
  };

  it('--no-watch leaves the watcher as it is without asking', async () => {
    const ask = vi.fn(async () => true);
    const lines = await printed(() => offerTranscriptWatcher({ noWatch: true, ask }));
    expect(ask).not.toHaveBeenCalled();
    expect(lines).toContain('  Transcript watcher left as it is (--no-watch).');
  });

  it('says a running watcher is running and what it watches, without asking', async () => {
    const ask = vi.fn(async () => true);
    const lines = await printed(() => offerTranscriptWatcher({
      ask,
      status: () => ({ running: true, pid: 1, dirs: [path.join(os.homedir(), '.claude', 'projects')] }),
    }));
    expect(ask).not.toHaveBeenCalled();
    expect(lines).toContain('  Transcript watcher running (watching ~/.claude/projects).');
  });

  it('names the install command when no transcript directory exists yet, without asking', async () => {
    const ask = vi.fn(async () => true);
    const lines = await printed(() => offerTranscriptWatcher({
      ask,
      status: () => ({ running: false, pid: null, dirs: [] }),
      exists: () => false,
    }));
    expect(ask).not.toHaveBeenCalled();
    expect(lines[0]).toContain('Transcript watcher not installed: no transcript directory yet.');
    expect(lines[1]).toBe('    Install it then: secretless-ai watch install');
  });

  it('with no terminal to ask on, names the install command', async () => {
    const lines = await printed(() => offerTranscriptWatcher({
      ask: async () => null,
      status: () => ({ running: false, pid: null, dirs: [] }),
      exists: () => true,
    }));
    expect(lines).toContain('  Transcript watcher not installed: no terminal to ask on. Install: secretless-ai watch install');
  });

  it('asks with yes as the default, and a no names the install command', async () => {
    const questions: string[] = [];
    const lines = await printed(() => offerTranscriptWatcher({
      ask: async (q) => { questions.push(q); return false; },
      status: () => ({ running: false, pid: null, dirs: [] }),
      exists: () => true,
    }));
    expect(questions).toHaveLength(1);
    expect(questions[0]).toContain('Install the transcript watcher?');
    expect(questions[0]).toContain('[Y/n]');
    expect(lines).toContain('  Transcript watcher not installed. Install later: secretless-ai watch install');
  });

  it('a yes installs it and reports what runs, now and at login', async () => {
    const install = vi.fn(async () => running);
    const lines = await printed(() => offerTranscriptWatcher({
      ask: async () => true,
      install,
      status: () => ({ running: false, pid: null, dirs: [] }),
      exists: () => true,
    }));
    expect(install).toHaveBeenCalledTimes(1);
    expect(lines[0]).toContain('Transcript watcher running (watching /srv/claude/projects)');
    expect(lines[1]).toContain('starts at each login');
  });

  it('an install that did not start says why and names the verify command', async () => {
    const lines = await printed(() => offerTranscriptWatcher({
      ask: async () => true,
      install: async () => ({ ...running, running: false, pid: null, launchAgent: false, reason: 'nothing to watch' }),
      status: () => ({ running: false, pid: null, dirs: [] }),
      exists: () => true,
    }));
    expect(lines[0]).toBe('  Transcript watcher not installed: nothing to watch.');
    expect(lines[1]).toBe('  Verify: secretless-ai watch status');
  });
});
