import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * `status` reported a project whose only Secretless configuration is an
 * instruction file as `Protected`, the same word it prints for a project with
 * the Claude Code guard hook. An instruction file is advice: nothing enforces
 * it. `status --json` carries `enforcement`, which names the strongest
 * mechanism `isProtected` rests on, the human verdict line names the mode, and
 * `init` states the mode of every tool it configures.
 *
 * `init` and `status` also disagreed about an Aider project: `init` printed
 * `Configured: Aider` and `status` then printed `Not protected`, because
 * `status` never read the `.aiderignore` file `init` writes.
 *
 * The transcript and watcher modules are mocked and HOME is a scratch
 * directory, so the assertions are about the project, not about whatever is
 * in the home directory of whoever runs the suite.
 */

vi.mock('./transcript', () => ({
  discoverTranscripts: () => [],
  scanTranscriptFile: () => ({ findings: [], redacted: '' }),
}));

vi.mock('./watch', () => ({ isWatchRunning: () => false }));

import { status } from './status';
import { init } from './init';
import { runInit, runStatus } from './commands/core';
import { toolDisplayName, type AITool } from './detect';

let root: string;
let home: string;
let project: string;
let savedHome: string | undefined;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-enforcement-'));
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

/** A marker that makes `init` detect one tool, and only that tool. */
const MARKERS: Record<Exclude<AITool, 'claude-code'>, string> = {
  cursor: '.cursor',
  copilot: '.copilot',
  windsurf: '.windsurf',
  cline: '.cline',
  aider: '.aider.conf.yml',
};

function projectFor(tool: Exclude<AITool, 'claude-code'>): void {
  const marker = path.join(project, MARKERS[tool]);
  if (tool === 'aider') fs.writeFileSync(marker, '');
  else fs.mkdirSync(marker, { recursive: true });
}

function capture(): string[] {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
    lines.push(a.map(String).join(' ').replace(/\[[0-9;]*m/g, ''));
  });
  return lines;
}

async function statusJson(dir: string): Promise<any> {
  const lines = capture();
  await runStatus(dir, { json: true });
  vi.restoreAllMocks();
  return JSON.parse(lines.join('\n'));
}

async function statusText(dir: string): Promise<string[]> {
  const lines = capture();
  await runStatus(dir);
  vi.restoreAllMocks();
  return lines;
}

/** The line `status` prints under its Verdict heading. */
function verdictLine(lines: string[]): string {
  const heading = lines.findIndex(l => l.includes('── Verdict'));
  expect(heading, 'status printed no Verdict heading').toBeGreaterThanOrEqual(0);
  return lines[heading + 1].trim();
}

function initOutput(dir: string): string[] {
  const lines = capture();
  const code = runInit(dir);
  vi.restoreAllMocks();
  expect(code).toBe(0);
  return lines.map(l => l.trim());
}

const ADVISORY_TOOLS = ['cursor', 'copilot', 'windsurf', 'cline'] as const;

describe('status --json names the mechanism isProtected rests on', () => {
  it.each(ADVISORY_TOOLS)('reports advisory for a project configured only through an instruction file (%s)', async (tool) => {
    projectFor(tool);
    expect(init(project).toolsConfigured).toEqual([tool]);

    const doc = await statusJson(project);

    expect(doc.enforcement).toBe('advisory');
    // What CI consumers already gate on is unchanged.
    expect(doc.isProtected).toBe(true);
    expect(doc.summary.verdict).toBe('protected-warnings');
    expect(doc.configuredTools).toEqual([tool]);
  });

  it('reports hook for a project with the Claude Code guard hook', async () => {
    expect(init(project).toolsConfigured).toEqual(['claude-code']);

    const doc = await statusJson(project);

    expect(doc.enforcement).toBe('hook');
    expect(doc.isProtected).toBe(true);
  });

  it('reports hook when an instruction file sits beside the guard hook', async () => {
    fs.mkdirSync(path.join(project, '.claude'));
    projectFor('cursor');
    expect(init(project).toolsConfigured).toEqual(['claude-code', 'cursor']);

    expect((await statusJson(project)).enforcement).toBe('hook');
  });

  it('reports hook for a project covered only by user-level settings', async () => {
    init(home); // `secretless-ai init` run once from ~

    const doc = await statusJson(project);

    expect(doc.protectionScope).toBe('user');
    expect(doc.enforcement).toBe('hook');
  });

  it('deny patterns with no Secretless guard script leave an instruction-file project advisory', async () => {
    projectFor('windsurf');
    expect(init(project).toolsConfigured).toEqual(['windsurf']);
    fs.mkdirSync(path.join(project, '.claude'));
    fs.writeFileSync(path.join(project, '.claude', 'settings.json'), JSON.stringify({ permissions: { deny: ['Bash(rm -rf *)'] } }));

    const doc = await statusJson(project);

    expect(doc.hookInstalled).toBe(false);
    expect(doc.denyRuleCount).toBe(1);
    expect(doc.enforcement).toBe('advisory');
  });

  it('reports none for a project with no configuration', async () => {
    const doc = await statusJson(project);

    expect(doc.isProtected).toBe(false);
    expect(doc.enforcement).toBe('none');
  });

  it('reports none when isProtected is refused over an unreadable settings file', async () => {
    projectFor('windsurf');
    init(project);
    fs.mkdirSync(path.join(project, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(project, '.claude', 'settings.json'), '{ not json');

    const doc = await statusJson(project);

    expect(doc.isProtected).toBe(false);
    expect(doc.enforcement).toBe('none');
  });
});

describe('status verdict line names the mode', () => {
  it.each(ADVISORY_TOOLS)('does not print Protected for a project configured only through an instruction file (%s)', async (tool) => {
    projectFor(tool);
    init(project);

    const lines = await statusText(project);
    const verdict = verdictLine(lines);

    expect(verdict).not.toMatch(/protected/i);
    expect(verdict).toMatch(/^Advisory only: /);
    expect(verdict).toContain(toolDisplayName(tool));
    expect(verdict).toContain('nothing enforces');
    // The instruction file is listed, and not as an enforced control.
    expect(lines.join('\n')).toMatch(new RegExp(`✓ Tool instructions: ${toolDisplayName(tool)} \\(advisory, not enforced\\)`));
  });

  it('still prints Protected for a project with the Claude Code guard hook', async () => {
    init(project);

    expect(verdictLine(await statusText(project))).toMatch(/^Protected/);
  });

  it('still prints Protected when an instruction file sits beside the guard hook', async () => {
    fs.mkdirSync(path.join(project, '.claude'));
    projectFor('windsurf');
    init(project);

    expect(verdictLine(await statusText(project))).toMatch(/^Protected/);
  });
});

describe('status reads the guard wiring, not only the guard script', () => {
  // `init` writes the guard script and wires it into PreToolUse in
  // `.claude/settings.json`. Claude Code runs only what a settings file wires,
  // so a script whose entry was removed (another tool rewrote the file, or it
  // was edited by hand) enforces nothing. `status` read the script's existence
  // as the hook: `enforcement: hook`, a green hook row and `Protected`.
  const settingsPath = (): string => path.join(project, '.claude', 'settings.json');

  /** Rewrite the project settings without the guard entry, and optionally without the deny patterns. */
  function unwireGuard(opts: { keepDeny: boolean }): void {
    const settings = JSON.parse(fs.readFileSync(settingsPath(), 'utf-8'));
    delete settings.hooks.PreToolUse;
    if (!opts.keepDeny) delete settings.permissions;
    fs.writeFileSync(settingsPath(), JSON.stringify(settings, null, 2));
  }

  function hookRow(lines: string[]): string {
    const row = lines.find(l => /Claude Code (guard|hook)/.test(l));
    expect(row, 'status printed no Claude Code hook row').toBeDefined();
    return row!.trim();
  }

  beforeEach(() => {
    init(project);
    expect(fs.existsSync(path.join(project, '.claude', 'hooks', 'secretless-guard.sh'))).toBe(true);
  });

  it('reports hookWired for the settings init writes', async () => {
    const doc = await statusJson(project);

    expect(doc.hookInstalled).toBe(true);
    expect(doc.hookWired).toBe(true);
    expect(doc.enforcement).toBe('hook');
  });

  it('does not report hook for a guard script nothing runs', async () => {
    unwireGuard({ keepDeny: false });
    fs.rmSync(path.join(project, 'CLAUDE.md'));

    const doc = await statusJson(project);

    expect(doc.hookInstalled).toBe(true);
    expect(doc.hookWired).toBe(false);
    expect(doc.enforcement).toBe('none');
    // What CI consumers gate on is unchanged.
    expect(doc.isProtected).toBe(true);
    expect(doc.summary.verdict).toBe('protected-warnings');
  });

  it('does not report hook when the project settings file is gone', async () => {
    fs.rmSync(settingsPath());
    fs.rmSync(path.join(project, 'CLAUDE.md'));

    const doc = await statusJson(project);

    expect(doc.hookWired).toBe(false);
    expect(doc.enforcement).toBe('none');
  });

  it('the hook row and the verdict line say the guard is not run, and name init as the fix', async () => {
    unwireGuard({ keepDeny: false });
    fs.rmSync(path.join(project, 'CLAUDE.md'));

    const lines = await statusText(project);
    const row = hookRow(lines);
    const verdict = verdictLine(lines);

    expect(row).toMatch(/^⚠ /);
    expect(row).not.toContain('hook installed');
    expect(row).toContain('.claude/settings.json does not run it');
    expect(row.split('→')[1]?.trim()).toBe('secretless-ai init');
    expect(verdict).not.toMatch(/protected/i);
    expect(verdict).toMatch(/^Not enforced: /);
  });

  it('an unwired guard beside the CLAUDE.md block reads as advisory', async () => {
    unwireGuard({ keepDeny: false });

    const doc = await statusJson(project);
    const verdict = verdictLine(await statusText(project));

    expect(doc.configuredTools).toEqual(['claude-code']);
    expect(doc.enforcement).toBe('advisory');
    expect(verdict).toMatch(/^Advisory only: instructions for Claude Code/);
  });

  it('deny patterns Claude Code applies still count as enforced when the guard is not run', async () => {
    unwireGuard({ keepDeny: true });

    const doc = await statusJson(project);
    const lines = await statusText(project);

    expect(doc.hookWired).toBe(false);
    expect(doc.denyRuleCount).toBeGreaterThan(0);
    expect(doc.enforcement).toBe('hook');
    expect(hookRow(lines)).toMatch(/^⚠ .*deny patterns apply/);
    expect(verdictLine(lines)).toMatch(/^Protected/);
  });

  it('user-level settings that run this project\'s guard script count as wired', async () => {
    init(home); // wires "$CLAUDE_PROJECT_DIR"/.claude/hooks/secretless-guard.sh at user level
    unwireGuard({ keepDeny: false });

    const doc = await statusJson(project);
    const lines = await statusText(project);

    expect(doc.hookWired).toBe(false);
    expect(doc.userSettings.guardReachable).toBe(true);
    expect(doc.enforcement).toBe('hook');
    expect(hookRow(lines)).toMatch(/^✓ Claude Code hook installed at user level/);
  });

  it('running init again wires the guard, so the named fix changes the row', async () => {
    unwireGuard({ keepDeny: false });
    expect((await statusJson(project)).hookWired).toBe(false);

    init(project);

    const doc = await statusJson(project);
    expect(doc.hookWired).toBe(true);
    expect(doc.enforcement).toBe('hook');
    expect(hookRow(await statusText(project))).toMatch(/^✓ Claude Code hook installed \(/);
  });
});

describe('init and status agree about an Aider project', () => {
  beforeEach(() => { projectFor('aider'); });

  it('status lists Aider once init has written .aiderignore', async () => {
    expect(init(project).toolsConfigured).toEqual(['aider']);

    const s = await status(project);

    expect(s.configuredTools).toEqual(['aider']);
    expect(s.enforcement).toBe('ignore-file');
  });

  it('status does not list Aider before init', async () => {
    const s = await status(project);

    expect(s.configuredTools).toEqual([]);
    expect(s.enforcement).toBe('none');
  });

  it('status does not list Aider for an .aiderignore init did not write', async () => {
    fs.writeFileSync(path.join(project, '.aiderignore'), 'node_modules/\n');

    const s = await status(project);

    expect(s.configuredTools).toEqual([]);
    expect(s.enforcement).toBe('none');
  });

  it('the verdict line names the ignore file and does not print Not protected or a bare Protected', async () => {
    init(project);

    const lines = await statusText(project);
    const verdict = verdictLine(lines);

    expect(verdict).not.toMatch(/protected/i);
    expect(verdict).toMatch(/^Ignore file only: /);
    expect(verdict).toContain('.aiderignore');
    expect(lines.join('\n')).toContain('✓ Ignore file: Aider (.aiderignore, no hook enforces it)');
    expect(lines.join('\n')).not.toContain('Tool instructions');
  });

  it('status --json names the ignore file apart from the instruction files', async () => {
    projectFor('windsurf');
    init(project);

    const doc = await statusJson(project);

    expect([...doc.configuredTools].sort()).toEqual(['aider', 'windsurf']);
    expect(doc.ignoreFileTools).toEqual(['aider']);
    expect([...doc.detectedTools].sort()).toEqual(['aider', 'windsurf']);
  });

  it('status --json lists a detected tool init has not configured', async () => {
    const doc = await statusJson(project);

    expect(doc.detectedTools).toEqual(['aider']);
    expect(doc.configuredTools).toEqual([]);
    expect(doc.ignoreFileTools).toEqual([]);
  });

  it('an instruction file beside the ignore file is still listed as advisory', async () => {
    projectFor('windsurf');
    init(project);

    const lines = await statusText(project);

    expect((await status(project)).enforcement).toBe('ignore-file');
    expect(verdictLine(lines)).toMatch(/^Ignore file only: /);
    expect(lines.join('\n')).toContain('✓ Tool instructions: Windsurf (advisory, not enforced)');
  });
});

describe('status never names a fix that leaves the row as it is', () => {
  /** The `→ command` a row ends in. */
  function actionOf(lines: string[], label: RegExp): string {
    const row = lines.find(l => label.test(l));
    expect(row, `no row matches ${label}`).toBeDefined();
    return row!.split('→')[1]?.trim() ?? '';
  }

  it.each(['windsurf', 'aider'] as const)('in a %s project the hook rows name a command that installs the hook', async (tool) => {
    projectFor(tool);
    init(project);

    const lines = await statusText(project);
    const hookFix = actionOf(lines, /⚠ Claude Code hook not installed/);
    const stopFix = actionOf(lines, /⚠ Stop hook not installed/);

    // `init` configures the tools it detects, and Claude Code is not one of
    // them here, so a bare `secretless-ai init` installs neither hook.
    expect(init(project).toolsConfigured).not.toContain('claude-code');
    expect((await status(project)).hookInstalled).toBe(false);
    expect(hookFix).toBe('for Claude Code: mkdir -p .claude && secretless-ai init');
    expect(stopFix).toBe(hookFix);

    // The printed command, run: it installs both.
    fs.mkdirSync(path.join(project, '.claude'), { recursive: true });
    init(project);
    const after = await status(project);
    expect(after.hookInstalled).toBe(true);
    expect(after.transcriptProtection.stopHookInstalled).toBe(true);
    expect(after.enforcement).toBe('hook');
  });

  it('in a project with no tool detected the hook rows still name init, which installs it', async () => {
    const lines = await statusText(project);

    expect(actionOf(lines, /⚠ Claude Code hook not installed/)).toBe('secretless-ai init');
    expect(actionOf(lines, /⚠ Stop hook not installed/)).toBe('secretless-ai init');

    init(project);
    expect((await status(project)).hookInstalled).toBe(true);
  });

  it('a project init has not set up yet, with no Claude Code, is not told init installs hooks', async () => {
    projectFor('windsurf');

    const verdict = verdictLine(await statusText(project));

    expect(verdict).toMatch(/^Not protected\. /);
    expect(verdict).not.toContain('install hooks');
    expect(verdict).toContain('secretless-ai init');
  });
});

describe('init states the mode of every tool it configures', () => {
  it('names Claude Code as enforced', () => {
    const out = initOutput(project);

    expect(out).toContain('Configured: Claude Code (no AI tools detected — defaulted to Claude Code)');
    expect(out).toContain('Enforced: Claude Code (guard hook and deny patterns)');
    expect(out.some(l => l.startsWith('Advisory:') || l.startsWith('Ignore file:'))).toBe(false);
  });

  it.each(ADVISORY_TOOLS)('names an instruction file as advisory (%s)', (tool) => {
    projectFor(tool);

    const out = initOutput(project);

    expect(out).toContain(`Configured: ${toolDisplayName(tool)} (1 of 1 detected)`);
    expect(out).toContain(`Advisory: ${toolDisplayName(tool)} (instruction file, nothing enforces it)`);
    expect(out.some(l => l.startsWith('Enforced:'))).toBe(false);
  });

  it('names the Aider ignore file, and that no hook enforces it', () => {
    projectFor('aider');

    const out = initOutput(project);

    expect(out).toContain('Configured: Aider (1 of 1 detected)');
    expect(out).toContain('Ignore file: Aider (.aiderignore, no hook enforces it)');
    expect(out.some(l => l.startsWith('Enforced:'))).toBe(false);
  });

  it('prints one line per mode, in the order hook, ignore file, advisory', () => {
    fs.mkdirSync(path.join(project, '.claude'));
    projectFor('cursor');
    projectFor('windsurf');
    projectFor('aider');

    const out = initOutput(project);
    const modes = out.filter(l => /^(Enforced|Ignore file|Advisory):/.test(l));

    expect(modes).toEqual([
      'Enforced: Claude Code (guard hook and deny patterns)',
      'Ignore file: Aider (.aiderignore, no hook enforces it)',
      'Advisory: Cursor, Windsurf (instruction files, nothing enforces them)',
    ]);
  });

  // The samples are what a reader sees before running anything, so they show
  // the mode lines the run they describe prints, and no others.
  const MODE_LINE = /^(Enforced|Ignore file|Advisory):/;

  /** The mode lines of the fenced sample that holds `configured`. */
  function sampleModeLines(doc: string, configured: string): string[] {
    const text = fs.readFileSync(path.resolve(__dirname, '..', doc), 'utf-8');
    const sample = [...text.matchAll(/^```\w*\n([\s\S]*?)^```$/gm)]
      .map(m => m[1])
      .find(block => block.includes(configured));
    expect(sample, `${doc} no longer shows a sample init run with "${configured}"`).toBeDefined();
    return sample!.split('\n').map(l => l.trim()).filter(l => MODE_LINE.test(l));
  }

  it('the README quick start shows the mode line of a Claude Code project', () => {
    fs.mkdirSync(path.join(project, '.claude'));

    const out = initOutput(project);

    expect(out).toContain('Configured: Claude Code (1 of 1 detected)');
    expect(sampleModeLines('README.md', 'Configured: Claude Code (1 of 1 detected)'))
      .toEqual(out.filter(l => MODE_LINE.test(l)));
  });

  it('the protect-my-credentials use case shows the mode lines of a Claude Code and Cursor project', () => {
    fs.mkdirSync(path.join(project, '.claude'));
    projectFor('cursor');

    const out = initOutput(project);

    expect(out).toContain('Configured: Claude Code, Cursor (2 of 2 detected)');
    expect(sampleModeLines('docs/use-cases/protect-my-credentials.md', 'Configured: Claude Code, Cursor (2 of 2 detected)'))
      .toEqual(out.filter(l => MODE_LINE.test(l)));
  });

  it('prints no mode line when nothing was configured', () => {
    fs.mkdirSync(path.join(project, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(project, '.claude', 'settings.json'), '{ not json');

    const lines = capture();
    const code = runInit(project);
    vi.restoreAllMocks();

    expect(code).toBe(1);
    expect(lines.map(l => l.trim())).toContain('Configured: none');
    expect(lines.some(l => /^\s*(Enforced|Ignore file|Advisory):/.test(l))).toBe(false);
  });
});
