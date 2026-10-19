/**
 * The watcher covers every configured transcript directory and says which
 * (#237): the default follows CLAUDE_CONFIG_DIR, `--dir` adds directories, the
 * PID file names them for `status`, each redaction is shown as a desktop
 * notification that carries no value, and `watch install` starts the watcher
 * in the background.
 *
 * The PID-file readers are given their own file: the real one under HOME is
 * shared with watch.test.ts, which may run in another worker at the same time.
 * The CLI cases spawn the built entry point with a fresh HOME each, and stop
 * the watcher they started by its recorded pid.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { defaultTranscriptDir } from './transcript';
import {
  resolveWatchDirs, watchStatus, watchNotification, notificationCommand, installLaunchAgent, installWatcher,
} from './watch';
import type { TranscriptFinding } from './transcript';

const CLI = path.resolve(__dirname, '..', 'dist', 'cli.js');

const dirs: string[] = [];
const startedPids: number[] = [];
const savedConfigDir = process.env.CLAUDE_CONFIG_DIR;

function tmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-watch-dirs-'));
  dirs.push(dir);
  return dir;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function untilGone(pid: number, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (alive(pid) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
  return !alive(pid);
}

afterEach(async () => {
  if (savedConfigDir === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = savedConfigDir;
  for (const pid of startedPids.splice(0)) {
    try { process.kill(pid, 'SIGTERM'); } catch { /* already gone */ }
    if (!(await untilGone(pid, 5_000))) {
      try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
    }
  }
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('defaultTranscriptDir', () => {
  it('is projects/ under ~/.claude, or under CLAUDE_CONFIG_DIR where that is set', () => {
    expect(defaultTranscriptDir({})).toBe(path.join(os.homedir(), '.claude', 'projects'));
    expect(defaultTranscriptDir({ CLAUDE_CONFIG_DIR: '/srv/claude-conf' })).toBe(path.join('/srv/claude-conf', 'projects'));
    expect(defaultTranscriptDir({ CLAUDE_CONFIG_DIR: '   ' })).toBe(path.join(os.homedir(), '.claude', 'projects'));
  });
});

describe('resolveWatchDirs', () => {
  it('puts the default first, makes each extra directory absolute, and lists each once', () => {
    const byDefault = defaultTranscriptDir();
    expect(resolveWatchDirs(['/srv/a', 'rel/b', '/srv/a', byDefault])).toEqual([byDefault, '/srv/a', path.resolve('rel/b')]);
    expect(resolveWatchDirs()).toEqual([byDefault]);
  });
});

describe('watchStatus reads the directories from the PID file', () => {
  it('names the directories of a running watcher, none for a dead one or a legacy file', () => {
    const pidFile = path.join(tmpDir(), 'watch.pid');
    fs.writeFileSync(pidFile, JSON.stringify({ pid: process.pid, startedAt: Date.now(), dirs: ['/srv/claude/projects'] }));
    expect(watchStatus(pidFile)).toEqual({ running: true, pid: process.pid, dirs: ['/srv/claude/projects'] });

    fs.writeFileSync(pidFile, JSON.stringify({ pid: 99999999, startedAt: 0, dirs: ['/srv/claude/projects'] }));
    expect(watchStatus(pidFile)).toEqual({ running: false, pid: null, dirs: [] });

    fs.writeFileSync(pidFile, String(process.pid));
    expect(watchStatus(pidFile)).toEqual({ running: true, pid: process.pid, dirs: [] });
  });
});

describe('watchNotification', () => {
  const finding = (patternId: string, patternName: string): TranscriptFinding => ({
    file: '~/.claude/projects/p/s.jsonl', line: 1, jsonPath: '.message', patternId, patternName, preview: '',
  });

  it('counts the values, names each pattern once and the file, and the stored secrets exposed', () => {
    const findings = [finding('github-pat', 'GitHub Token'), finding('github-pat', 'GitHub Token'), finding('aws-access', 'AWS Access Key')];
    const notice = watchNotification(findings, '~/.claude/projects/p/s.jsonl', {
      marked: [{ name: 'GH', where: 'transcript ... (found by watch)' }],
      alreadyOpen: [{ name: 'AWS', exposedAt: '2026-10-01T00:00:00.000Z' }],
      failed: [],
    });
    expect(notice.title).toBe('Secretless');
    expect(notice.body).toBe(
      'Redacted 3 credentials (GitHub Token, AWS Access Key) in ~/.claude/projects/p/s.jsonl. '
      + 'Stored secrets GH, AWS exposed: rotate at the provider, then secret set.',
    );
    expect(watchNotification([finding('slack', 'Slack Token')], '~/t.jsonl').body).toBe('Redacted 1 credential (Slack Token) in ~/t.jsonl.');
  });
});

describe('notificationCommand', () => {
  it('runs osascript on macOS with the text as AppleScript strings, quotes and backslashes escaped', () => {
    expect(notificationCommand('darwin', 'Secretless', 'Redacted 1 credential in "s.jsonl" \\ done')).toEqual({
      command: 'osascript',
      args: ['-e', 'display notification "Redacted 1 credential in \\"s.jsonl\\" \\\\ done" with title "Secretless"'],
    });
  });

  it('runs notify-send on Linux, replaces control characters, and has no command elsewhere', () => {
    expect(notificationCommand('linux', 'Secretless', 'line one\nline two')).toEqual({
      command: 'notify-send', args: ['--app-name=Secretless', 'Secretless', 'line one?line two'],
    });
    expect(notificationCommand('win32', 'Secretless', 'body')).toBeNull();
  });
});

describe('installLaunchAgent', () => {
  it('writes the agent under the given home with each --dir, owner-only, and nothing off macOS', () => {
    const home = tmpDir();
    expect(installLaunchAgent({ dirs: ['/srv/extra <dir>'], homeDir: home, platform: 'darwin' })).toBe(true);
    const plistPath = path.join(home, 'Library', 'LaunchAgents', 'ai.secretless.watch.plist');
    const plist = fs.readFileSync(plistPath, 'utf-8');
    expect(plist).toContain(
      '    <string>watch</string>\n    <string>start</string>\n    <string>--dir</string>\n    <string>/srv/extra &lt;dir&gt;</string>',
    );
    expect(fs.statSync(plistPath).mode & 0o777).toBe(0o600);

    const other = tmpDir();
    expect(installLaunchAgent({ homeDir: other, platform: 'linux' })).toBe(false);
    expect(fs.existsSync(path.join(other, 'Library'))).toBe(false);
  });
});

describe('installWatcher starts nothing it cannot run, and says why', () => {
  it('with no transcript directory present', async () => {
    const home = tmpDir();
    process.env.CLAUDE_CONFIG_DIR = path.join(home, 'claude-conf');
    const result = await installWatcher({ dirs: [path.join(home, 'missing')], pidFile: path.join(home, 'watch.pid') });
    expect(result.running).toBe(false);
    expect(result.reason).toContain('no transcript directory to watch');
    expect(result.reason).toContain(path.join(home, 'claude-conf', 'projects'));
    expect(result.reason).toContain(path.join(home, 'missing'));
  });

  it('with a CLI script that is not a file', async () => {
    const home = tmpDir();
    process.env.CLAUDE_CONFIG_DIR = path.join(home, 'claude-conf');
    fs.mkdirSync(path.join(home, 'claude-conf', 'projects'), { recursive: true });
    const script = path.join(home, 'no-cli.js');
    const result = await installWatcher({ script, pidFile: path.join(home, 'watch.pid') });
    expect(result.running).toBe(false);
    expect(result.reason).toContain(script);
    expect(result.launchAgent).toBe(false);
  });
});

describe('watch install and watch start --dir (built CLI)', () => {
  beforeAll(() => {
    if (!fs.existsSync(CLI)) {
      throw new Error(`dist/cli.js is missing at ${CLI}; run \`npm run build\` first.`);
    }
  });

  function cli(args: string[], home: string): { status: number | null; stdout: string; stderr: string } {
    const res = spawnSync(process.execPath, [CLI, ...args], {
      cwd: home,
      env: { ...process.env, HOME: home, NO_COLOR: '1' },
      encoding: 'utf-8',
      timeout: 30_000,
    });
    return { status: res.status, stdout: res.stdout, stderr: res.stderr };
  }

  it('install starts a background watcher covering the default and each --dir, which status reports, and stop ends it', async () => {
    const home = tmpDir();
    fs.mkdirSync(path.join(home, '.claude', 'projects'), { recursive: true });
    const extra = path.join(home, 'extra');
    fs.mkdirSync(extra);

    const res = cli(['watch', 'install', '--dir', extra], home);
    const pidPath = path.join(home, '.secretless-ai', 'watch.pid');
    if (fs.existsSync(pidPath)) startedPids.push(JSON.parse(fs.readFileSync(pidPath, 'utf-8')).pid);
    expect(res.status, res.stdout + res.stderr).toBe(0);
    expect(res.stdout).toContain('Transcript watcher running (watching ~/.claude/projects, ~/extra)');
    if (process.platform === 'darwin') {
      expect(res.stdout).toContain('starts at each login');
      const plist = fs.readFileSync(path.join(home, 'Library', 'LaunchAgents', 'ai.secretless.watch.plist'), 'utf-8');
      expect(plist).toContain(`<string>${extra}</string>`);
    }

    expect(cli(['watch', 'status'], home).stdout).toContain('Watcher: running (watching ~/.claude/projects, ~/extra)');
    const json = JSON.parse(cli(['status', '--json'], home).stdout);
    expect(json.transcriptProtection.watcherRunning).toBe(true);
    expect(json.transcriptProtection.watcherDirs).toEqual([path.join(home, '.claude', 'projects'), extra]);

    const again = cli(['watch', 'install'], home);
    expect(again.status).toBe(0);
    expect(again.stdout).toContain('Transcript watcher already running');

    const pid = startedPids[0];
    expect(cli(['watch', 'stop'], home).stdout).toContain('Watcher stopped.');
    expect(await untilGone(pid, 10_000)).toBe(true);
  }, 60_000);

  it('start exits 1 when none of the directories exists, naming each', () => {
    const home = tmpDir();
    const missing = path.join(home, 'nope');
    const res = cli(['watch', 'start', '--dir', missing], home);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain(`Transcript directory not found: ${path.join(home, '.claude', 'projects')}`);
    expect(res.stderr).toContain(`Transcript directory not found: ${missing}`);
    expect(res.stderr).toContain('Watcher did not start');
  });
});
