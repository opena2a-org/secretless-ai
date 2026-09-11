/**
 * SLS-05.AC3: the built CLI's `hook --check-only` as Claude Code runs it.
 *
 * Every cell spawns `node dist/cli.js hook --check-only` with HOME set to a
 * fresh temporary directory, so the session file (~/.secretless-ai/session.json)
 * and the broker pid file live under that HOME and nothing touches the
 * developer's real session. The session file is written by a child process
 * under the same HOME because its HMAC key is derived from os.homedir().
 *
 * A missing dist/cli.js is a test ERROR naming `npm run build`, never a skip:
 * this suite exists to prove the shipped binary, not the source.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { pathToFileURL } from 'url';

const ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const SESSION_STATE = path.join(ROOT, 'dist', 'session', 'session-state.js');

const EXPECTED_DENY_PREFIX =
  '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"';

const homes: string[] = [];

function freshHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-cli-'));
  homes.push(home);
  return home;
}

afterEach(() => {
  while (homes.length > 0) {
    fs.rmSync(homes.pop()!, { recursive: true, force: true });
  }
});

/** Write a session file under HOME from a child process, so the HMAC key matches that HOME. */
function writeSessionUnder(home: string, ttlSeconds: number): void {
  const script = `import(${JSON.stringify(pathToFileURL(SESSION_STATE).href)}).then((m) => { m.writeSessionState(${ttlSeconds}); });`;
  const res = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, HOME: home },
    encoding: 'utf-8',
  });
  if (res.status !== 0) {
    throw new Error(`could not write the session fixture under ${home}: ${res.stderr}`);
  }
  const file = path.join(home, '.secretless-ai', 'session.json');
  if (!fs.existsSync(file)) {
    throw new Error(`session fixture was not written at ${file}`);
  }
}

function runHook(home: string): { status: number | null; stdout: string; stderr: string } {
  const res = spawnSync(process.execPath, [CLI, 'hook', '--check-only'], {
    env: { ...process.env, HOME: home },
    encoding: 'utf-8',
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

function parseDenyLine(stdout: string): { reason: string } {
  const lines = stdout.split('\n').filter((l) => l.length > 0);
  expect(lines, 'stdout carries exactly one line').toHaveLength(1);
  expect(lines[0].startsWith(EXPECTED_DENY_PREFIX)).toBe(true);
  const parsed = JSON.parse(lines[0]);
  expect(Object.keys(parsed)).toEqual(['hookSpecificOutput']);
  expect(Object.keys(parsed.hookSpecificOutput)).toEqual([
    'hookEventName',
    'permissionDecision',
    'permissionDecisionReason',
  ]);
  return { reason: parsed.hookSpecificOutput.permissionDecisionReason };
}

describe('secretless-ai hook --check-only (built CLI, SLS-05.AC3)', () => {
  beforeAll(() => {
    if (!fs.existsSync(CLI) || !fs.existsSync(SESSION_STATE)) {
      throw new Error(`dist/cli.js is missing at ${CLI}; run \`npm run build\` before this suite`);
    }
  });

  it('expired session: exit 2, the deny JSON on stdout, the reason on stderr', async () => {
    const home = freshHome();
    writeSessionUnder(home, 1);
    await new Promise((resolve) => setTimeout(resolve, 1500));

    const res = runHook(home);
    expect(res.status).toBe(2);
    const { reason } = parseDenyLine(res.stdout);
    expect(reason).toMatch(/expired/);
    // No broker runs under a fresh HOME, so the reason names `broker start` before `warm`.
    expect(reason).toContain('secretless-ai broker start');
    expect(reason.indexOf('secretless-ai broker start')).toBeLessThan(reason.indexOf('secretless-ai warm'));
    expect(res.stderr).toMatch(/expired/);
  });

  it('warm session: exit 0 with empty stdout and stderr', () => {
    const home = freshHome();
    writeSessionUnder(home, 300);

    const res = runHook(home);
    expect(res.status).toBe(0);
    expect(res.stdout).toBe('');
    expect(res.stderr).toBe('');
  });

  it('no session file at all: exit 0 with empty stdout and stderr', () => {
    const home = freshHome();
    expect(fs.existsSync(path.join(home, '.secretless-ai', 'session.json'))).toBe(false);

    const res = runHook(home);
    expect(res.status).toBe(0);
    expect(res.stdout).toBe('');
    expect(res.stderr).toBe('');
  });

  it('tampered session file (one hmac byte changed): exit 2 with the deny JSON naming tampering', () => {
    const home = freshHome();
    writeSessionUnder(home, 300);
    const file = path.join(home, '.secretless-ai', 'session.json');
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
    expect(typeof parsed.hmac).toBe('string');
    const first = parsed.hmac[0];
    parsed.hmac = (first === '0' ? '1' : '0') + parsed.hmac.slice(1);
    fs.writeFileSync(file, JSON.stringify(parsed));

    const res = runHook(home);
    expect(res.status).toBe(2);
    const { reason } = parseDenyLine(res.stdout);
    expect(reason).toMatch(/tamper/i);
    expect(res.stderr).toMatch(/tamper/i);
  });
});
