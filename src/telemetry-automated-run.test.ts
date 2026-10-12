import { describe, it, expect, afterEach } from 'vitest';
import { spawn, spawnSync, execFile, execFileSync, execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { promisify } from 'util';
import { AUTOMATED_RUN_VARIABLES, automatedRunVariable } from './telemetry-gate';
// The guard is not imported here: importing it installs it, and these tests
// have to show that vitest.config.ts installs it in every worker.

/**
 * No usage event is sent from CI or from a test runner, and a test that
 * starts the CLI with telemetry on fails (#320).
 *
 * Each CI job and test run started the CLI in a fresh home, and the telemetry
 * SDK gave every fresh home a new install id, so every run was counted as a
 * new user. Events here are printed with OPENA2A_TELEMETRY_DEBUG=print and
 * sent to a closed port on this machine, with no proxy, so nothing leaves it.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;
const PREFIX = '[opena2a:telemetry] ';

const made: string[] = [];
function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

/** The CLI run for `args` with telemetry on, plus `extra`; its events parsed. */
function run(args: string[], extra: NodeJS.ProcessEnv = {}) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: tmp('automated-home-'),
    NO_COLOR: '1',
    OPENA2A_TELEMETRY_DEBUG: 'print',
    OPENA2A_TELEMETRY_URL: 'http://127.0.0.1:9/',
  };
  for (const name of ['OPENA2A_TELEMETRY', ...AUTOMATED_RUN_VARIABLES, 'XDG_CONFIG_HOME', 'NODE_USE_ENV_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']) {
    delete env[name];
  }
  Object.assign(env, extra);
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: tmp('automated-cwd-'),
    env,
  });
  const printed = res.stderr.split('\n').filter((l) => l.startsWith(PREFIX));
  return {
    status: res.status,
    stdout: res.stdout,
    events: printed.map((l) => JSON.parse(l.slice(PREFIX.length)) as Record<string, unknown>),
  };
}

describe('precondition: the suite runs with telemetry off', () => {
  it('OPENA2A_TELEMETRY is "off" in this worker; if this fails, vitest.config.ts lost it from test.env', () => {
    expect(process.env.OPENA2A_TELEMETRY).toBe('off');
  });

  it('the guard is installed in this worker; if this fails, vitest.config.ts lost its setupFiles line', () => {
    for (const launch of [spawn, spawnSync, execFile, execFileSync, execSync]) {
      expect((launch as unknown as Record<symbol, unknown>)[Symbol.for('secretless.telemetryGuard')]).toBe(true);
    }
  });
});

describe('automatedRunVariable names the variable that marks CI or a test run', () => {
  it.each([
    ['CI', 'true'],
    ['CI', '1'],
    ['GITHUB_ACTIONS', 'true'],
    ['GITLAB_CI', 'true'],
    ['TF_BUILD', 'True'],
    ['JENKINS_URL', 'http://ci.example/'],
    ['VITEST', 'true'],
    ['JEST_WORKER_ID', '1'],
    ['NODE_TEST_CONTEXT', 'child-v8'],
  ])('%s=%s', (name, value) => {
    expect(automatedRunVariable({ [name]: value })).toBe(name);
  });

  it.each(['', 'false', 'FALSE', '0', ' 0 '])('CI=%j is not CI', (value) => {
    expect(automatedRunVariable({ CI: value })).toBeUndefined();
  });

  it('an environment with none of them is not an automated run', () => {
    expect(automatedRunVariable({ PATH: '/usr/bin', HOME: '/home/u', TERM: 'xterm' })).toBeUndefined();
  });
});

describe('the release smoke clears every variable that turns telemetry off (#365)', () => {
  it('section 10 unsets each name in AUTOMATED_RUN_VARIABLES before step 10.1', () => {
    const doc = fs.readFileSync(path.resolve(__dirname, '..', 'docs', 'testing', 'release-smoke.md'), 'utf-8');
    const start = doc.indexOf('## 10.');
    const section = doc.slice(start, doc.indexOf('| 10.1 |', start)).replace(/\\\n/g, ' ');
    const unset = section.split('\n')
      .filter((line) => line.startsWith('unset '))
      .flatMap((line) => line.trim().split(/\s+/).slice(1));
    expect(unset).toContain('OPENA2A_TELEMETRY');
    expect(AUTOMATED_RUN_VARIABLES.filter((name) => !unset.includes(name))).toEqual([]);
  });
});

describe('the CLI sends no usage event from CI or a test runner', () => {
  itIfBuilt.each([
    ['CI', 'true'],
    ['GITHUB_ACTIONS', 'true'],
    ['VITEST', 'true'],
    ['JEST_WORKER_ID', '1'],
    ['NODE_TEST_CONTEXT', 'child-v8'],
  ])('%s=%s: a scan runs and sends nothing', (name, value) => {
    const res = run(['scan', tmp('automated-scan-'), '--json'], { [name]: value });

    expect(res.status).toBe(0);
    expect(res.events).toEqual([]);
  });

  itIfBuilt('CONTROL: with none of them set, the same scan sends one event', () => {
    const res = run(['scan', tmp('automated-scan-'), '--json']);

    expect(res.status).toBe(0);
    expect(res.events).toHaveLength(1);
    expect(res.events[0]).toMatchObject({ event: 'command', name: 'scan', success: true });
  });

  itIfBuilt('CI=false is not CI: the event is sent', () => {
    const res = run(['scan', tmp('automated-scan-'), '--json'], { CI: 'false' });

    expect(res.events).toHaveLength(1);
  });

  itIfBuilt('--version in CI says telemetry is off', () => {
    const res = run(['--version'], { CI: 'true' });

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Telemetry: off');
  });

  itIfBuilt('`telemetry status` in CI says off, and names the variable that turned it off', () => {
    const res = run(['telemetry', 'status'], { CI: 'true' });

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('state:       off');
    expect(res.stdout).toContain('Off for this run: CI is set, and no usage event is sent from CI or a test runner.');
  });

  itIfBuilt('CONTROL: `telemetry status` outside CI says on, with no such line', () => {
    const res = run(['telemetry', 'status']);

    expect(res.stdout).toContain('state:       on');
    expect(res.stdout).not.toContain('Off for this run');
  });
});

describe('a test that starts the CLI with telemetry on fails before the child starts', () => {
  // An environment built from scratch, as a test does to keep the real one
  // out: it carries neither the opt-out nor a CI or test-runner variable.
  // `--version` sends no event, so a guard that let one through sends nothing.
  function scratch(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
    return { PATH: process.env.PATH, HOME: tmp('automated-scratch-'), SECRETLESS_OS_KEYCHAIN: 'off', ...extra };
  }
  const REFUSAL = /starts the CLI with telemetry on[\s\S]*OPENA2A_TELEMETRY: 'off'/;
  const quoted = (p: string) => `"${p}"`;

  it('spawnSync(node, [dist/cli.js])', () => {
    expect(() => spawnSync(process.execPath, [CLI_PATH, '--version'], { env: scratch() })).toThrow(REFUSAL);
  });

  it('execFileSync(node, [dist/cli.js])', () => {
    expect(() => execFileSync(process.execPath, [CLI_PATH, '--version'], { env: scratch() })).toThrow(REFUSAL);
  });

  it('spawn(node, [dist/cli.js])', () => {
    expect(() => spawn(process.execPath, [CLI_PATH, '--version'], { env: scratch() })).toThrow(REFUSAL);
  });

  it('execFile, and promisify(execFile)', () => {
    expect(() => execFile(process.execPath, [CLI_PATH, '--version'], { env: scratch() })).toThrow(REFUSAL);
    expect(() => promisify(execFile)(process.execPath, [CLI_PATH, '--version'], { env: scratch() })).toThrow(REFUSAL);
  });

  it('execSync of a command line naming dist/cli.js', () => {
    expect(() => execSync(`${quoted(process.execPath)} ${quoted(CLI_PATH)} --version`, { env: scratch() })).toThrow(REFUSAL);
  });

  it('sh -c with the CLI passed after the script', () => {
    expect(() => spawnSync('sh', ['-c', '"$0" "$1" --version', process.execPath, CLI_PATH], { env: scratch() })).toThrow(REFUSAL);
  });

  itIfBuilt('CONTROL: the same call with OPENA2A_TELEMETRY=off starts the CLI', () => {
    const res = spawnSync(process.execPath, [CLI_PATH, '--version'], { encoding: 'utf-8', env: scratch({ OPENA2A_TELEMETRY: 'off' }) });

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Telemetry: off');
  });

  itIfBuilt('CONTROL: a child given process.env starts the CLI', () => {
    const res = spawnSync(process.execPath, [CLI_PATH, '--version'], { encoding: 'utf-8' });

    expect(res.status).toBe(0);
  });

  itIfBuilt('CONTROL: promisify(execFile) still resolves stdout and stderr', async () => {
    const res = await promisify(execFile)(process.execPath, [CLI_PATH, '--version'], { env: scratch({ OPENA2A_TELEMETRY: 'off' }) });

    expect(res.stdout).toContain('secretless-ai');
    expect(typeof res.stderr).toBe('string');
  });

  it('CONTROL: a child that is not the CLI is not checked', () => {
    const res = spawnSync(process.execPath, ['-e', 'process.exit(0)'], { env: scratch() });

    expect(res.status).toBe(0);
  });

  // Last in the file: importing the guard installs it if the config had not,
  // and the cases above would then pass without it.
  it('a telemetry URL on this machine is allowed: nothing sent there leaves it', async () => {
    const { wouldSendTelemetry } = await import('./telemetry-guard.test-support.js');
    expect(wouldSendTelemetry({ OPENA2A_TELEMETRY_URL: 'http://127.0.0.1:9/' })).toBe(false);
    expect(wouldSendTelemetry({ OPENA2A_TELEMETRY_URL: 'http://[::1]:9/' })).toBe(false);
    expect(wouldSendTelemetry({ OPENA2A_TELEMETRY_URL: 'https://telemetry.example/' })).toBe(true);
    expect(wouldSendTelemetry({ OPENA2A_TELEMETRY: 'OFF' })).toBe(false);
    expect(wouldSendTelemetry({})).toBe(true);
  });

  it('recognises the CLI by its entry, its bin name, npx and a shell command line', async () => {
    const { startsCli } = await import('./telemetry-guard.test-support.js');
    expect(startsCli(process.execPath, [CLI_PATH, 'scan'])).toBe(true);
    expect(startsCli('node', ['--no-warnings', 'dist/cli.js'])).toBe(true);
    expect(startsCli('npx', ['-y', 'secretless-ai', 'scan'])).toBe(true);
    expect(startsCli('/usr/local/bin/secretless-ai', ['scan'])).toBe(true);
    expect(startsCli('sh', ['-c', 'npx secretless-ai scan .'])).toBe(true);
    expect(startsCli('git', ['commit', '-m', 'dist/cli.js'])).toBe(false);
    expect(startsCli('sh', ['-c', 'grep -n TOKEN ~/.zshenv'])).toBe(false);
    expect(startsCli('sh', ['-c', 'ls /tmp/secretless-ai-test-1'])).toBe(false);
  });
});
