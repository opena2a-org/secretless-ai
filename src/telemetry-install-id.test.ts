import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  AUTOMATED_RUN_VARIABLES, optedOutByVariable, telemetrySettingFile, readTelemetrySetting, storeTelemetrySetting,
} from './telemetry-gate';

/**
 * No install id is derived or written while telemetry is off (#422).
 *
 * The telemetry SDK wrote `{"enabled": true, "installId": "..."}` to the
 * setting file on a run under OPENA2A_TELEMETRY=off whenever the file was
 * absent: the opt-out stopped sending and nothing else. `opena2a init` runs
 * `secretless-ai --version`, so an opted-out user got an install id from it.
 *
 * Each CLI run here gets a fresh home and sends any event to a closed port on
 * this machine, with no proxy, so nothing leaves it.
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

/** Every file under `dir`, by its path from `dir` with `/` between the parts. */
function filesUnder(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory()
    ? filesUnder(path.join(dir, e.name)).map((rel) => `${e.name}/${rel}`)
    : [e.name])).sort();
}

/** The CLI run for `args` in `home` with telemetry on, plus `extra`; its events parsed. */
function run(home: string, args: string[], extra: NodeJS.ProcessEnv = {}) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
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
    cwd: tmp('install-id-cwd-'),
    env,
  });
  const printed = res.stderr.split('\n').filter((l) => l.startsWith(PREFIX));
  return {
    status: res.status,
    stdout: res.stdout,
    events: printed.map((l) => JSON.parse(l.slice(PREFIX.length)) as Record<string, unknown>),
  };
}

const settingIn = (home: string) => path.join(home, '.config', 'opena2a', 'telemetry.json');
const stored = (home: string) => JSON.parse(fs.readFileSync(settingIn(home), 'utf-8')) as Record<string, unknown>;
const OFF = { OPENA2A_TELEMETRY: 'off' };

describe('under OPENA2A_TELEMETRY=off no install id is derived or written (#422)', () => {
  itIfBuilt('--version writes no setting file', () => {
    const home = tmp('install-id-home-');

    const res = run(home, ['--version'], OFF);

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Telemetry: off');
    expect(filesUnder(home)).toEqual([]);
  });

  itIfBuilt.each(['off', 'OFF', '0', 'false', 'no'])('OPENA2A_TELEMETRY=%s: a scan writes no setting file and sends nothing', (value) => {
    const home = tmp('install-id-home-');

    const res = run(home, ['scan', tmp('install-id-scan-'), '--json'], { OPENA2A_TELEMETRY: value });

    expect(res.status).toBe(0);
    expect(res.events).toEqual([]);
    expect(filesUnder(home)).toEqual([]);
  });

  itIfBuilt('with XDG_CONFIG_HOME set, nothing is written there either', () => {
    const home = tmp('install-id-home-');
    const xdg = tmp('install-id-xdg-');

    const res = run(home, ['--version'], { ...OFF, XDG_CONFIG_HOME: xdg });

    expect(res.status).toBe(0);
    expect(filesUnder(xdg)).toEqual([]);
    expect(filesUnder(home)).toEqual([]);
  });

  itIfBuilt('`telemetry status` says off, prints no install id, and writes nothing', () => {
    const home = tmp('install-id-home-');

    const res = run(home, ['telemetry', 'status'], OFF);

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('state:       off');
    expect(res.stdout).toContain('install_id:  none (one is created on the first run with telemetry on)');
    expect(res.stdout).toContain(`config:      ${settingIn(home)}`);
    expect(res.stdout).toContain('Off for this run: OPENA2A_TELEMETRY is set to turn it off.');
    expect(filesUnder(home)).toEqual([]);
  });

  itIfBuilt('`telemetry off` stores the setting with no install id', () => {
    const home = tmp('install-id-home-');

    const res = run(home, ['telemetry', 'off'], OFF);

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Telemetry disabled for secretless-ai.');
    expect(stored(home)).toEqual({ enabled: false });
  });

  itIfBuilt('`telemetry on` stores the setting with no install id, and says this run is still off', () => {
    const home = tmp('install-id-home-');

    const res = run(home, ['telemetry', 'on'], OFF);

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('state:       off');
    expect(res.stdout).toContain('Off for this run: OPENA2A_TELEMETRY is set to turn it off.');
    expect(stored(home)).toEqual({ enabled: true });
  });

  itIfBuilt('a setting file already there is left byte for byte as it was', () => {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true });
    const before = '{"enabled":true,"installId":"FAKE-INSTALL-ID"}\n';
    fs.writeFileSync(settingIn(home), before);

    const res = run(home, ['scan', tmp('install-id-scan-'), '--json'], OFF);

    expect(res.status).toBe(0);
    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(before);
  });

  itIfBuilt('`telemetry status` prints an install id that is already stored, and changes nothing', () => {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true });
    const before = '{"enabled":true,"installId":"FAKE-INSTALL-ID"}\n';
    fs.writeFileSync(settingIn(home), before);

    const res = run(home, ['telemetry', 'status'], OFF);

    expect(res.stdout).toContain('install_id:  FAKE-INSTALL-ID');
    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(before);
  });
});

describe('the other ways telemetry is off write no install id either', () => {
  itIfBuilt('CI=true: --version and a scan write no setting file', () => {
    const home = tmp('install-id-home-');

    expect(run(home, ['--version'], { CI: 'true' }).stdout).toContain('Telemetry: off');
    expect(run(home, ['scan', tmp('install-id-scan-'), '--json'], { CI: 'true' }).status).toBe(0);
    expect(filesUnder(home)).toEqual([]);
  });

  itIfBuilt('a stored `enabled: false` with no install id: a scan sends nothing and adds none', () => {
    const home = tmp('install-id-home-');
    expect(run(home, ['telemetry', 'off'], OFF).status).toBe(0);

    // Telemetry otherwise on: no opt-out variable, no CI or test runner.
    const res = run(home, ['scan', tmp('install-id-scan-'), '--json']);

    expect(res.status).toBe(0);
    expect(res.events).toEqual([]);
    expect(stored(home)).toEqual({ enabled: false });
  });

  itIfBuilt('`telemetry off` on a run with telemetry on drops the install id that run created', () => {
    const home = tmp('install-id-home-');

    const res = run(home, ['telemetry', 'off']);

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('state:       off');
    expect(stored(home)).toEqual({ enabled: false });
  });
});

describe('CONTROL: with telemetry on, the SDK still creates and keeps the install id', () => {
  itIfBuilt('--version creates the setting file with an install id', () => {
    const home = tmp('install-id-home-');

    const res = run(home, ['--version']);

    expect(res.stdout).toContain('Telemetry: on');
    expect(filesUnder(home)).toEqual(['.config/opena2a/telemetry.json']);
    expect(stored(home)).toMatchObject({ enabled: true, installId: expect.any(String) });
  });

  itIfBuilt('a scan sends one event under that install id', () => {
    const home = tmp('install-id-home-');

    const res = run(home, ['scan', tmp('install-id-scan-'), '--json']);

    expect(res.events).toHaveLength(1);
    expect(res.events[0].install_id).toBe(stored(home).installId);
  });

  itIfBuilt('`telemetry on` after `telemetry off` creates an install id again', () => {
    const home = tmp('install-id-home-');
    run(home, ['telemetry', 'off']);

    const res = run(home, ['telemetry', 'on']);

    expect(res.stdout).toContain('state:       on');
    expect(stored(home)).toMatchObject({ enabled: true, installId: expect.any(String) });
  });

  itIfBuilt('telemetrySettingFile names the file the SDK creates, under HOME and under XDG_CONFIG_HOME', () => {
    const home = tmp('install-id-home-');
    const xdg = tmp('install-id-xdg-');

    run(home, ['--version']);
    run(home, ['--version'], { XDG_CONFIG_HOME: xdg });

    expect(telemetrySettingFile({}, home)).toBe(settingIn(home));
    expect(fs.existsSync(telemetrySettingFile({}, home))).toBe(true);
    expect(fs.existsSync(telemetrySettingFile({ XDG_CONFIG_HOME: xdg }, home))).toBe(true);
    expect(telemetrySettingFile({ XDG_CONFIG_HOME: xdg }, home)).toBe(path.join(xdg, 'opena2a', 'telemetry.json'));
    expect(telemetrySettingFile({ XDG_CONFIG_HOME: '' }, home)).toBe(settingIn(home));
  });
});

describe('the helpers read the setting as the SDK reads it', () => {
  it.each(['off', 'OFF', 'Off', '0', 'false', 'FALSE', 'no', 'No'])('OPENA2A_TELEMETRY=%j is an opt-out', (value) => {
    expect(optedOutByVariable({ OPENA2A_TELEMETRY: value })).toBe(true);
  });

  it.each(['', 'on', '1', 'true', ' off', 'off '])('OPENA2A_TELEMETRY=%j is not', (value) => {
    expect(optedOutByVariable({ OPENA2A_TELEMETRY: value })).toBe(false);
  });

  it('an unset OPENA2A_TELEMETRY is not an opt-out', () => {
    expect(optedOutByVariable({})).toBe(false);
  });

  it.each([
    ['{"enabled":false}', { enabled: false }],
    ['{"enabled":true,"installId":"FAKE-ID"}', { enabled: true, installId: 'FAKE-ID' }],
    ['{"installId":"FAKE-ID"}', { enabled: true, installId: 'FAKE-ID' }],
    ['{"enabled":null}', { enabled: true }],
    ['{"enabled":0}', { enabled: false }],
    ['{"enabled":true,"installId":""}', { enabled: true }],
    ['5', { enabled: true }],
    ['null', { enabled: true }],
  ])('%s reads as %j', (text, expected) => {
    const file = path.join(tmp('install-id-read-'), 'telemetry.json');
    fs.writeFileSync(file, text);

    expect(readTelemetrySetting(file)).toEqual(expected);
  });

  it('an absent file and one that is not JSON read as null', () => {
    const dir = tmp('install-id-read-');
    fs.writeFileSync(path.join(dir, 'broken.json'), '{not json');

    expect(readTelemetrySetting(path.join(dir, 'absent.json'))).toBeNull();
    expect(readTelemetrySetting(path.join(dir, 'broken.json'))).toBeNull();
  });

  it('storeTelemetrySetting(on) keeps a stored install id, (off) drops it, and neither derives one', () => {
    const file = path.join(tmp('install-id-store-'), 'opena2a', 'telemetry.json');

    expect(storeTelemetrySetting(file, true)).toEqual({ enabled: true });
    fs.writeFileSync(file, '{"enabled":false,"installId":"FAKE-ID"}\n');
    expect(storeTelemetrySetting(file, true)).toEqual({ enabled: true, installId: 'FAKE-ID' });
    expect(storeTelemetrySetting(file, false)).toEqual({ enabled: false });
    expect(fs.readFileSync(file, 'utf-8')).toBe('{\n  "enabled": false\n}\n');
  });

  it.skipIf(process.platform === 'win32')('storeTelemetrySetting creates the directory 0700 and the file 0600, as the SDK does', () => {
    const file = path.join(tmp('install-id-store-'), 'opena2a', 'telemetry.json');

    storeTelemetrySetting(file, false);

    expect(fs.statSync(path.dirname(file)).mode & 0o777).toBe(0o700);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });
});
