import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  AUTOMATED_RUN_VARIABLES, optedOutByVariable, telemetrySettingFile, readTelemetrySetting, storeTelemetrySetting,
  dropStoredInstallId,
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

/**
 * The CLI run for `args` in `home` with telemetry on, plus `extra`; its events
 * parsed. With `noFileBytes`, it runs under `ulimit -f 0`, where its first
 * write of a byte to a regular file fails with EFBIG.
 */
function run(home: string, args: string[], extra: NodeJS.ProcessEnv = {}, noFileBytes = false) {
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
  const command = [process.execPath, CLI_PATH, ...args];
  const res = spawnSync(noFileBytes ? '/bin/sh' : command[0], noFileBytes
    ? ['-c', 'ulimit -f 0; exec "$@"', 'sh', ...command]
    : command.slice(1), {
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

  itIfBuilt('a setting file with no install id is left byte for byte as it was', () => {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true });
    const before = '{"enabled":true}\n';
    fs.writeFileSync(settingIn(home), before);

    const res = run(home, ['scan', tmp('install-id-scan-'), '--json'], OFF);

    expect(res.status).toBe(0);
    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(before);
  });
});

describe('an install id left by an earlier run is deleted on a run with telemetry off (#426)', () => {
  /** A home whose setting file holds `text`, as an earlier run left it. */
  function homeWith(text: string): string {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true });
    fs.writeFileSync(settingIn(home), text);
    return home;
  }
  const LEFT = '{"enabled":true,"installId":"FAKE-INSTALL-ID"}\n';

  itIfBuilt('OPENA2A_TELEMETRY=off: --version deletes it, then `telemetry on` stores {"enabled": true} without it', () => {
    const home = homeWith(LEFT);

    expect(run(home, ['--version'], OFF).status).toBe(0);
    expect(stored(home)).toEqual({ enabled: true });

    const res = run(home, ['telemetry', 'on'], OFF);

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('install_id:  none (one is created on the first run with telemetry on)');
    expect(stored(home)).toEqual({ enabled: true });
  });

  itIfBuilt('OPENA2A_TELEMETRY=off: a scan deletes it and sends nothing', () => {
    const home = homeWith(LEFT);

    const res = run(home, ['scan', tmp('install-id-scan-'), '--json'], OFF);

    expect(res.status).toBe(0);
    expect(res.events).toEqual([]);
    expect(stored(home)).toEqual({ enabled: true });
  });

  itIfBuilt('`telemetry status` deletes it and prints none', () => {
    const home = homeWith(LEFT);

    const res = run(home, ['telemetry', 'status'], OFF);

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('install_id:  none (one is created on the first run with telemetry on)');
    expect(stored(home)).toEqual({ enabled: true });
  });

  itIfBuilt('`telemetry on` with no other run first stores {"enabled": true} without it', () => {
    const home = homeWith('{"enabled":false,"installId":"FAKE-INSTALL-ID"}\n');

    const res = run(home, ['telemetry', 'on'], OFF);

    expect(res.status).toBe(0);
    expect(stored(home)).toEqual({ enabled: true });
  });

  itIfBuilt('a stored "enabled": false: a scan with no opt-out variable deletes it, keeps the false, and sends nothing', () => {
    const home = homeWith('{"enabled":false,"installId":"FAKE-INSTALL-ID"}\n');

    // Telemetry otherwise on: no opt-out variable, no CI or test runner.
    const res = run(home, ['scan', tmp('install-id-scan-'), '--json']);

    expect(res.status).toBe(0);
    expect(res.events).toEqual([]);
    expect(stored(home)).toEqual({ enabled: false });
  });

  itIfBuilt('CI=true: --version deletes it and keeps the stored setting', () => {
    const home = homeWith(LEFT);

    expect(run(home, ['--version'], { CI: 'true' }).status).toBe(0);
    expect(stored(home)).toEqual({ enabled: true });
  });

  itIfBuilt('a file with no "enabled" key is rewritten as on, which is how the SDK reads it', () => {
    const home = homeWith('{"installId":"FAKE-INSTALL-ID"}\n');

    expect(run(home, ['--version'], OFF).status).toBe(0);
    expect(stored(home)).toEqual({ enabled: true });
  });

  itIfBuilt('with XDG_CONFIG_HOME set, the id is deleted from the file there', () => {
    const home = tmp('install-id-home-');
    const xdg = tmp('install-id-xdg-');
    const file = path.join(xdg, 'opena2a', 'telemetry.json');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, '{"enabled":false,"installId":"FAKE-INSTALL-ID"}\n');

    expect(run(home, ['--version'], { ...OFF, XDG_CONFIG_HOME: xdg }).status).toBe(0);
    expect(JSON.parse(fs.readFileSync(file, 'utf-8'))).toEqual({ enabled: false });
    expect(filesUnder(home)).toEqual([]);
  });

  const unwritable = process.platform === 'win32' || process.getuid?.() === 0;
  (fs.existsSync(CLI_PATH) && !unwritable ? it : it.skip)('a setting file that cannot be written stops no command, and status still prints the id', () => {
    const home = homeWith(LEFT);
    fs.chmodSync(settingIn(home), 0o400);
    try {
      expect(run(home, ['--version'], OFF).status).toBe(0);
      const res = run(home, ['telemetry', 'status'], OFF);

      expect(res.status).toBe(0);
      expect(res.stdout).toContain('install_id:  FAKE-INSTALL-ID');
      expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(LEFT);
    } finally {
      fs.chmodSync(settingIn(home), 0o600);
    }
  });

  itIfBuilt('CONTROL: with telemetry on, a stored id is kept and sent', () => {
    const home = homeWith(LEFT);

    const res = run(home, ['scan', tmp('install-id-scan-'), '--json']);

    expect(res.events).toHaveLength(1);
    expect(res.events[0].install_id).toBe('FAKE-INSTALL-ID');
    expect(stored(home)).toEqual({ enabled: true, installId: 'FAKE-INSTALL-ID' });
  });
});

describe('a rewrite of the setting file that does not finish leaves the previous content (#429)', () => {
  // The rewrite truncated the file before writing it, so a write that failed
  // part way left it empty; an empty file reads as absent, and absent is on.
  const OPTED_OUT = '{"enabled":false,"installId":"FAKE-INSTALL-ID"}\n';
  const REWRITTEN = '{\n  "enabled": false\n}\n';
  const posix = process.platform !== 'win32';
  const itIfBuiltPosix = fs.existsSync(CLI_PATH) && posix ? it : it.skip;
  const GATE_PATH = path.resolve(__dirname, '..', 'dist', 'telemetry-gate.js');

  function settingDirWith(text: string): string {
    const dir = path.join(tmp('install-id-atomic-'), 'opena2a');
    fs.mkdirSync(dir, { mode: 0o700 });
    fs.writeFileSync(path.join(dir, 'telemetry.json'), text);
    return dir;
  }

  itIfBuiltPosix.each([
    { args: ['--version'] },
    { args: ['telemetry', 'off'] },
    { args: ['telemetry', 'on'] },
  ])('OPENA2A_TELEMETRY=off: $args with a write that fails keeps the stored "enabled": false', ({ args }) => {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true });
    fs.writeFileSync(settingIn(home), OPTED_OUT);

    run(home, args, OFF, true);

    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(OPTED_OUT);
    expect(fs.readdirSync(path.dirname(settingIn(home)))).toEqual(['telemetry.json']);
    expect(run(home, ['telemetry', 'status']).stdout).toContain('state:       off');
  });

  it.skipIf(!posix)('a rewrite leaves no other file in the directory, and the file is 0600 as the SDK writes it', () => {
    const dir = settingDirWith(OPTED_OUT);
    const file = path.join(dir, 'telemetry.json');
    fs.chmodSync(file, 0o644);

    expect(dropStoredInstallId(file)).toBe(true);

    expect(fs.readFileSync(file, 'utf-8')).toBe(REWRITTEN);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it.skipIf(!posix)('a symlinked setting file stays a link, and the file it points to is rewritten', () => {
    const dir = settingDirWith(OPTED_OUT);
    const file = path.join(dir, 'telemetry.json');
    const real = path.join(tmp('install-id-link-'), 'kept.json');
    fs.renameSync(file, real);
    fs.symlinkSync(real, file);

    expect(dropStoredInstallId(file)).toBe(true);

    expect(fs.lstatSync(file).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(real, 'utf-8')).toBe(REWRITTEN);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
    expect(fs.readdirSync(path.dirname(real))).toEqual(['kept.json']);
  });

  // fs.existsSync is false for a link whose target does not exist yet, so the
  // new content was renamed over the link and the link was gone (#432).
  it.skipIf(!posix).each([
    ['an absolute', (real: string) => real],
    ['a relative', (real: string, dir: string) => path.relative(dir, real)],
  ] as const)('%s link to a file that does not exist yet stays a link, and the file is created', (_, text) => {
    const dir = path.join(tmp('install-id-dangling-'), 'opena2a');
    fs.mkdirSync(dir, { mode: 0o700 });
    const file = path.join(dir, 'telemetry.json');
    const real = path.join(tmp('install-id-link-'), 'dotfiles', 'telemetry.json');
    fs.mkdirSync(path.dirname(real));
    fs.symlinkSync(text(real, dir), file);

    storeTelemetrySetting(file, false);

    expect(fs.lstatSync(file).isSymbolicLink()).toBe(true);
    expect(fs.readlinkSync(file)).toBe(text(real, dir));
    expect(fs.readFileSync(real, 'utf-8')).toBe(REWRITTEN);
    expect(fs.statSync(real).mode & 0o777).toBe(0o600);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
    expect(fs.readdirSync(path.dirname(real))).toEqual(['telemetry.json']);
  });

  itIfBuiltPosix('OPENA2A_TELEMETRY=off: telemetry off through a link to a file that does not exist yet creates that file', () => {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true });
    const real = path.join(home, 'dotfiles-telemetry.json');
    fs.symlinkSync(real, settingIn(home));

    expect(run(home, ['telemetry', 'off'], OFF).status).toBe(0);

    expect(fs.lstatSync(settingIn(home)).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(real, 'utf-8')).toBe(REWRITTEN);
    expect(run(home, ['telemetry', 'status']).stdout).toContain('state:       off');
  });

  it.skipIf(!posix)('a setting file that is a link loop is not replaced', () => {
    const dir = path.join(tmp('install-id-loop-'), 'opena2a');
    fs.mkdirSync(dir, { mode: 0o700 });
    const file = path.join(dir, 'telemetry.json');
    const other = path.join(dir, 'other.json');
    fs.symlinkSync(other, file);
    fs.symlinkSync(file, other);

    expect(() => storeTelemetrySetting(file, false)).toThrow(/ELOOP/);

    expect(fs.readlinkSync(file)).toBe(other);
    expect(fs.readlinkSync(other)).toBe(file);
    expect(fs.readdirSync(dir).sort()).toEqual(['other.json', 'telemetry.json']);
  });

  it.skipIf(!posix || process.getuid?.() === 0)('a setting file this user cannot write is not replaced', () => {
    const dir = settingDirWith(OPTED_OUT);
    const file = path.join(dir, 'telemetry.json');
    fs.chmodSync(file, 0o400);

    expect(() => dropStoredInstallId(file)).toThrow(/EACCES/);

    expect(fs.readFileSync(file, 'utf-8')).toBe(OPTED_OUT);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
  });

  (fs.existsSync(GATE_PATH) && posix ? it : it.skip)('a process killed before the rename leaves the setting file as it was', () => {
    const dir = settingDirWith(OPTED_OUT);
    const file = path.join(dir, 'telemetry.json');

    // The rename of the setting file to itself is let through; the process is
    // killed at the rename of the new file over the setting file.
    const res = spawnSync(process.execPath, ['-e', [
      "const fs = require('fs');",
      'const renameSync = fs.renameSync;',
      "fs.renameSync = (from, to) => (from === to ? renameSync(from, to) : process.kill(process.pid, 'SIGKILL'));",
      'require(process.argv[1]).dropStoredInstallId(process.argv[2]);',
    ].join('\n'), GATE_PATH, file], { encoding: 'utf-8' });

    expect(res.signal).toBe('SIGKILL');
    expect(fs.readFileSync(file, 'utf-8')).toBe(OPTED_OUT);
    const others = fs.readdirSync(dir).filter((name) => name !== 'telemetry.json');
    expect(others).toHaveLength(1);
    expect(others[0]).toMatch(/^\.telemetry\.json\.\d+\.[0-9a-f]{12}\.tmp$/);
    expect(fs.readFileSync(path.join(dir, others[0]), 'utf-8')).toBe(REWRITTEN);
  });
});

describe('a setting file this user can write is rewritten in a directory this user cannot write to (#431)', () => {
  // Since #429 the new content went to a new file in the setting file's
  // directory, so a directory this user cannot write to stopped `telemetry on`
  // and `telemetry off` with EACCES, where the in-place write stored the setting.
  const OPTED_OUT = '{"enabled":false,"installId":"FAKE-INSTALL-ID"}\n';
  const REWRITTEN = '{\n  "enabled": false\n}\n';
  // root writes to a directory of any mode, so the new file is never refused.
  const dirModeBinds = process.platform !== 'win32' && process.getuid?.() !== 0;
  const itIfDirModeBinds = dirModeBinds ? it : it.skip;
  const itIfBuiltDirModeBinds = fs.existsSync(CLI_PATH) && dirModeBinds ? it : it.skip;

  /** Run `fn` with the setting directory of `home` at mode 0500, then give it 0700 back. */
  function inReadOnlyDir<T>(home: string, fn: () => T): T {
    const dir = path.dirname(settingIn(home));
    fs.chmodSync(dir, 0o500);
    try {
      return fn();
    } finally {
      fs.chmodSync(dir, 0o700);
    }
  }

  /** A home whose setting file, mode 0600, holds `text`. */
  function homeWith(text: string): string {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true, mode: 0o700 });
    fs.writeFileSync(settingIn(home), text, { mode: 0o600 });
    return home;
  }

  itIfBuiltDirModeBinds.each([
    { args: ['telemetry', 'off'], expected: { enabled: false } },
    { args: ['telemetry', 'on'], expected: { enabled: true } },
    { args: ['--version'], expected: { enabled: false } },
  ])('OPENA2A_TELEMETRY=off: $args exits 0 and stores $expected', ({ args, expected }) => {
    const home = homeWith(OPTED_OUT);

    const res = inReadOnlyDir(home, () => run(home, args, OFF));

    expect(res.status).toBe(0);
    expect(stored(home)).toEqual(expected);
    expect(fs.readdirSync(path.dirname(settingIn(home)))).toEqual(['telemetry.json']);
  });

  itIfBuiltDirModeBinds('OPENA2A_TELEMETRY=off: telemetry off with a write that fails keeps the stored "enabled": false', () => {
    const home = homeWith(OPTED_OUT);

    inReadOnlyDir(home, () => run(home, ['telemetry', 'off'], OFF, true));

    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(OPTED_OUT);
    expect(fs.readdirSync(path.dirname(settingIn(home)))).toEqual(['telemetry.json']);
    expect(run(home, ['telemetry', 'status']).stdout).toContain('state:       off');
  });

  itIfDirModeBinds('the in-place rewrite cuts a longer file to the new content and keeps the file mode', () => {
    const home = homeWith(OPTED_OUT);
    fs.chmodSync(settingIn(home), 0o644);

    expect(inReadOnlyDir(home, () => dropStoredInstallId(settingIn(home)))).toBe(true);

    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(REWRITTEN);
    expect(fs.statSync(settingIn(home)).mode & 0o777).toBe(0o644);
    expect(fs.readdirSync(path.dirname(settingIn(home)))).toEqual(['telemetry.json']);
  });

  itIfDirModeBinds('the in-place rewrite stores content longer than the file had', () => {
    const home = homeWith('{}\n');

    inReadOnlyDir(home, () => storeTelemetrySetting(settingIn(home), false));

    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(REWRITTEN);
  });

  itIfDirModeBinds('a setting file this user cannot write is still not replaced', () => {
    const home = homeWith(OPTED_OUT);
    fs.chmodSync(settingIn(home), 0o400);

    expect(() => inReadOnlyDir(home, () => dropStoredInstallId(settingIn(home)))).toThrow(/EACCES/);

    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(OPTED_OUT);
  });

  itIfDirModeBinds('with no setting file, the directory refusal still throws and creates nothing', () => {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true, mode: 0o700 });

    expect(() => inReadOnlyDir(home, () => storeTelemetrySetting(settingIn(home), false))).toThrow(/EACCES/);

    expect(fs.readdirSync(path.dirname(settingIn(home)))).toEqual([]);
  });
});

describe('a setting file this user can write is rewritten in a directory with the immutable flag set (#434)', () => {
  // The immutable flag refuses a new file in the directory with EPERM, not the
  // EACCES of #431, and leaves the setting file in it writable, so the in-place
  // rewrite was not used: `telemetry on` and `telemetry off` exited 1 and left
  // the file unchanged.
  const OPTED_OUT = '{"enabled":false,"installId":"FAKE-INSTALL-ID"}\n';
  const REWRITTEN = '{\n  "enabled": false\n}\n';
  // Node sets no file flags, so the macOS chflags command sets this one.
  const darwin = process.platform === 'darwin';
  const itIfDarwin = darwin ? it : it.skip;
  const itIfBuiltDarwin = fs.existsSync(CLI_PATH) && darwin ? it : it.skip;
  const GATE_PATH = path.resolve(__dirname, '..', 'dist', 'telemetry-gate.js');

  /** Run `fn` with the immutable flag set on each of `paths`, then clear it. */
  function withImmutable<T>(paths: string[], fn: () => T): T {
    execFileSync('/usr/bin/chflags', ['uchg', ...paths]);
    try {
      return fn();
    } finally {
      execFileSync('/usr/bin/chflags', ['nouchg', ...paths]);
    }
  }

  /** A home whose setting file, mode 0600, holds `text`. */
  function homeWith(text: string): string {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true, mode: 0o700 });
    fs.writeFileSync(settingIn(home), text, { mode: 0o600 });
    return home;
  }

  itIfBuiltDarwin.each([
    { args: ['telemetry', 'off'], expected: { enabled: false } },
    { args: ['telemetry', 'on'], expected: { enabled: true } },
    { args: ['--version'], expected: { enabled: false } },
  ])('OPENA2A_TELEMETRY=off: $args exits 0 and stores $expected', ({ args, expected }) => {
    const home = homeWith(OPTED_OUT);
    const dir = path.dirname(settingIn(home));

    const res = withImmutable([dir], () => run(home, args, OFF));

    expect(res.status).toBe(0);
    expect(stored(home)).toEqual(expected);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
  });

  itIfBuiltDarwin('OPENA2A_TELEMETRY=off: telemetry off with a write that fails keeps the stored "enabled": false', () => {
    const home = homeWith(OPTED_OUT);
    const dir = path.dirname(settingIn(home));

    withImmutable([dir], () => run(home, ['telemetry', 'off'], OFF, true));

    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(OPTED_OUT);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
    expect(run(home, ['telemetry', 'status']).stdout).toContain('state:       off');
  });

  itIfDarwin('a setting file with the immutable flag set is still not replaced', () => {
    const home = homeWith(OPTED_OUT);
    const dir = path.dirname(settingIn(home));

    expect(() => withImmutable([settingIn(home), dir], () => dropStoredInstallId(settingIn(home)))).toThrow(/EPERM/);

    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(OPTED_OUT);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
  });

  itIfDarwin('with no setting file, the EPERM is still thrown and nothing is created', () => {
    const home = tmp('install-id-home-');
    const dir = path.dirname(settingIn(home));
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    expect(() => withImmutable([dir], () => storeTelemetrySetting(settingIn(home), false))).toThrow(/EPERM/);

    expect(fs.readdirSync(dir)).toEqual([]);
  });

  // The flag is set above on macOS only. Here a child process refuses the new
  // file with EPERM, so this test is not limited to macOS.
  (fs.existsSync(GATE_PATH) ? it : it.skip)('the setting file is rewritten in place when the new file is refused with EPERM', () => {
    const dir = path.join(tmp('install-id-eperm-'), 'opena2a');
    fs.mkdirSync(dir, { mode: 0o700 });
    const file = path.join(dir, 'telemetry.json');
    fs.writeFileSync(file, OPTED_OUT);

    const res = spawnSync(process.execPath, ['-e', [
      "const fs = require('fs');",
      "const path = require('path');",
      'const [gate, file] = process.argv.slice(1);',
      'const openSync = fs.openSync;',
      'fs.openSync = (target, ...rest) => {',
      '  if (path.dirname(target) !== path.dirname(file) || fs.existsSync(target)) return openSync(target, ...rest);',
      "  console.log('refused ' + path.basename(target));",
      "  throw Object.assign(new Error('EPERM: operation not permitted, open ' + target), { code: 'EPERM' });",
      '};',
      'require(gate).storeTelemetrySetting(file, false);',
    ].join('\n'), GATE_PATH, file], { encoding: 'utf-8' });

    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/^refused \.telemetry\.json\.\d+\.[0-9a-f]{12}\.tmp$/m);
    expect(fs.readFileSync(file, 'utf-8')).toBe(REWRITTEN);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
  });
});

describe('a setting file this user can write is rewritten in a directory with the append-only flag set (#436)', () => {
  // An append-only directory takes a new file but refuses to rename or remove
  // it, so the new file stayed, the write threw the refused removal, and the
  // setting file was left unchanged: each write left one more file.
  const OPTED_OUT = '{"enabled":false,"installId":"FAKE-INSTALL-ID"}\n';
  const REWRITTEN = '{\n  "enabled": false\n}\n';
  const NEW_FILE = /^\.telemetry\.json\.\d+\.[0-9a-f]{12}\.tmp$/;
  // Node sets no file flags, so the macOS chflags command sets this one.
  const darwin = process.platform === 'darwin';
  const itIfDarwin = darwin ? it : it.skip;
  const itIfBuiltDarwin = fs.existsSync(CLI_PATH) && darwin ? it : it.skip;
  const GATE_PATH = path.resolve(__dirname, '..', 'dist', 'telemetry-gate.js');
  const itIfGateBuilt = fs.existsSync(GATE_PATH) ? it : it.skip;

  /** Run `fn` with the append-only flag set on `dir`, then clear it. */
  function withAppendOnly<T>(dir: string, fn: () => T): T {
    execFileSync('/usr/bin/chflags', ['uappnd', dir]);
    try {
      return fn();
    } finally {
      execFileSync('/usr/bin/chflags', ['nouappnd', dir]);
    }
  }

  /** A home whose setting file, mode 0600, holds `text`. */
  function homeWith(text: string): string {
    const home = tmp('install-id-home-');
    fs.mkdirSync(path.dirname(settingIn(home)), { recursive: true, mode: 0o700 });
    fs.writeFileSync(settingIn(home), text, { mode: 0o600 });
    return home;
  }

  itIfDarwin('each rewrite stores the setting in place and leaves no other file', () => {
    const home = homeWith(OPTED_OUT);
    const dir = path.dirname(settingIn(home));
    fs.chmodSync(settingIn(home), 0o644);

    withAppendOnly(dir, () => {
      expect(dropStoredInstallId(settingIn(home))).toBe(true);
      expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(REWRITTEN);
      storeTelemetrySetting(settingIn(home), true);
      expect(stored(home)).toEqual({ enabled: true });
      expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
    });

    expect(fs.statSync(settingIn(home)).mode & 0o777).toBe(0o644);
  });

  itIfBuiltDarwin.each([
    { args: ['telemetry', 'off'], expected: { enabled: false } },
    { args: ['telemetry', 'on'], expected: { enabled: true } },
    { args: ['--version'], expected: { enabled: false } },
  ])('OPENA2A_TELEMETRY=off: $args exits 0, stores $expected and leaves no other file', ({ args, expected }) => {
    const home = homeWith(OPTED_OUT);
    const dir = path.dirname(settingIn(home));

    const res = withAppendOnly(dir, () => run(home, args, OFF));

    expect(res.status).toBe(0);
    expect(stored(home)).toEqual(expected);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
  });

  itIfBuiltDarwin('OPENA2A_TELEMETRY=off: telemetry off with a write that fails keeps the stored "enabled": false', () => {
    const home = homeWith(OPTED_OUT);
    const dir = path.dirname(settingIn(home));

    withAppendOnly(dir, () => run(home, ['telemetry', 'off'], OFF, true));

    expect(fs.readFileSync(settingIn(home), 'utf-8')).toBe(OPTED_OUT);
    expect(fs.readdirSync(dir)).toEqual(['telemetry.json']);
    expect(run(home, ['telemetry', 'status']).stdout).toContain('state:       off');
  });

  itIfDarwin('with no setting file, the error thrown is the refused rename, not the refused removal', () => {
    const home = tmp('install-id-home-');
    const dir = path.dirname(settingIn(home));
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    const thrown = withAppendOnly(dir, () => {
      try {
        storeTelemetrySetting(settingIn(home), false);
      } catch (err) {
        return err as NodeJS.ErrnoException;
      }
      return undefined;
    });

    expect(thrown).toMatchObject({ code: 'EPERM', syscall: 'rename' });
    // The directory refuses the removal of the new file as well, so it stays
    // until the flag is cleared.
    expect(fs.readdirSync(dir)).toEqual([expect.stringMatching(NEW_FILE)]);
  });

  // Where a rename to the same name is not refused, the refusal shows only at
  // the rename of the new file. Here a child process refuses that rename, and
  // where a case says so the removal of the new file, so these tests are not
  // limited to macOS.
  /** Lines that make the child refuse the rename of the new file with `code`, and with `removal` its removal too. */
  const refusing = (code: string, removal: boolean) => [
    "const fs = require('fs');",
    'const [gate, file] = process.argv.slice(1);',
    'const renameSync = fs.renameSync;',
    'fs.renameSync = (from, to) => {',
    '  if (from === to) return renameSync(from, to);',
    "  console.log('refused rename');",
    `  throw Object.assign(new Error('${code}: rename'), { code: '${code}', syscall: 'rename' });`,
    '};',
    ...(removal ? [
      'fs.rmSync = () => {',
      "  console.log('refused removal');",
      `  throw Object.assign(new Error('${code}: rm'), { code: '${code}', syscall: 'rm' });`,
      '};',
    ] : []),
  ];

  itIfGateBuilt.each([
    { code: 'EPERM', removal: false, printed: 'refused rename\n', others: 0 },
    { code: 'EACCES', removal: false, printed: 'refused rename\n', others: 0 },
    { code: 'EPERM', removal: true, printed: 'refused rename\nrefused removal\n', others: 1 },
  ])('the setting file is rewritten in place when the rename of the new file is refused with $code, removal refused: $removal', ({ code, removal, printed, others }) => {
    const dir = path.join(tmp('install-id-appnd-'), 'opena2a');
    fs.mkdirSync(dir, { mode: 0o700 });
    const file = path.join(dir, 'telemetry.json');
    fs.writeFileSync(file, OPTED_OUT);

    const res = spawnSync(process.execPath, ['-e', [
      ...refusing(code, removal),
      'require(gate).storeTelemetrySetting(file, false);',
    ].join('\n'), GATE_PATH, file], { encoding: 'utf-8' });

    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toBe(printed);
    expect(fs.readFileSync(file, 'utf-8')).toBe(REWRITTEN);
    const left = fs.readdirSync(dir).filter((name) => name !== 'telemetry.json');
    expect(left).toHaveLength(others);
    for (const name of left) expect(name).toMatch(NEW_FILE);
  });

  // Under `ulimit -f 0` the write of the new file fails with EFBIG before the rename.
  (fs.existsSync(GATE_PATH) && process.platform !== 'win32' ? it : it.skip).each([
    { failed: 'rename', noFileBytes: false, printed: 'refused rename\nrefused removal\nthrown rename EPERM\n' },
    { failed: 'write', noFileBytes: true, printed: 'refused removal\nthrown write EFBIG\n' },
  ])('with no setting file and the removal refused too, the error thrown is the failed $failed', ({ noFileBytes, printed }) => {
    const dir = path.join(tmp('install-id-appnd-'), 'opena2a');
    fs.mkdirSync(dir, { mode: 0o700 });
    const file = path.join(dir, 'telemetry.json');
    const node = [process.execPath, '-e', [
      ...refusing('EPERM', true),
      'try {',
      '  require(gate).storeTelemetrySetting(file, false);',
      '} catch (err) {',
      "  console.log('thrown ' + err.syscall + ' ' + err.code);",
      '}',
    ].join('\n'), GATE_PATH, file];

    const res = spawnSync(noFileBytes ? '/bin/sh' : node[0], noFileBytes
      ? ['-c', 'ulimit -f 0; exec "$@"', 'sh', ...node]
      : node.slice(1), { encoding: 'utf-8' });

    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toBe(printed);
    expect(fs.existsSync(file)).toBe(false);
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

  it('storeTelemetrySetting(on) and (off) each drop a stored install id, and neither derives one', () => {
    const file = path.join(tmp('install-id-store-'), 'opena2a', 'telemetry.json');

    expect(storeTelemetrySetting(file, true)).toEqual({ enabled: true });
    fs.writeFileSync(file, '{"enabled":false,"installId":"FAKE-ID"}\n');
    expect(storeTelemetrySetting(file, true)).toEqual({ enabled: true });
    expect(fs.readFileSync(file, 'utf-8')).toBe('{\n  "enabled": true\n}\n');
    fs.writeFileSync(file, '{"enabled":true,"installId":"FAKE-ID"}\n');
    expect(storeTelemetrySetting(file, false)).toEqual({ enabled: false });
    expect(fs.readFileSync(file, 'utf-8')).toBe('{\n  "enabled": false\n}\n');
  });

  it.each([
    ['{"enabled":true,"installId":"FAKE-ID"}', '{\n  "enabled": true\n}\n'],
    ['{"enabled":false,"installId":"FAKE-ID"}', '{\n  "enabled": false\n}\n'],
    ['{"enabled":0,"installId":"FAKE-ID"}', '{\n  "enabled": false\n}\n'],
    ['{"installId":"FAKE-ID"}', '{\n  "enabled": true\n}\n'],
  ])('dropStoredInstallId rewrites %s keeping the setting', (text, after) => {
    const file = path.join(tmp('install-id-drop-'), 'telemetry.json');
    fs.writeFileSync(file, text);

    expect(dropStoredInstallId(file)).toBe(true);
    expect(fs.readFileSync(file, 'utf-8')).toBe(after);
  });

  it.each(['{"enabled":false}', '{"enabled":true,"installId":""}', '{not json'])('dropStoredInstallId leaves %s as it was', (text) => {
    const file = path.join(tmp('install-id-drop-'), 'telemetry.json');
    fs.writeFileSync(file, text);

    expect(dropStoredInstallId(file)).toBe(false);
    expect(fs.readFileSync(file, 'utf-8')).toBe(text);
  });

  it('dropStoredInstallId creates no file where there is none', () => {
    const file = path.join(tmp('install-id-drop-'), 'opena2a', 'telemetry.json');

    expect(dropStoredInstallId(file)).toBe(false);
    expect(fs.existsSync(path.dirname(file))).toBe(false);
  });

  it.skipIf(process.platform === 'win32')('storeTelemetrySetting creates the directory 0700 and the file 0600, as the SDK does', () => {
    const file = path.join(tmp('install-id-store-'), 'opena2a', 'telemetry.json');

    storeTelemetrySetting(file, false);

    expect(fs.statSync(path.dirname(file)).mode & 0o777).toBe(0o700);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });
});
