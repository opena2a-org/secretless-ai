import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { capThatClears } from './commands/core';
import { runClean } from './commands/transcript';
import { MAX_FILES_LIMIT } from './scan';
import {
  AUTOMATED_RUN_VARIABLES, telemetrySettingFile, storeTelemetrySetting, telemetryToggleLine, withToggleLine,
} from './telemetry-gate';

/**
 * Findings from the 0.21.3 fresh-user walkthrough (#127) that
 * walkthrough-followups.test.ts does not cover: the exit code of a command
 * given none of the arguments it needs, `--max-files` above its range, the
 * message for a `scan` target that is not there, the `telemetry status`
 * toggle line, and the progress line and run time of `clean`.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

const made: string[] = [];
function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

function cli(args: string[], env: NodeJS.ProcessEnv = {}) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: tmp('followups-127-cwd-'),
    env: { ...process.env, HOME: tmp('followups-127-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1', ...env },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

describe('a command given none of the arguments it needs exits 2 (#127)', () => {
  // Each printed its usage and ran nothing. `secret`, `scope`, `vault`,
  // `broker` and `watch` exited 0; `ignore`, `rules test` and the rest exited 1.
  const BARE = [
    ['secret'], ['scope'], ['vault'], ['broker'], ['watch'], ['ignore'], ['rules', 'test'],
    ['secret', 'set'], ['secret', 'get'], ['secret', 'rm'], ['secret', 'show'],
    ['scope', 'discover'], ['scope', 'check'], ['scope', 'reset'],
    ['vault', 'register'], ['vault', 'rotate'], ['vault', 'revoke'], ['vault', 'exec'],
    ['run'], ['import'], ['migrate'],
  ];
  for (const args of BARE) {
    itIfBuilt(`\`${args.join(' ')}\` prints its usage and exits 2`, () => {
      const res = cli(args);
      expect(res.status).toBe(2);
      expect(`${res.stdout}${res.stderr}`).toMatch(/Usage: /);
    });
  }

  for (const verb of ['broker', 'watch', 'vault']) {
    itIfBuilt(`CONTROL: \`${verb} --help\` asks for the usage and exits 0`, () => {
      const res = cli([verb, '--help']);
      expect(res.status).toBe(0);
    });
  }
});

describe('`scan --max-files` above its range is refused, naming the range (#127)', () => {
  it('the largest value is a million', () => {
    expect(MAX_FILES_LIMIT).toBe(1_000_000);
  });

  for (const value of ['999999999999', '1000001', '99999999999999999999']) {
    itIfBuilt(`--max-files ${value}`, () => {
      const res = cli(['scan', tmp('followups-127-scan-'), '--max-files', value]);
      expect(res.status).toBe(2);
      expect(res.stdout).toBe('');
      expect(res.stderr).toContain(
        `  --max-files needs a whole number from 1 to 1000000, e.g. --max-files 20000, but was given "${value}".`,
      );
    });
  }

  itIfBuilt('CONTROL: --max-files 1000000 runs the scan', () => {
    const res = cli(['scan', tmp('followups-127-scan-'), '--max-files', '1000000']);
    expect(res.status).toBe(0);
    expect(res.stderr).toBe('');
  });

  it('a Fix line offers no cap above the range', () => {
    expect(capThatClears(30, 2)).toBe(30);
    expect(capThatClears(0, 5000)).toBe(5001);
    expect(capThatClears(MAX_FILES_LIMIT, 5000)).toBe(MAX_FILES_LIMIT);
    expect(capThatClears(MAX_FILES_LIMIT + 1, 5000)).toBeNull();
    expect(capThatClears(10, MAX_FILES_LIMIT)).toBeNull();
  });
});

describe('a `scan` target that is not there is not called a directory (#127)', () => {
  itIfBuilt('`scan nope.js` says "File or directory not found"', () => {
    const missing = path.join(tmp('followups-127-missing-'), 'nope.js');
    const res = cli(['scan', missing]);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain(`  File or directory not found: ${missing}\n`);
    expect(res.stderr).not.toContain('Directory not found');
  });

  itIfBuilt('CONTROL: `status` takes a directory, so it still says "Directory not found"', () => {
    const missing = path.join(tmp('followups-127-missing-'), 'nope');
    const res = cli(['status', missing]);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain(`  Directory not found: ${missing}\n`);
  });
});

describe('`telemetry status` offers a toggle that changes the state shown (#127)', () => {
  const base = { automated: undefined, optedOut: false, storedOn: true };

  it('names `telemetry off` while it is on, and `telemetry on` while a stored setting turns it off', () => {
    expect(telemetryToggleLine('secretless-ai', { ...base, on: true }))
      .toBe("toggle: 'secretless-ai telemetry off'  or  OPENA2A_TELEMETRY=off");
    expect(telemetryToggleLine('secretless-ai', { ...base, on: false, storedOn: false }))
      .toBe("toggle: 'secretless-ai telemetry on'");
  });

  it('names the variable while OPENA2A_TELEMETRY turns it off, and nothing in CI', () => {
    expect(telemetryToggleLine('x', { ...base, on: false, optedOut: true })).toBe('toggle: unset OPENA2A_TELEMETRY');
    expect(telemetryToggleLine('x', { ...base, on: false, optedOut: true, storedOn: false }))
      .toBe("toggle: unset OPENA2A_TELEMETRY, then 'x telemetry on'");
    expect(telemetryToggleLine('x', { ...base, on: false, automated: 'CI' })).toBeNull();
  });

  it('replaces the helper line, keeping its colour, or drops it with the blank line above', () => {
    const status = "head\n  state:       off\n\n\u001b[2m  toggle: 'x telemetry off'  or  OPENA2A_TELEMETRY=off\u001b[22m";
    expect(withToggleLine(status, 'x', "toggle: 'x telemetry on'"))
      .toBe("head\n  state:       off\n\n\u001b[2m  toggle: 'x telemetry on'\u001b[22m");
    expect(withToggleLine(status, 'x', null)).toBe('head\n  state:       off');
  });

  itIfBuilt('a stored `telemetry off` is followed by `telemetry on`, not `telemetry off`', () => {
    const home = tmp('followups-127-telemetry-');
    storeTelemetrySetting(telemetrySettingFile({}, home), false);
    // Nothing turns it off but the stored setting: no CI or test-runner
    // variable and no OPENA2A_TELEMETRY. The address is a closed local port,
    // and a status run sends nothing.
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, NO_COLOR: '1', OPENA2A_TELEMETRY_URL: 'http://127.0.0.1:9/' };
    for (const name of ['OPENA2A_TELEMETRY', 'XDG_CONFIG_HOME', ...AUTOMATED_RUN_VARIABLES]) delete env[name];
    const res = spawnSync(process.execPath, [CLI_PATH, 'telemetry', 'status'], { encoding: 'utf-8', env });

    expect(res.status).toBe(0);
    expect(res.stdout).toContain('  state:       off');
    expect(res.stdout).toContain("  toggle: 'secretless-ai telemetry on'");
    expect(res.stdout).not.toContain("telemetry off'");
  });
});

describe('`clean` shows its progress on a terminal and prints its run time (#127)', () => {
  function transcripts(): string {
    const dir = tmp('followups-127-clean-');
    fs.writeFileSync(path.join(dir, 'a.jsonl'), '{"type":"user","message":"hello"}\n');
    fs.writeFileSync(path.join(dir, 'b.jsonl'), '{"type":"user","message":"again"}\n');
    return dir;
  }

  async function run(isTTY: boolean) {
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    const writes: string[] = [];
    let clock = 1_000;
    const code = await runClean(['--dry-run', '--path', transcripts()], {
      progressOut: { isTTY, write: (chunk: string) => writes.push(chunk) },
      // Each read of the clock moves it on 1.25 seconds: one read at the start, one at the end.
      now: () => { clock += 1_250; return clock; },
    });
    return { code, out: out.join('\n'), writes };
  }

  it('a terminal gets a line rewritten in place from 0 to every file, blanked before the report', async () => {
    const { code, out, writes } = await run(true);
    expect(code).toBe(0);
    expect(writes[0]).toContain('  Read 0 of 2 files (0%)');
    expect(writes.some((w) => w.includes('  Read 2 of 2 files (100%)'))).toBe(true);
    for (const w of writes) expect(w.startsWith('\r') && w.endsWith('\r')).toBe(true);
    expect(writes[writes.length - 1].trim()).toBe('');
    expect(out).toContain('  Scanned: 2 files in ');
  });

  it('a stream that is not a terminal gets nothing, and the report still names the run time', async () => {
    const { out, writes } = await run(false);
    expect(writes).toEqual([]);
    expect(out).toMatch(/ {2}Scanned: 2 files in \d+\.\ds\n/);
  });
});
