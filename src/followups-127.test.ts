import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { capThatClears, runScan } from './commands/core';
import { runClean } from './commands/transcript';
import { init, managedHookState } from './init';
import { MAX_FILES_LIMIT, newScanStats, scan } from './scan';
import {
  AUTOMATED_RUN_VARIABLES, telemetrySettingFile, storeTelemetrySetting, telemetryToggleLine, withToggleLine,
} from './telemetry-gate';

/**
 * Findings from the 0.21.3 fresh-user walkthrough (#127) that
 * walkthrough-followups.test.ts does not cover: the exit code of a command
 * given none of the arguments it needs, `--max-files` above its range, the
 * message for a `scan` target that is not there, the `telemetry status`
 * toggle line, the progress line and run time of `clean`, the version line in
 * the files `init` writes, the credential variables its instruction block
 * leaves out, and a file `scan` reads through a link out of the scan root.
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
  vi.unstubAllEnvs();
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

  // `backend set` with no type named the types it takes, set nothing and
  // exited 1. An empty type counts as none, as an empty pattern does for
  // `rules test`.
  for (const [label, args] of [['`backend set`', ['backend', 'set']], ["`backend set ''`", ['backend', 'set', '']]] as const) {
    itIfBuilt(`${label} names the backend types and exits 2`, () => {
      const res = cli([...args]);
      expect(res.status).toBe(2);
      expect(res.stderr).toContain("Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.");
      expect(res.stdout).not.toContain('Backend set to');
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

describe('the files `init` writes name the version that wrote them (#127)', () => {
  // None of them did, so nothing told which release wrote the guard a project runs.
  const VERSION: string = require('../package.json').version;
  const GUARD = path.join('.claude', 'hooks', 'secretless-guard.sh');
  const CHECK = path.join('.claude', 'hooks', 'secretless-output-check.cjs');

  it('the guard hook, the output check and the CLAUDE.md block each carry a line naming it', () => {
    const dir = tmp('followups-127-init-');
    init(dir);
    expect(fs.readFileSync(path.join(dir, GUARD), 'utf-8'))
      .toContain(`# Managed by secretless-ai. Do not edit manually.\n# Written by secretless-ai ${VERSION}\n`);
    expect(fs.readFileSync(path.join(dir, CHECK), 'utf-8'))
      .toContain(`// Managed by secretless-ai. Do not edit manually.\n// Written by secretless-ai ${VERSION}\n`);
    expect(fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf-8'))
      .toContain(`<!-- secretless:managed -->\n## Secretless Mode\n<!-- Written by secretless-ai ${VERSION} -->\n`);
  });

  it('a hook whose line names another version differs from the one this version writes', () => {
    const dir = tmp('followups-127-init-');
    init(dir);
    for (const rel of [GUARD, CHECK]) {
      const file = path.join(dir, rel);
      expect(managedHookState(file)).toBe('current');
      fs.writeFileSync(file, fs.readFileSync(file, 'utf-8').replace(`Written by secretless-ai ${VERSION}\n`, 'Written by secretless-ai 0.0.0\n'));
      expect(managedHookState(file)).toBe('differs');
    }
  });
});

describe('the instruction block `init` writes names no credential variable (#127)', () => {
  // It listed each known credential variable set where `init` ran, in a file
  // that is usually committed. The values are placeholders.
  const POINTER = '`npx secretless-ai verify` names the ones it knows that this shell sets, without their values.';

  function initWithVariablesSet(prepare: (dir: string) => void = () => {}): string {
    vi.stubEnv('ANTHROPIC_API_KEY', 'not-a-real-token');
    vi.stubEnv('STRIPE_SECRET_KEY', 'not-a-real-token');
    const dir = tmp('followups-127-init-');
    prepare(dir);
    init(dir);
    return dir;
  }

  it('CLAUDE.md names neither variable and says which command names them', () => {
    const block = fs.readFileSync(path.join(initWithVariablesSet(), 'CLAUDE.md'), 'utf-8');
    expect(block).not.toContain('ANTHROPIC_API_KEY');
    expect(block).not.toContain('STRIPE_SECRET_KEY');
    expect(block).not.toContain('Available API keys');
    expect(block).toContain(POINTER);
  });

  it("Cursor's rule file names neither variable", () => {
    const dir = initWithVariablesSet((d) => fs.mkdirSync(path.join(d, '.cursor')));
    const rule = fs.readFileSync(path.join(dir, '.cursor', 'rules', 'secretless.mdc'), 'utf-8');
    expect(rule).toContain('<!-- secretless:managed -->');
    expect(rule).not.toContain('ANTHROPIC_API_KEY');
    expect(rule).not.toContain('STRIPE_SECRET_KEY');
    expect(rule).toContain(POINTER);
  });
});

describe('a file `scan` reads through a link out of the scan root is listed, with its real path (#127)', () => {
  // A line the gcp-service-account pattern matches. It holds no credential
  // value, so the fixture is not credential-shaped.
  const LINE = 'export const account = { "type": "service_account" };\n';

  /** `<base>/proj/<name>`, a relative link to `<base>/shared/<name>`, which holds `content`. */
  function linkedOut(name: string, content: string): { proj: string; real: string } {
    const base = tmp('followups-127-link-');
    fs.mkdirSync(path.join(base, 'proj'));
    fs.mkdirSync(path.join(base, 'shared'));
    const real = path.join(base, 'shared', name);
    fs.writeFileSync(real, content);
    fs.symlinkSync(path.join('..', 'shared', name), path.join(base, 'proj', name));
    return { proj: path.join(base, 'proj'), real };
  }

  function captureLog(): string[] {
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    return lines;
  }

  /** The printed lines without colour. */
  function plain(lines: string[]): string[] {
    // eslint-disable-next-line no-control-regex
    return lines.join('\n').replace(/\x1b\[[0-9;]*m/g, '').split('\n');
  }

  it('the finding carries the real path, and the stats list the link with it', () => {
    const { proj, real } = linkedOut('app.ts', LINE);
    const stats = newScanStats();
    const findings = scan(proj, { scanGlobal: false }, stats);
    expect(findings.map(f => ({ file: f.file, realPath: f.realPath }))).toEqual([{ file: 'app.ts', realPath: real }]);
    expect(stats.outOfRootFiles).toEqual([{ path: 'app.ts', realPath: real }]);
    // The directory links not followed are a list of their own.
    expect(stats.outOfRoot).toEqual([]);
  });

  it('a linked file skipped for size is listed as skipped, not as read', () => {
    const { proj } = linkedOut('app.ts', LINE);
    const stats = newScanStats();
    expect(scan(proj, { scanGlobal: false, maxFileSizeBytes: 10 }, stats)).toEqual([]);
    expect(stats.oversize.map(o => o.path)).toEqual(['app.ts']);
    expect(stats.outOfRootFiles).toEqual([]);
  });

  it('CONTROL: a file reached by its own path has no realPath and lists nothing', () => {
    const dir = tmp('followups-127-link-');
    fs.writeFileSync(path.join(dir, 'app.ts'), LINE);
    const stats = newScanStats();
    const findings = scan(dir, { scanGlobal: false }, stats);
    expect(findings.map(f => f.file)).toEqual(['app.ts']);
    expect('realPath' in findings[0]).toBe(false);
    expect(stats.outOfRootFiles).toEqual([]);
  });

  it('--json counts and lists the link, and a clean file read through it leaves exit 0', async () => {
    const { proj, real } = linkedOut('notes.ts', 'export const n = 1;\n');
    const lines = captureLog();
    const code = await runScan(proj, { json: true });
    const doc = JSON.parse(lines.join('\n'));
    expect(code).toBe(0);
    expect(doc.summary.total).toBe(0);
    expect(doc.summary.outOfRootFiles).toBe(1);
    expect(doc.outOfRootFileLinks).toEqual([{ path: 'notes.ts', realPath: real }]);
    expect(doc.summary.outOfRoot).toBe(0);
  });

  it('the text report gives the real path under the finding and lists the link', async () => {
    const { proj, real } = linkedOut('app.ts', LINE);
    const lines = captureLog();
    const code = await runScan(proj, {});
    const out = plain(lines);
    expect(code).toBe(1);
    const at = out.findIndex(l => l.endsWith(' app.ts:1'));
    expect(at).toBeGreaterThan(-1);
    expect(out[at + 1]).toMatch(/^ {2}\S Links to: /);
    expect(out[at + 1].slice(out[at + 1].indexOf('Links to: '))).toBe(`Links to: ${real} (outside the scan root)`);
    const heading = out.indexOf('  1 file read through a link out of the scan root:');
    expect(heading).toBeGreaterThan(-1);
    expect(out[heading + 1]).toBe(`    ${path.join(proj, 'app.ts')} -> ${real}`);
  });

  it('--explain gives the real path under the finding', async () => {
    const { proj, real } = linkedOut('app.ts', LINE);
    const lines = captureLog();
    await runScan(proj, { explain: true });
    expect(plain(lines)).toContain(`         Links to: ${real} (outside the scan root)`);
  });

  it('the Fix of a finding in a .env read through the link imports the real file', () => {
    const { proj, real } = linkedOut('.env', LINE);
    const findings = scan(proj, { scanGlobal: false });
    expect(findings).toHaveLength(1);
    expect(findings[0].fix).toContain(`npx secretless-ai import ${real}, delete the line`);
  });
});
