/**
 * Follow-ups to #485 (#486): `ignore` given an empty pattern, a finding the
 * scan reached through a symlink under `--min-confidence` and in
 * `scan --explain`, the telemetry hint `--version` prints while telemetry is
 * off, a backend type or cache duration the tool does not take, and the
 * `--max-files` limit beside `summary.eligibleFiles` in docs/scanning.md.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from './commands/core';
import { scan, scoredPathOf, MAX_FILES_LIMIT, type ScanStats } from './scan';
import {
  AUTOMATED_RUN_VARIABLES, telemetrySettingFile, storeTelemetrySetting, withVersionHint,
} from './telemetry-gate';

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

function cli(args: string[], cwd: string = tmp('followups-486-cwd-')) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd,
    env: { ...process.env, HOME: tmp('followups-486-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** A command line as a shell would take it, with an empty argument as `''`. */
function shown(args: string[]): string {
  return args.map(a => (a === '' ? "''" : a)).join(' ');
}

describe('`ignore` given an empty pattern prints its usage and exits 2 (#486)', () => {
  // `ignore` given nothing exited 2, and these printed the same usage and
  // exited 1: the exit code was decided from the count of paths given and the
  // presence of --pattern, so an empty one counted as given.
  for (const args of [['ignore', ''], ['ignore', '--pattern', ''], ['ignore', '--pattern='], ['ignore', 'app.js', '']]) {
    itIfBuilt(`\`${shown(args)}\``, () => {
      const cwd = tmp('followups-486-ignore-');
      const res = cli(args, cwd);
      expect(res.status).toBe(2);
      expect(res.stderr).toContain('  Usage: secretless-ai ignore <path>');
      expect(fs.existsSync(path.join(cwd, '.secretlessignore'))).toBe(false);
    });
  }

  itIfBuilt("CONTROL: `ignore '' app.js` writes app.js, the pattern given last, and exits 0", () => {
    const cwd = tmp('followups-486-ignore-');
    const res = cli(['ignore', '', 'app.js'], cwd);
    expect(res.status).toBe(0);
    expect(fs.readFileSync(path.join(cwd, '.secretlessignore'), 'utf-8').split('\n')).toContain('app.js');
  });
});

// A line the gcp-service-account pattern matches. It holds no credential
// value, so the fixture is not credential-shaped.
const LINE = `SERVICE_ACCOUNT='{"type": "service_account"}'\n`;

/** `scripts/app.sh` holding LINE, and `config.yaml -> scripts/app.sh`. */
function linkedConfig(): string {
  const dir = tmp('followups-486-link-');
  fs.mkdirSync(path.join(dir, 'scripts'));
  fs.writeFileSync(path.join(dir, 'scripts/app.sh'), LINE);
  fs.symlinkSync('scripts/app.sh', path.join(dir, 'config.yaml'));
  return dir;
}

function newStats(): ScanStats {
  return { placeholdersSuppressed: 0, truncated: false, confidenceSuppressed: 0 };
}

function captureLog(): string[] {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
  return lines;
}

/** The printed lines without colour, which these tests do not assert. */
function plain(lines: string[]): string[] {
  // eslint-disable-next-line no-control-regex
  return lines.join('\n').replace(/\x1b\[[0-9;]*m/g, '').split('\n');
}

describe('a finding reached through a symlink, under a --min-confidence floor (#486)', () => {
  it('the two paths score on either side of 0.86', () => {
    // The config walk's finding for `config.yaml` is the one kept. The source
    // walk scores `scripts/app.sh` lower, so a floor between the two dropped
    // that path before the path to report was chosen.
    const [kept] = scan(linkedConfig(), { scanGlobal: false });
    expect(kept.confidence).toBeGreaterThanOrEqual(0.86);

    const alone = tmp('followups-486-alone-');
    fs.mkdirSync(path.join(alone, 'scripts'));
    fs.writeFileSync(path.join(alone, 'scripts/app.sh'), LINE);
    const [source] = scan(alone, { scanGlobal: false });
    expect(source.confidence).toBeLessThan(0.86);
  });

  for (const floor of [0.8, 0.86]) {
    it(`a floor of ${floor} keeps the path and aliases the scan reports with none`, () => {
      const dir = linkedConfig();
      const none = scan(dir, { scanGlobal: false });
      const stats = newStats();
      const floored = scan(dir, { scanGlobal: false, minConfidence: floor }, stats);
      const shape = (f: (typeof none)[number]) => ({ file: f.file, aliases: f.aliases, severity: f.severity, confidence: f.confidence });
      expect(none.map(shape)).toEqual([{ file: 'scripts/app.sh', aliases: ['config.yaml'], severity: 'critical', confidence: none[0].confidence }]);
      expect(floored.map(shape)).toEqual(none.map(shape));
      // The floor hid no credential: the one there is reported.
      expect(stats.confidenceSuppressed).toBe(0);
    });
  }

  it('a floor that hides the credential counts it once, not once per path', () => {
    const stats = newStats();
    expect(scan(linkedConfig(), { scanGlobal: false, minConfidence: 0.9 }, stats)).toEqual([]);
    expect(stats.confidenceSuppressed).toBe(1);
  });

  it('CONTROL: two files each holding the line are two credentials hidden', () => {
    const dir = tmp('followups-486-two-');
    fs.mkdirSync(path.join(dir, 'scripts'));
    fs.writeFileSync(path.join(dir, 'scripts/a.sh'), LINE);
    fs.writeFileSync(path.join(dir, 'scripts/b.sh'), LINE);
    const stats = newStats();
    expect(scan(dir, { scanGlobal: false, minConfidence: 0.9 }, stats)).toEqual([]);
    expect(stats.confidenceSuppressed).toBe(2);
  });

  it('--json gives the same path, aliases and suppressed count', async () => {
    const dir = linkedConfig();
    const json = async (minConfidence: number) => {
      const lines = captureLog();
      await runScan(dir, { json: true, minConfidence });
      vi.restoreAllMocks();
      return JSON.parse(lines.join('\n')) as {
        findings: Array<{ file: string; aliases?: string[] }>;
        summary: { total: number; confidenceSuppressed: number };
      };
    };
    const kept = await json(0.86);
    expect(kept.findings.map(f => ({ file: f.file, aliases: f.aliases }))).toEqual([{ file: 'scripts/app.sh', aliases: ['config.yaml'] }]);
    expect(kept.summary.confidenceSuppressed).toBe(0);
    const hidden = await json(0.9);
    expect(hidden.summary.total).toBe(0);
    expect(hidden.summary.confidenceSuppressed).toBe(1);
  });
});

describe('scan --explain for a finding that kept the score of a symlink path (#486)', () => {
  it('scoredPathOf names the link path the finding was scored for', () => {
    const [finding] = scan(linkedConfig(), { scanGlobal: false });
    expect(finding.file).toBe('scripts/app.sh');
    expect(scoredPathOf(finding)).toBe('config.yaml');
  });

  it('the Path line names that path, and Verify scans it', async () => {
    const dir = linkedConfig();
    const lines = captureLog();
    await runScan(dir, { explain: true });
    const out = plain(lines);
    const at = out.indexOf('         scripts/app.sh:1');
    expect(at).toBeGreaterThanOrEqual(0);
    const block = out.slice(at, out.indexOf('', at));
    expect(block).toContain('         Path: env or config file (1.00) for config.yaml: live credentials are usually kept here');
    expect(block.filter(l => l.startsWith('         Verify: '))).toEqual([
      `         Verify: npx secretless-ai scan ${path.join(dir, 'config.yaml')}`,
    ]);
  });

  it('the Verify target, scanned alone, reports the severity and confidence the finding was reported with', () => {
    const dir = linkedConfig();
    const [reported] = scan(dir, { scanGlobal: false });
    const [verified] = scan(path.join(dir, 'config.yaml'), { scanGlobal: false });
    expect({ severity: verified.severity, confidence: verified.confidence })
      .toEqual({ severity: reported.severity, confidence: reported.confidence });
    // The path printed above it, the one Verify scanned, reports another.
    const [printed] = scan(path.join(dir, 'scripts/app.sh'), { scanGlobal: false });
    expect({ severity: printed.severity, confidence: printed.confidence })
      .not.toEqual({ severity: reported.severity, confidence: reported.confidence });
  });

  it('CONTROL: a link path that scored the same as the path reported is not named, and Verify scans the path reported', async () => {
    const dir = tmp('followups-486-alias-');
    fs.mkdirSync(path.join(dir, 'src'));
    fs.writeFileSync(path.join(dir, 'src/app.ts'), 'export const account = { "type": "service_account" };\n');
    fs.symlinkSync('src', path.join(dir, '.alias'), 'dir');
    const [finding] = scan(dir, { scanGlobal: false });
    expect(finding.file).toBe('src/app.ts');
    expect(scoredPathOf(finding)).toBeUndefined();

    const lines = captureLog();
    await runScan(dir, { explain: true });
    const out = plain(lines);
    const at = out.indexOf('         src/app.ts:1');
    const block = out.slice(at, out.indexOf('', at));
    expect(block.find(l => l.startsWith('         Path: '))).not.toContain(' for ');
    expect(block.filter(l => l.startsWith('         Verify: '))).toEqual([
      `         Verify: npx secretless-ai scan ${path.join(dir, 'src/app.ts')}`,
    ]);
  });

  it('CONTROL: a file flagged for existing is listed under the path reported', async () => {
    const dir = tmp('followups-486-bundle-');
    fs.mkdirSync(path.join(dir, 'real'));
    fs.writeFileSync(path.join(dir, 'real/backup.secretless-bundle'), 'not a real bundle\n');
    fs.symlinkSync('real', path.join(dir, 'link'), 'dir');
    const lines = captureLog();
    await runScan(dir, { explain: true });
    const out = plain(lines);
    const at = out.indexOf('         real/backup.secretless-bundle:1');
    expect(at).toBeGreaterThanOrEqual(0);
    expect(out[at + 1]).toBe('         Also linked as: link/backup.secretless-bundle');
    const block = out.slice(at, out.indexOf('', at));
    expect(block.filter(l => l.startsWith('         Verify: '))).toEqual([
      `         Verify: ls -l ${path.join(dir, 'real/backup.secretless-bundle')}`,
    ]);
  });
});

describe('`--version` names what turns telemetry on while it is off (#486)', () => {
  const helper = (state: 'on' | 'off') =>
    `secretless-ai 1.0.0\nTelemetry: ${state} (opt-out: OPENA2A_TELEMETRY=off  •  details: opena2a.org/telemetry)`;
  const base = { automated: undefined, optedOut: false, storedOn: true };

  it('a stored `telemetry off` is followed by `telemetry on`', () => {
    expect(withVersionHint(helper('off'), 'x', { ...base, on: false, storedOn: false }))
      .toBe("secretless-ai 1.0.0\nTelemetry: off (turn on: 'x telemetry on'  •  details: opena2a.org/telemetry)");
  });

  it('OPENA2A_TELEMETRY is named to unset, then `telemetry on` when it is stored off as well', () => {
    expect(withVersionHint(helper('off'), 'x', { ...base, on: false, optedOut: true }))
      .toBe('secretless-ai 1.0.0\nTelemetry: off (turn on: unset OPENA2A_TELEMETRY  •  details: opena2a.org/telemetry)');
    expect(withVersionHint(helper('off'), 'x', { ...base, on: false, optedOut: true, storedOn: false }))
      .toBe("secretless-ai 1.0.0\nTelemetry: off (turn on: unset OPENA2A_TELEMETRY, then 'x telemetry on'  •  details: opena2a.org/telemetry)");
  });

  it('under CI or a test runner, where nothing given here turns it on, the details alone', () => {
    expect(withVersionHint(helper('off'), 'x', { ...base, on: false, automated: 'CI' }))
      .toBe('secretless-ai 1.0.0\nTelemetry: off (details: opena2a.org/telemetry)');
  });

  it('CONTROL: while it is on, the opt-out is kept', () => {
    expect(withVersionHint(helper('on'), 'x', { ...base, on: true })).toBe(helper('on'));
  });

  it('the colour the helper gives the line is kept', () => {
    const coloured = '\u001b[2mTelemetry: \u001b[2moff\u001b[22m\u001b[2m (opt-out: OPENA2A_TELEMETRY=off  •  details: d)\u001b[22m\u001b[22m';
    expect(withVersionHint(coloured, 'x', { ...base, on: false, storedOn: false }))
      .toBe("\u001b[2mTelemetry: \u001b[2moff\u001b[22m\u001b[2m (turn on: 'x telemetry on'  •  details: d)\u001b[22m\u001b[22m");
  });

  it('the hint replaced is the one the versionLine helper prints', async () => {
    const { versionLine } = await import('@opena2a/cli-ui');
    const line = versionLine({ tool: 'x', version: '1.0.0', telemetry: { enabled: false, policyURL: 'https://opena2a.org/telemetry' } });
    const out = withVersionHint(line, 'x', { ...base, on: false, storedOn: false });
    expect(out).toContain("turn on: 'x telemetry on'  •  details: opena2a.org/telemetry");
    expect(out).not.toContain('opt-out');
  });

  itIfBuilt('a stored `telemetry off`: the line names `telemetry on`, not OPENA2A_TELEMETRY=off', () => {
    const home = tmp('followups-486-telemetry-');
    storeTelemetrySetting(telemetrySettingFile({}, home), false);
    // Nothing turns it off but the stored setting: no CI or test-runner
    // variable and no OPENA2A_TELEMETRY. The address is a closed local port,
    // and a `--version` run sends nothing.
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, NO_COLOR: '1', OPENA2A_TELEMETRY_URL: 'http://127.0.0.1:9/' };
    for (const name of ['OPENA2A_TELEMETRY', 'XDG_CONFIG_HOME', 'SECRETLESS_CLI_PREFIX', ...AUTOMATED_RUN_VARIABLES]) delete env[name];
    const res = spawnSync(process.execPath, [CLI_PATH, '--version'], { encoding: 'utf-8', env });

    expect(res.status).toBe(0);
    expect(res.stdout).toContain("Telemetry: off (turn on: 'secretless-ai telemetry on'  •  details: opena2a.org/telemetry)");
    expect(res.stdout).not.toContain('opt-out');
  });
});

describe('a backend type or cache duration the tool does not take exits 2 (#486)', () => {
  // Each was refused before anything ran and exited 1, the code for
  // credentials found.
  const cases: Array<[string[], string]> = [
    [['backend', 'set', 'nope'], "  Unknown backend type: nope. Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'."],
    [['migrate', '--from', 'nope', '--to', 'local'], '  Unknown backend type: nope. Valid: local, keychain, 1password, vault, gcp-sm'],
    [['migrate', '--from', 'local', '--to', 'nope'], '  Unknown backend type: nope. Valid: local, keychain, 1password, vault, gcp-sm'],
    [['cache', 'ttl', 'nope'], '  Invalid duration: "nope". Use: 5m, 1h, 1d, 300, or off'],
  ];
  for (const [args, line] of cases) {
    itIfBuilt(`\`${args.join(' ')}\``, () => {
      const res = cli(args);
      expect(res.status).toBe(2);
      expect(res.stderr.split('\n')).toContain(line);
    });
  }

  itIfBuilt("`backend set ''` names the type it was given as `(none)`, as `backend set` does", () => {
    // It printed `Unknown backend type: .`, naming nothing.
    for (const args of [['backend', 'set', ''], ['backend', 'set']]) {
      const res = cli(args);
      expect(res.status).toBe(2);
      expect(res.stderr.split('\n')).toContain("  Unknown backend type: (none). Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.");
    }
  });

  itIfBuilt('CONTROL: `cache ttl 5m` sets the TTL and exits 0', () => {
    const res = cli(['cache', 'ttl', '5m']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('  Cache TTL set to ');
  });
});

describe('docs/scanning.md names the --max-files limit beside summary.eligibleFiles (#486)', () => {
  it('each sentence that offers summary.eligibleFiles as a --max-files value names the limit', () => {
    // `scan` refuses --max-files above the limit with exit 2, so the value
    // the page offered could be refused.
    const page = fs.readFileSync(path.resolve(__dirname, '..', 'docs', 'scanning.md'), 'utf-8');
    const offers = page.split(/(?<=\.)\s+/).filter(s => s.includes('`summary.eligibleFiles`') && s.includes('`--max-files` value'));
    expect(offers.length).toBeGreaterThan(0);
    for (const sentence of offers) expect(sentence).toContain(String(MAX_FILES_LIMIT));
  });
});
