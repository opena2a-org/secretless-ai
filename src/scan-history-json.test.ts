import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * `scan --history --json` through the built CLI (#458). The `--history` branch
 * returned before `--json` and `--format` were read, so the flag printed the
 * text report, exited 1 on a finding, and a caller parsing stdout failed on
 * `Shell History Scanner`. It now writes one JSON document with the text
 * report's exit codes, `--format json` writes the same document, and a format
 * it does not write is refused with exit 2 and nothing on stdout.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

// `secret set NAME=VALUE` is reported whatever the value's length, so the
// value can read as the placeholder it is.
const SECRET_SET_LINE = 'npx secretless-ai secret set STRIPE_KEY=not-a-real-value';
const SECRET_SET_PREVIEW = 'npx secretless-ai secret set STRIPE_KEY=[Secret in secret set NAME=VALUE REDACTED]';

const made: string[] = [];

function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

/** A home directory whose `.bash_history` holds `lines`, or none when `lines` is null. */
function home(lines: string[] | null): string {
  const dir = tmp('scan-history-json-home-');
  if (lines) fs.writeFileSync(path.join(dir, '.bash_history'), `${lines.join('\n')}\n`);
  return dir;
}

function cli(homeDir: string, args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: os.tmpdir(),
    // HOME is where the history scanner reads .bash_history and .zsh_history.
    env: { ...process.env, HOME: homeDir, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

describe('scan --history --json (#458)', () => {
  itIfBuilt('writes one JSON document with each finding, and exits 1 on a finding as the text report does', () => {
    const res = cli(home([SECRET_SET_LINE]), ['scan', '--history', '--json']);
    expect(res.status).toBe(1);
    expect(res.stderr).toBe('');
    const doc = JSON.parse(res.stdout);
    expect(doc.tool).toBe('secretless-ai');
    expect(typeof doc.version).toBe('string');
    expect(doc.findings).toEqual([{
      file: '~/.bash_history',
      line: 1,
      patternId: 'cmd-secret-set',
      patternName: 'Secret in secret set NAME=VALUE',
      preview: SECRET_SET_PREVIEW,
    }]);
    expect(doc.summary).toEqual({ total: 1, filesScanned: 1 });
    expect(res.stdout).not.toContain('Shell History Scanner');
    expect(res.stdout).not.toContain('not-a-real-value');
  });

  itIfBuilt('the flag may come before --history', () => {
    const res = cli(home([SECRET_SET_LINE]), ['scan', '--json', '--history']);
    expect(res.status).toBe(1);
    expect(JSON.parse(res.stdout).summary).toEqual({ total: 1, filesScanned: 1 });
  });

  itIfBuilt('`--format json` writes what `--json` writes', () => {
    const dir = home([SECRET_SET_LINE]);
    const viaFormat = cli(dir, ['scan', '--history', '--format', 'json']);
    const viaJson = cli(dir, ['scan', '--history', '--json']);
    expect(viaFormat.status).toBe(1);
    expect(viaJson.status).toBe(1);
    expect(JSON.parse(viaFormat.stdout)).toEqual(JSON.parse(viaJson.stdout));
  });

  itIfBuilt('a history with no credential is an empty list at exit 0', () => {
    const res = cli(home(['ls -la', 'git status']), ['scan', '--history', '--json']);
    expect(res.status).toBe(0);
    const doc = JSON.parse(res.stdout);
    expect(doc.findings).toEqual([]);
    expect(doc.summary).toEqual({ total: 0, filesScanned: 1 });
  });

  itIfBuilt('a home with no history file reports no file scanned, at exit 0 as the text report does', () => {
    const res = cli(home(null), ['scan', '--history', '--json']);
    expect(res.status).toBe(0);
    expect(JSON.parse(res.stdout).summary).toEqual({ total: 0, filesScanned: 0 });
  });

  itIfBuilt('`--format sarif` is refused with exit 2 and nothing on stdout', () => {
    const res = cli(home([SECRET_SET_LINE]), ['scan', '--history', '--format', 'sarif']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('--history has no SARIF output; give --json or --format json for JSON, or neither for text.');
    expect(res.stderr).toContain('`scan` was not run. Nothing was changed.');
  });

  itIfBuilt('a format the tool does not write is refused naming json, and two formats are refused as without --history', () => {
    const dir = home([SECRET_SET_LINE]);
    const yaml = cli(dir, ['scan', '--history', '--format', 'yaml']);
    expect(yaml.status).toBe(2);
    expect(yaml.stdout).toBe('');
    // `--history` refuses `--format sarif`, so the refusal offers json (#466).
    expect(yaml.stderr).toContain('--format needs json with --history, e.g. --format json, but was given "yaml".');
    const both = cli(dir, ['scan', '--history', '--json', '--format', 'sarif']);
    expect(both.status).toBe(2);
    expect(both.stdout).toBe('');
    expect(both.stderr).toContain('--json and --format sarif ask for two formats on one output; give one of them.');
  });

  itIfBuilt('CONTROL: without the flag the text report is printed, at exit 1', () => {
    const res = cli(home([SECRET_SET_LINE]), ['scan', '--history']);
    expect(res.status).toBe(1);
    expect(res.stdout).toContain('Shell History Scanner');
    expect(res.stdout).toContain(SECRET_SET_PREVIEW);
    expect(() => JSON.parse(res.stdout)).toThrow();
  });

  itIfBuilt('`scan --help` names --json on the --history form', () => {
    const res = cli(home(null), ['scan', '--help']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('scan --history [--json]');
  });
});
