import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * `scan-history` and `clean-history` with a path, through the built CLI
 * (#466). Neither verb takes a path and neither read one: a path given to
 * either was accepted and not used, so `scan-history ./some-dir` printed the
 * shell history report at exit 1 and `clean-history ./some-dir` redacted the
 * shell history files, neither naming ./some-dir. Each is now refused with
 * exit 2 before anything runs, as `scan --history ./some-dir` is.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

// `secret set NAME=VALUE` is reported whatever the value's length, so the
// value can read as the placeholder it is.
const SECRET_SET_LINE = 'npx secretless-ai secret set STRIPE_KEY=not-a-real-value';

const made: string[] = [];

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

/** A home directory whose `.bash_history` holds a credential. */
function home(): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'history-verb-refusals-home-')));
  made.push(dir);
  fs.writeFileSync(path.join(dir, '.bash_history'), `${SECRET_SET_LINE}\n`);
  return dir;
}

function cli(homeDir: string, args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: os.tmpdir(),
    // HOME is where both verbs read .bash_history and .zsh_history.
    env: { ...process.env, HOME: homeDir, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** The files in `dir` and the content of each, to show that nothing was written. */
function snapshot(dir: string): Record<string, string> {
  return Object.fromEntries(fs.readdirSync(dir).sort().map((name) => [name, fs.readFileSync(path.join(dir, name), 'utf-8')]));
}

describe('scan-history and clean-history refuse a path (#466)', () => {
  itIfBuilt('scan-history ./some-dir is refused with exit 2 and the path named', () => {
    const res = cli(home(), ['scan-history', './some-dir']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(
      '`scan-history` scans shell history and takes no path; to scan the path, give it to `scan`: ./some-dir',
    );
    expect(res.stderr).toContain('`scan-history` was not run. Nothing was changed.');
    expect(res.stderr).toContain('  Supported: --help\n');
  });

  for (const args of [['clean-history', '--dry-run', './some-dir'], ['clean-history', './some-dir']]) {
    itIfBuilt(`${args.join(' ')} is refused with exit 2, the path named and the history left as it is`, () => {
      const dir = home();
      const before = snapshot(dir);

      const res = cli(dir, args);
      expect(res.status).toBe(2);
      expect(res.stdout).toBe('');
      expect(res.stderr).toContain(
        '`clean-history` redacts credentials in shell history and takes no path; leave the path out: ./some-dir',
      );
      expect(res.stderr).toContain('`clean-history` was not run. Nothing was changed.');
      expect(res.stderr).toContain('  Supported: --dry-run, --help\n');
      expect(snapshot(dir)).toEqual(before);
    });
  }

  itIfBuilt('two paths are refused and both named', () => {
    const scan = cli(home(), ['scan-history', './a', './b']);
    expect(scan.status).toBe(2);
    expect(scan.stderr).toContain(
      '`scan-history` scans shell history and takes no path; to scan the paths, give each to `scan` on its own: ./a, ./b',
    );
    const clean = cli(home(), ['clean-history', './a', '--dry-run', './b']);
    expect(clean.status).toBe(2);
    expect(clean.stderr).toContain(
      '`clean-history` redacts credentials in shell history and takes no path; leave the paths out: ./a, ./b',
    );
  });

  itIfBuilt('a path is quoted where the shell needs it, and a line feed in it is escaped on the same line', () => {
    const spaced = cli(home(), ['scan-history', 'my dir']);
    expect(spaced.status).toBe(2);
    expect(spaced.stderr).toContain("give it to `scan`: 'my dir'");
    const split = cli(home(), ['clean-history', 'a\nb']);
    expect(split.status).toBe(2);
    expect(split.stderr).toContain("leave the path out: $'a\\nb'");
    expect(split.stderr.split('\n').filter((line) => line.startsWith('b'))).toEqual([]);
  });

  itIfBuilt('CONTROL: without a path, scan-history reports the credential and clean-history --dry-run counts it', () => {
    const dir = home();
    const before = snapshot(dir);

    const scan = cli(dir, ['scan-history']);
    expect(scan.status).toBe(1);
    expect(scan.stderr).toBe('');
    expect(scan.stdout).toContain('~/.bash_history:1');

    const dry = cli(dir, ['clean-history', '--dry-run']);
    expect(dry.status).toBe(0);
    expect(dry.stderr).toBe('');
    expect(dry.stdout).toContain('Lines that would be redacted: 1');
    expect(snapshot(dir)).toEqual(before);
  });
});
