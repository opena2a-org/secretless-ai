import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VERBS } from './argv';

/**
 * `scan --history` with a path or a directory-scan flag, through the built CLI
 * (#463). The `--history` branch returned before the path and these flags
 * were read, so each was accepted and had no effect: `--min-confidence 7`
 * printed the full report at exit 1 with its value unchecked, `./some-dir`
 * was not mentioned, and `--check-validity` printed the report
 * `scan --history` prints alone. Each is now refused with exit 2 and nothing
 * on stdout, as `--format sarif` is.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

// `secret set NAME=VALUE` is reported whatever the value's length, so the
// value can read as the placeholder it is.
const SECRET_SET_LINE = 'npx secretless-ai secret set STRIPE_KEY=not-a-real-value';
const NOT_RUN = '`scan` was not run. Nothing was changed.';
const HISTORY_SUPPORTED = '  Supported with --history: --format json, --help, --json';

/** The lines of a refusal that name the supported flags. */
function supportedLines(stderr: string): string[] {
  return stderr.split('\n').filter((line) => line.startsWith('  Supported'));
}

/** The flags `scan` reads for a directory only, each with a value it accepts there. */
const DIRECTORY_SCAN_FLAGS: ReadonlyArray<readonly [string, string[]]> = [
  ['--include-tests', []],
  ['--include-config', []],
  ['--explain', []],
  ['--no-ignore', []],
  ['--show-placeholders', []],
  ['--check-validity', []],
  ['--min-confidence', ['0.8']],
  ['--max-files', ['20000']],
  ['--max-file-size', ['20mb']],
];

const made: string[] = [];

function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

/** A home directory whose `.bash_history` holds a credential. */
function home(): string {
  const dir = tmp('scan-history-refusals-home-');
  fs.writeFileSync(path.join(dir, '.bash_history'), `${SECRET_SET_LINE}\n`);
  return dir;
}

function cli(args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: os.tmpdir(),
    // HOME is where the history scanner reads .bash_history and .zsh_history.
    env: { ...process.env, HOME: home(), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

describe('scan --history refuses a path and the directory-scan flags (#463)', () => {
  it('the registry gives scan these nine flags besides --history, --json and --format', () => {
    // Named rather than derived, so a flag added to `scan` shows up here and
    // its line below is a deliberate edit.
    const read = new Set(['--history', '--json', '--format']);
    const others = Object.keys(VERBS.scan.flags).filter((f) => !read.has(f)).sort();
    expect(others).toEqual(DIRECTORY_SCAN_FLAGS.map(([flag]) => flag).sort());
  });

  for (const [flag, value] of DIRECTORY_SCAN_FLAGS) {
    itIfBuilt(`${[flag, ...value].join(' ')} is refused with exit 2 and nothing on stdout`, () => {
      const res = cli(['scan', '--history', flag, ...value]);
      expect(res.status).toBe(2);
      expect(res.stdout).toBe('');
      expect(res.stderr).toContain(
        `--history does not use ${flag}, which applies to a directory scan; give it without --history, or leave it out.`,
      );
      expect(res.stderr).toContain(NOT_RUN);
      // The supported line names what --history takes, not the flag just refused.
      expect(supportedLines(res.stderr)).toEqual([HISTORY_SUPPORTED]);
    });
  }

  itIfBuilt('--min-confidence 7 is refused for --history, and without --history for its value', () => {
    const history = cli(['scan', '--history', '--min-confidence', '7']);
    expect(history.status).toBe(2);
    expect(history.stdout).toBe('');
    expect(history.stderr).toContain(
      '--history does not use --min-confidence, which applies to a directory scan; give it without --history, or leave it out.',
    );
    expect(history.stderr).not.toContain('--min-confidence needs a number');
    // CONTROL: the value check a directory scan makes is unchanged.
    const directory = cli(['scan', '.', '--min-confidence', '7']);
    expect(directory.status).toBe(2);
    expect(directory.stderr).toContain(
      '--min-confidence needs a number in [0, 1], e.g. --min-confidence 0.8, but was given "7".',
    );
    const [directorySupported] = supportedLines(directory.stderr);
    expect(directorySupported).toMatch(/^ {2}Supported: /);
    expect(directorySupported).toContain('--min-confidence <value>');
  });

  itIfBuilt('a flag given before --history is refused as one given after it', () => {
    const res = cli(['scan', '--check-validity', '--history']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('--history does not use --check-validity, which applies to a directory scan;');
  });

  itIfBuilt('several flags are named in one line, in the order typed and each once', () => {
    const res = cli(['scan', '--history', '--min-confidence', '0.8', '--explain', '--include-tests', '--explain']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(
      '--history does not use --min-confidence, --explain or --include-tests, which apply to a directory scan; '
      + 'give them without --history, or leave them out.',
    );
  });

  itIfBuilt('a path is refused with exit 2 and named', () => {
    const res = cli(['scan', '--history', './some-dir']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(
      '--history scans shell history and takes no path; give the path without --history to scan it: ./some-dir',
    );
    expect(res.stderr).toContain(NOT_RUN);
    expect(supportedLines(res.stderr)).toEqual([HISTORY_SUPPORTED]);
  });

  itIfBuilt('two paths are refused and both named', () => {
    const res = cli(['scan', './a', '--history', './b']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(
      '--history scans shell history and takes no path; scan each path on its own, without --history: ./a, ./b',
    );
  });

  itIfBuilt('a path is quoted where the shell needs it, and a line feed in it is escaped on the same line', () => {
    const spaced = cli(['scan', '--history', 'my dir']);
    expect(spaced.status).toBe(2);
    expect(spaced.stderr).toContain("give the path without --history to scan it: 'my dir'");
    const split = cli(['scan', '--history', 'a\nb']);
    expect(split.status).toBe(2);
    expect(split.stderr).toContain("give the path without --history to scan it: $'a\\nb'");
    expect(split.stderr.split('\n').filter((line) => line.startsWith('b'))).toEqual([]);
  });

  itIfBuilt('--format sarif, a flag and a path given together are refused in one message, a line for each', () => {
    const res = cli(['scan', '--history', '--format', 'sarif', '--explain', './some-dir']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    const lines = res.stderr.split('\n');
    const at = (text: string) => lines.findIndex((line) => line.includes(text));
    const sarif = at('--history has no SARIF output;');
    const flag = at('--history does not use --explain, which applies to a directory scan;');
    const operand = at('--history scans shell history and takes no path;');
    const notRun = at(NOT_RUN);
    expect(sarif).toBeGreaterThanOrEqual(0);
    expect(flag).toBe(sarif + 1);
    expect(operand).toBe(flag + 1);
    expect(notRun).toBe(operand + 1);
    expect(lines.filter((line) => line.includes(NOT_RUN))).toHaveLength(1);
    expect(supportedLines(res.stderr)).toEqual([HISTORY_SUPPORTED]);
  });

  itIfBuilt('the --format sarif refusal names what --history takes as well', () => {
    const res = cli(['scan', '--history', '--format', 'sarif']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(supportedLines(res.stderr)).toEqual([HISTORY_SUPPORTED]);
  });

  itIfBuilt('CONTROL: --history alone, with --json and with --format json still scans, at exit 1 on a finding', () => {
    const text = cli(['scan', '--history']);
    expect(text.status).toBe(1);
    expect(text.stderr).toBe('');
    expect(text.stdout).toContain('Shell History Scanner');
    for (const args of [['--json'], ['--format', 'json']]) {
      const res = cli(['scan', '--history', ...args]);
      expect(res.status).toBe(1);
      expect(res.stderr).toBe('');
      expect(JSON.parse(res.stdout).summary).toEqual({ total: 1, filesScanned: 1 });
    }
  });
});
