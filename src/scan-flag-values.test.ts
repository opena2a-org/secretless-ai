import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VERBS } from './argv';

/**
 * A `scan` value flag whose value is another value flag, through the built CLI
 * (#469). The argv layer binds the second flag as the first one's value, but
 * the `scan` branch found each value flag by its spelling in argv and read the
 * token after it. In `scan --min-confidence --format` that found `--format`,
 * read the token after it, which does not exist, and refused with
 * `--format needs json or sarif, e.g. --format sarif, but was given "undefined".`
 * The refusal now names the flag whose value was refused, with that value.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

const NOT_RUN = '`scan` was not run. Nothing was changed.';
const HISTORY_SUPPORTED = '  Supported with --history: --format json, --help, --json';

/** What each value flag of `scan` says it needs, without `--history`. */
const NEEDS: Readonly<Record<string, string>> = {
  '--format': 'json or sarif, e.g. --format sarif',
  '--min-confidence': 'a number in [0, 1], e.g. --min-confidence 0.8',
  '--max-files': 'a positive whole number, e.g. --max-files 20000',
  '--max-file-size': 'a size, e.g. --max-file-size 20mb, 500kb, or a byte count',
};
const VALUE_FLAGS = Object.keys(NEEDS);

const made: string[] = [];

function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

function cli(args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: os.tmpdir(),
    // An empty HOME: no shell history, and no home-directory files for a scan.
    env: { ...process.env, HOME: tmp('scan-flag-values-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** The lines of a refusal that name the supported flags. */
function supportedLines(stderr: string): string[] {
  return stderr.split('\n').filter((line) => line.startsWith('  Supported'));
}

describe('a scan value flag given another value flag as its value (#469)', () => {
  it('the registry gives scan these four value flags', () => {
    // Named rather than derived, so a value flag added to `scan` shows up here
    // and its row above is a deliberate edit.
    const valued = Object.keys(VERBS.scan.flags).filter((f) => VERBS.scan.flags[f]).sort();
    expect(valued).toEqual([...VALUE_FLAGS].sort());
  });

  itIfBuilt('scan --history --min-confidence --format refuses --min-confidence for --history', () => {
    const res = cli(['scan', '--history', '--min-confidence', '--format']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(
      '--history does not use --min-confidence, which applies to a directory scan; give it without --history, or leave it out.',
    );
    expect(res.stderr).not.toContain('--format needs');
    expect(res.stderr).not.toContain('undefined');
    expect(supportedLines(res.stderr)).toEqual([HISTORY_SUPPORTED]);
  });

  // `scan --min-confidence --format` is the reported case; the other eleven
  // pairs are the same command line with other flags.
  for (const first of VALUE_FLAGS) {
    for (const second of VALUE_FLAGS.filter((f) => f !== first)) {
      itIfBuilt(`scan ${first} ${second} refuses ${first} for the value "${second}"`, () => {
        const res = cli(['scan', first, second]);
        expect(res.status).toBe(2);
        expect(res.stdout).toBe('');
        expect(res.stderr).toContain(`${first} needs ${NEEDS[first]}, but was given "${second}".`);
        expect(res.stderr).not.toContain(`${second} needs`);
        expect(res.stderr).not.toContain('undefined');
        expect(res.stderr).toContain(NOT_RUN);
      });
    }
  }

  // One test per command line, as for the pairs above, so each start of the
  // CLI has the default timeout to itself: twelve starts in one test ran up
  // to and past it on CI.
  describe('under --history, the refusal names the flag that took the value', () => {
    for (const second of VALUE_FLAGS.filter((f) => f !== '--format')) {
      itIfBuilt(`scan --history --format ${second}`, () => {
        const format = cli(['scan', '--history', '--format', second]);
        expect(format.status).toBe(2);
        expect(format.stderr).toContain(
          `--format needs json with --history, e.g. --format json, but was given "${second}".`,
        );
        expect(format.stderr).not.toContain('undefined');
      });
    }
    for (const first of VALUE_FLAGS.filter((f) => f !== '--format')) {
      for (const second of VALUE_FLAGS.filter((f) => f !== first)) {
        itIfBuilt(`scan --history ${first} ${second}`, () => {
          const res = cli(['scan', '--history', first, second]);
          expect(res.status).toBe(2);
          expect(res.stdout).toBe('');
          // The `--history` refusal names each directory-scan flag typed (#463),
          // so `second` is named beside `first` unless it is `--format`.
          expect(res.stderr).toContain(`--history does not use ${first}`);
          expect(res.stderr).not.toContain(`${second} needs`);
          expect(res.stderr).not.toContain('undefined');
        });
      }
    }
  });

  itIfBuilt('CONTROL: each value flag given a value it accepts still applies', () => {
    const dir = tmp('scan-flag-values-tree-');
    for (const args of [
      ['--format', 'json', '--min-confidence', '0.5', '--max-files', '10', '--max-file-size', '1mb'],
      ['--format=json', '--min-confidence=0.5', '--max-files=10', '--max-file-size=1mb'],
    ]) {
      const res = cli(['scan', dir, ...args]);
      expect(res.status).toBe(0);
      expect(res.stderr).toBe('');
      // `--format json` applied: stdout is one JSON document.
      expect(() => JSON.parse(res.stdout)).not.toThrow();
    }
  });

  itIfBuilt('CONTROL: a value flag given a value it refuses is refused with that value, as before', () => {
    const res = cli(['scan', '--min-confidence', '7']);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain(
      '--min-confidence needs a number in [0, 1], e.g. --min-confidence 0.8, but was given "7".',
    );
  });
});
