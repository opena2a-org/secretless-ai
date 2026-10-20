import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * `scan --history` names what it did not read (#462), through the built CLI.
 * It matches the last 10000 lines of each history file, skips a line longer
 * than 4096 characters, and skipped a history file it could not read; none of
 * the three was reported, so each printed "No credentials found in shell
 * history." at exit 0, and `--json` wrote the summary of a clean history. The
 * text report and the JSON document now list each, with the reason. The exit
 * codes are unchanged: 0 with no credential found, 1 with one.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;
// Mode 000 does not stop root, and Windows does not apply it.
const modesBind = process.platform !== 'win32' && process.getuid?.() !== 0;

// `secret set NAME=VALUE` is reported whatever the value's length, so the
// value can read as the placeholder it is.
const SET = 'npx secretless-ai secret set STRIPE_KEY=not-a-real-value';
const CLEAN = 'No credentials found in shell history.';

const made: string[] = [];

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

/** A home directory whose `.bash_history` holds `lines`, each ended by a newline. */
function home(lines: string[] | null): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'scan-history-not-read-')));
  made.push(dir);
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

function json(homeDir: string) {
  const res = cli(homeDir, ['scan', '--history', '--json']);
  return { status: res.status, doc: JSON.parse(res.stdout) };
}

describe('scan --history names what it did not read (#462)', () => {
  itIfBuilt('a credential on line 1 followed by 10000 lines: the line before the window is listed, and clean-history counts it', () => {
    const dir = home([SET, ...Array(10000).fill('ls')]);

    const text = cli(dir, ['scan', '--history']);
    expect(text.status).toBe(0);
    expect(text.stdout).not.toContain(CLEAN);
    expect(text.stdout).toContain('No credentials found in the lines that were read.');
    expect(text.stdout).toContain('1 line not read, so not known to be clean:');
    expect(text.stdout).toContain('~/.bash_history:1: before the last 10000 lines');
    // The remark under the command, not after it (#471).
    expect(text.stdout).toContain('  Verify: npx secretless-ai clean-history --dry-run\n          clean-history has no 10000-line limit\n');

    const { status, doc } = json(dir);
    expect(status).toBe(0);
    expect(doc.summary).toEqual({ total: 0, filesScanned: 1 });
    expect(doc.notRead).toEqual({
      files: [],
      lines: [{ file: '~/.bash_history', firstLine: 1, lastLine: 1, count: 1, reason: 'before the last 10000 lines' }],
    });

    // The Verify line's command finds the credential the scan did not read.
    const before = fs.readFileSync(path.join(dir, '.bash_history'), 'utf-8');
    const dry = cli(dir, ['clean-history', '--dry-run']);
    expect(dry.status).toBe(0);
    expect(dry.stdout).toContain('Lines that would be redacted: 1');
    expect(fs.readFileSync(path.join(dir, '.bash_history'), 'utf-8')).toBe(before);
  });

  itIfBuilt('a credential on a line longer than 4096 characters: the line is listed by number', () => {
    const dir = home(['ls', `curl -d "${'a'.repeat(4200)}" https://example.invalid; ${SET}`, 'git status']);

    const text = cli(dir, ['scan', '--history']);
    expect(text.status).toBe(0);
    expect(text.stdout).not.toContain(CLEAN);
    expect(text.stdout).toContain('1 line not read, so not known to be clean:');
    expect(text.stdout).toContain('~/.bash_history:2: longer than 4096 characters');

    const { status, doc } = json(dir);
    expect(status).toBe(0);
    expect(doc.notRead).toEqual({
      files: [],
      lines: [{ file: '~/.bash_history', firstLine: 2, lastLine: 2, count: 1, reason: 'longer than 4096 characters' }],
    });
  });

  itIfBuilt('the text report lists ten runs and counts the rest, and the JSON document lists the twelve', () => {
    const long = `curl -d "${'a'.repeat(4200)}" https://example.invalid`;
    // Twelve over-length lines, each followed by a short one: twelve runs.
    const dir = home(Array.from({ length: 12 }, () => [long, 'ls']).flat());

    const text = cli(dir, ['scan', '--history']);
    expect(text.status).toBe(0);
    expect(text.stdout).toContain('12 lines not read, so not known to be clean:');
    expect(text.stdout).toContain('~/.bash_history:19: longer than 4096 characters');
    expect(text.stdout).not.toContain('~/.bash_history:21:');
    expect(text.stdout).toContain('… and 2 more');

    const { doc } = json(dir);
    expect(doc.notRead.lines.map((run: { firstLine: number }) => run.firstLine)).toEqual(
      Array.from({ length: 12 }, (_, i) => 2 * i + 1),
    );
  });

  it.skipIf(!modesBind || !fs.existsSync(CLI_PATH))('a history file with mode 000 is listed as not read, and its document differs from a home with no history file', () => {
    const dir = home([SET]);
    fs.chmodSync(path.join(dir, '.bash_history'), 0o000);

    const text = cli(dir, ['scan', '--history']);
    expect(text.status).toBe(0);
    expect(text.stdout).not.toContain(CLEAN);
    expect(text.stdout).toContain('Files scanned: 0');
    expect(text.stdout).toContain('No history file was read.');
    expect(text.stdout).toContain('1 history file not read, so not known to be clean:');
    expect(text.stdout).toContain('~/.bash_history: could not be read (EACCES)');
    expect(text.stdout).toContain('Verify: ls -l ~/.bash_history');

    const unreadable = json(dir);
    expect(unreadable.status).toBe(0);
    expect(unreadable.doc.summary).toEqual({ total: 0, filesScanned: 0 });
    expect(unreadable.doc.notRead).toEqual({
      files: [{ file: '~/.bash_history', reason: 'could not be read (EACCES)' }],
      lines: [],
    });

    const none = json(home(null));
    expect(none.doc.summary).toEqual(unreadable.doc.summary);
    expect(none.doc.notRead).toEqual({ files: [], lines: [] });
  });

  it.skipIf(!modesBind || !fs.existsSync(CLI_PATH))('under a HOME that ends in a slash, the file is ~/.bash_history and its Verify command lists it (#466)', () => {
    const dir = home([SET]);
    fs.chmodSync(path.join(dir, '.bash_history'), 0o000);
    const slashed = `${dir}/`;

    const text = cli(slashed, ['scan', '--history']);
    expect(text.status).toBe(0);
    expect(text.stdout).not.toContain('~.bash_history');
    expect(text.stdout).toContain('~/.bash_history: could not be read (EACCES)');
    const verify = text.stdout.split('\n').map((line) => line.trim()).filter((line) => line.startsWith('Verify: '));
    expect(verify).toEqual(['Verify: ls -l ~/.bash_history']);
    // The command as printed, run by a shell with the same HOME, lists the file.
    const ls = spawnSync('sh', ['-c', 'ls -l ~/.bash_history'], {
      encoding: 'utf-8',
      env: { PATH: process.env.PATH, HOME: slashed },
    });
    expect(ls.status).toBe(0);
    expect(ls.stdout).toContain('.bash_history');

    const unreadable = cli(slashed, ['scan', '--history', '--json']);
    expect(JSON.parse(unreadable.stdout).notRead.files).toEqual([{ file: '~/.bash_history', reason: 'could not be read (EACCES)' }]);

    fs.chmodSync(path.join(dir, '.bash_history'), 0o600);
    const found = cli(slashed, ['scan', '--history']);
    expect(found.status).toBe(1);
    expect(found.stdout).toContain('~/.bash_history:1');
    expect(found.stdout).not.toContain('~.bash_history');
  });

  itIfBuilt('a finding and lines not read: both are reported, at exit 1 as for a finding alone', () => {
    const dir = home([SET, ...Array(9999).fill('ls'), SET]);

    const text = cli(dir, ['scan', '--history']);
    expect(text.status).toBe(1);
    expect(text.stdout).toContain('Found 1 credential(s):');
    expect(text.stdout).toContain('~/.bash_history:10001');
    expect(text.stdout).toContain('~/.bash_history:1: before the last 10000 lines');

    const { status, doc } = json(dir);
    expect(status).toBe(1);
    expect(doc.findings.map((f: { line: number }) => f.line)).toEqual([10001]);
    expect(doc.notRead.lines).toEqual([
      { file: '~/.bash_history', firstLine: 1, lastLine: 1, count: 1, reason: 'before the last 10000 lines' },
    ]);
  });

  itIfBuilt('CONTROL: a history read in full is reported clean, and lists nothing', () => {
    const dir = home(['ls -la', 'git status']);

    const text = cli(dir, ['scan', '--history']);
    expect(text.status).toBe(0);
    expect(text.stdout).toContain(CLEAN);
    expect(text.stdout).not.toContain('not read');

    const { status, doc } = json(dir);
    expect(status).toBe(0);
    expect(doc.notRead).toEqual({ files: [], lines: [] });
  });
});
