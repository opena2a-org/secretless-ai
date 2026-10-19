import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * `clean-history` names what it did not read (#466), through the built CLI.
 * It skipped a history file it could not read and every line longer than
 * 4096 characters, and then printed "No credentials found in shell history."
 * at exit 0, as `scan --history` did before #462. It now lists the file and
 * the lines, with the reason, as `scan --history` lists them, and says what
 * it found in the lines it read. The exit codes are unchanged.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;
// Mode 000 does not stop root, and Windows does not apply it.
const modesBind = process.platform !== 'win32' && process.getuid?.() !== 0;

// `secret set NAME=VALUE` is reported whatever the value's length, so the
// value can read as the placeholder it is.
const SET = 'npx secretless-ai secret set STRIPE_KEY=not-a-real-value';
const LONG = `curl -d "${'a'.repeat(4200)}" https://example.invalid; ${SET}`;
const CLEAN = 'No credentials found in shell history.';

const made: string[] = [];

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

/** A home directory whose `.bash_history` holds `lines`, each ended by a newline. */
function home(lines: string[]): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'clean-history-not-read-')));
  made.push(dir);
  fs.writeFileSync(path.join(dir, '.bash_history'), `${lines.join('\n')}\n`);
  return dir;
}

function cli(homeDir: string, args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: os.tmpdir(),
    // HOME is where clean-history reads .bash_history and .zsh_history.
    env: { ...process.env, HOME: homeDir, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

describe('clean-history names what it did not read (#466)', () => {
  it.skipIf(!modesBind || !fs.existsSync(CLI_PATH))('a history file with mode 000 is listed as not read, on a dry run and on a real run', () => {
    const dir = home([SET]);
    fs.chmodSync(path.join(dir, '.bash_history'), 0o000);

    for (const args of [['clean-history', '--dry-run'], ['clean-history']]) {
      const res = cli(dir, args);
      expect(res.status).toBe(0);
      expect(res.stdout).not.toContain(CLEAN);
      expect(res.stdout).toMatch(/Files scanned:\s+0/);
      expect(res.stdout).toContain('No history file was read.');
      expect(res.stdout).toContain('1 history file not read, so not known to be clean:');
      expect(res.stdout).toContain('~/.bash_history: could not be read (EACCES)');
      expect(res.stdout).toContain('Verify: ls -l ~/.bash_history');
    }
    expect(fs.existsSync(path.join(dir, '.bash_history.bak'))).toBe(false);
  });

  itIfBuilt('a credential on a line longer than 4096 characters: the line is listed by number and left as it is', () => {
    const dir = home(['ls', LONG, 'git status']);
    const before = fs.readFileSync(path.join(dir, '.bash_history'), 'utf-8');

    const dry = cli(dir, ['clean-history', '--dry-run']);
    expect(dry.status).toBe(0);
    expect(dry.stdout).not.toContain(CLEAN);
    expect(dry.stdout).toContain('Lines that would be redacted: 0');
    expect(dry.stdout).toContain('No credentials found in the lines that were read.');
    expect(dry.stdout).toContain('1 line not read, so not known to be clean:');
    expect(dry.stdout).toContain('~/.bash_history:2: longer than 4096 characters');

    const real = cli(dir, ['clean-history']);
    expect(real.status).toBe(0);
    expect(real.stdout).not.toContain(CLEAN);
    expect(real.stdout).toContain('~/.bash_history:2: longer than 4096 characters');
    expect(fs.readFileSync(path.join(dir, '.bash_history'), 'utf-8')).toBe(before);
    expect(fs.existsSync(path.join(dir, '.bash_history.bak'))).toBe(false);
  });

  itIfBuilt('a credential redacted and a line not read: the history is cleaned in the lines that were read, and the line is listed', () => {
    const dir = home([SET, LONG]);

    const res = cli(dir, ['clean-history']);
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/Lines redacted:\s+1/);
    expect(res.stdout).toContain('History cleaned in the lines that were read. Backups saved with .bak extension.');
    expect(res.stdout).not.toContain('History cleaned. Backups');
    expect(res.stdout).toContain('~/.bash_history:2: longer than 4096 characters');
    expect(fs.readFileSync(path.join(dir, '.bash_history'), 'utf-8')).toBe(
      `npx secretless-ai [REDACTED:cmd-secret-set]\n${LONG}\n`,
    );
  });

  itIfBuilt('CONTROL: a history read in full is reported as before, and lists nothing', () => {
    const clean = cli(home(['ls -la', 'git status']), ['clean-history', '--dry-run']);
    expect(clean.status).toBe(0);
    expect(clean.stdout).toContain(CLEAN);
    expect(clean.stdout).not.toContain('not read');

    const found = cli(home(['ls', SET]), ['clean-history']);
    expect(found.status).toBe(0);
    expect(found.stdout).toContain('History cleaned. Backups saved with .bak extension.');
    expect(found.stdout).not.toContain('not read');
  });
});
