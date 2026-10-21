/**
 * Two command lines that `migrate` and `backend purge` refuse before anything
 * runs (#490): `migrate` given one backend as both `--from` and `--to`, and
 * `backend purge` given a `--prefix` other than `mcp` or `secret`. Each
 * exited 1, the code for credentials found, where a command line that was
 * refused and ran nothing exits 2. An empty `--prefix` was not refused:
 * `purge` read it as no `--prefix` and purged both kinds of entry.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runBackend } from './commands/backend';
import { writeBackendConfig } from './backends/config';
import { LocalBackend } from './backends/local';

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

const savedHome = process.env.HOME;
const made: string[] = [];
function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

function cli(args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: tmp('followups-490-cwd-'),
    env: { ...process.env, HOME: tmp('followups-490-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** A command line as a shell would take it, with an empty argument as `''`. */
function shown(args: string[]): string {
  return args.map(a => (a === '' ? "''" : a)).join(' ');
}

describe('`migrate` given one backend as both --from and --to exits 2 (#490)', () => {
  // The refusal comes before a backend is built, so the Vault and GCP
  // checks that exit 1 are not reached either.
  for (const type of ['local', 'keychain', '1password', 'vault', 'gcp-sm']) {
    itIfBuilt(`\`migrate --from ${type} --to ${type}\``, () => {
      const res = cli(['migrate', '--from', type, '--to', type]);
      expect(res.status).toBe(2);
      expect(res.stderr.split('\n')).toContain(`  Source and destination backends are the same: ${type}`);
      expect(res.stdout).not.toContain('Secretless Migration');
    });
  }
});

describe('`backend purge` given a --prefix other than mcp or secret exits 2 (#490)', () => {
  const cases: Array<[string[], string]> = [
    [['backend', 'purge', '--prefix', 'nope'], "  Unknown prefix: nope. Use 'mcp' or 'secret'."],
    [['backend', 'purge', '--prefix', 'nope', '--yes'], "  Unknown prefix: nope. Use 'mcp' or 'secret'."],
    // An empty prefix is named as none, as `backend set ''` names an empty
    // type (#486). It printed `No entries to purge.` and exited 0.
    [['backend', 'purge', '--prefix', ''], "  Unknown prefix: (none). Use 'mcp' or 'secret'."],
    [['backend', 'purge', '--prefix='], "  Unknown prefix: (none). Use 'mcp' or 'secret'."],
  ];
  for (const [args, line] of cases) {
    itIfBuilt(`\`${shown(args)}\``, () => {
      const res = cli(args);
      expect(res.status).toBe(2);
      expect(res.stderr.split('\n')).toContain(line);
    });
  }
});

describe('a --prefix that `backend purge --yes` refuses deletes nothing (#490)', () => {
  const ENTRIES = { 'mcp/github': 'held-by-file', 'secret/STRIPE_KEY': 'held-by-file' };

  /**
   * A HOME whose configured backend is the encrypted file, holding one entry
   * of each kind, with the output of the command under test captured.
   */
  async function seededHome(): Promise<string[]> {
    process.env.HOME = tmp('followups-490-store-');
    writeBackendConfig('local');
    const file = new LocalBackend();
    for (const [key, value] of Object.entries(ENTRIES)) await file.store(key, value);
    const err: string[] = [];
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
    return err;
  }

  /** Every entry the encrypted file holds, read without the cache layer. */
  function held(): Promise<Record<string, string>> {
    return new LocalBackend().resolve('');
  }

  for (const value of ['nope', '']) {
    it(`\`backend purge --prefix ${shown([value])} --yes\``, async () => {
      const err = await seededHome();
      expect(await runBackend(['purge', '--prefix', value, '--yes'])).toBe(2);
      expect(err.join('\n')).toContain('Unknown prefix: ');
      // With an empty prefix, both entries were deleted at exit 0.
      expect(await held()).toEqual(ENTRIES);
    });
  }

  it('CONTROL: `backend purge --prefix mcp --yes` deletes the mcp entry alone', async () => {
    await seededHome();
    expect(await runBackend(['purge', '--prefix', 'mcp', '--yes'])).toBe(0);
    expect(await held()).toEqual({ 'secret/STRIPE_KEY': 'held-by-file' });
  });

  it('CONTROL: `backend purge --yes` with no --prefix deletes both kinds', async () => {
    await seededHome();
    expect(await runBackend(['purge', '--yes'])).toBe(0);
    expect(await held()).toEqual({});
  });
});

describe('the exit codes in docs/commands.md and docs/scanning.md name both among the cases of 2 (#490)', () => {
  for (const doc of ['commands.md', 'scanning.md']) {
    it(doc, () => {
      const text = fs.readFileSync(path.resolve(__dirname, '..', 'docs', doc), 'utf-8');
      const line = text.split('\n').find(l => l.startsWith('Exit codes: '));
      // From the first `2` on, which is the code's own clause.
      const two = line?.slice(line.indexOf('`2`'));
      expect(two).toContain('a backend type, `backend purge` prefix or cache duration it does not take');
      expect(two).toContain('one backend given to `migrate` as both `--from` and `--to`');
    });
  }
});
