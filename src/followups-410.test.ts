import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { printHelp } from './commands/help';
import { runVault } from './commands/vault';
import { CLI, CLI_BARE } from './commands/utils';
import { VERBS } from './argv';

/**
 * Follow-ups from a fresh-install walkthrough (#410), the three that concern
 * what the CLI tells a user to type next:
 *
 * - The top-level help listed `warm`, `install`, `scan --include-tests`,
 *   `--include-config`, `--no-ignore` and `--min-confidence` twice each, and
 *   did not list the `telemetry` and `scan-staged` commands at all.
 * - `secretless-ai scna` printed `Unknown command: scna` and then the whole
 *   help, with no suggestion of the command meant.
 * - The `vault exec` example `vault init` prints next, and the vault help and
 *   usage repeat, ran `curl https://api.github.com/user`: the child is given
 *   the credential as `$GITHUB` and the example never read it.
 */

async function captured(fn: () => unknown): Promise<string[]> {
  const out: string[] = [];
  const push = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
  const log = vi.spyOn(console, 'log').mockImplementation(push);
  const err = vi.spyOn(console, 'error').mockImplementation(push);
  try {
    await fn();
  } finally {
    log.mockRestore();
    err.mockRestore();
  }
  return out.join('\n').split('\n');
}

/**
 * The entries of the top-level help, each as the words a user types: a line
 * that starts with the CLI name gives the words after it, and a flag under
 * "Scan options:" gives `scan <flag>`. The words end at the first run of two
 * spaces, where the description starts. "Quick start:" is left out: it picks
 * three commands from the list below it on purpose.
 */
async function helpEntries(): Promise<string[]> {
  const entries: string[] = [];
  let section = '';
  for (const line of await captured(() => printHelp())) {
    const heading = line.match(/^ {2}(\S[^:]*):/);
    if (heading) section = heading[1];
    const body = line.trim();
    if (section === 'Quick start') continue;
    if (body.startsWith(`${CLI} `)) {
      entries.push(body.slice(CLI.length + 1).split(/ {2,}/)[0].trim());
    } else if (section === 'Scan options' && body.startsWith('-')) {
      entries.push(`scan ${body.split(/ {2,}/)[0].trim()}`);
    }
  }
  return entries;
}

describe('the top-level help lists each command once (#410)', () => {
  it('lists every registered command, telemetry and scan-staged among them', async () => {
    const entries = await helpEntries();
    const missing = Object.keys(VERBS).filter(
      (verb) => !entries.some((e) => e === verb || e.startsWith(`${verb} `)),
    );
    expect(missing).toEqual([]);
  });

  it('lists no entry twice', async () => {
    const entries = await helpEntries();
    const twice = entries.filter((e, i) => entries.indexOf(e) !== i);
    expect(twice).toEqual([]);
  });

  it('the entries the walkthrough found twice are each listed once', async () => {
    const entries = await helpEntries();
    for (const entry of ['warm', 'install', 'scan --include-tests', 'scan --include-config', 'scan --no-ignore']) {
      expect(entries.filter((e) => e === entry), entry).toHaveLength(1);
    }
    expect(entries.filter((e) => e.startsWith('scan --min-confidence')), 'scan --min-confidence').toHaveLength(1);
  });
});

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

function cli(args: string[]) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-followups-410-'));
  try {
    return spawnSync(process.execPath, [CLI_PATH, ...args], {
      encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], cwd: tmp,
      env: {
        PATH: process.env.PATH ?? '', HOME: tmp, NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off', SECRETLESS_OS_KEYCHAIN: 'off',
      },
    });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

describe('an unknown command names the nearest command (#410)', () => {
  itIfBuilt('`scna` suggests `scan` and points at --help instead of printing it', () => {
    const res = cli(['scna']);

    expect(res.status).toBe(2);
    expect(res.stderr).toBe(
      'Unknown command: scna (did you mean `scan`?)\n'
      + `Run \`${CLI_BARE} --help\` for the list of commands.\n`,
    );
    expect(res.stdout).toBe('');
  });

  itIfBuilt('a mistyped top-level flag suggests the flag', () => {
    const res = cli(['--verison']);

    expect(res.status).toBe(2);
    expect(res.stderr.split('\n')[0]).toBe('Unknown command: --verison (did you mean `--version`?)');
  });

  itIfBuilt('CONTROL: a token near no command gets no suggestion', () => {
    const res = cli(['bogus']);

    expect(res.status).toBe(2);
    expect(res.stderr.split('\n')[0]).toBe('Unknown command: bogus');
  });
});

/**
 * The example reads the injected `$GITHUB` in the child's shell and hands it
 * to curl on standard input, the shape docs/how-it-works.md documents, so the
 * value is on no command line `ps` shows.
 */
const EXEC_EXAMPLE = `secretless-ai vault exec github -- sh -c 'printf "Authorization: Bearer %s\\n" "$GITHUB" | curl -s -H @- https://api.github.com/user'`;

function execLines(lines: string[]): string[] {
  return lines.filter((l) => l.includes('vault exec github'));
}

describe('the vault exec example reads the injected $GITHUB (#410)', () => {
  it('in the vault help', async () => {
    const lines = await captured(() => runVault(['--help']));
    expect(execLines(lines).length).toBeGreaterThan(0);
    for (const line of execLines(lines)) expect(line.trim()).toBe(EXEC_EXAMPLE);
  });

  it('in the usage `vault exec` prints without `--`', async () => {
    const lines = await captured(() => runVault(['exec', 'github']));
    expect(execLines(lines).length).toBeGreaterThan(0);
    for (const line of execLines(lines)) expect(line.trim()).toBe(EXEC_EXAMPLE);
  });

  let aimCoreAvailable = false;
  try {
    require.resolve('@opena2a/aim-core');
    aimCoreAvailable = true;
  } catch {
    // aim-core not installed: the init case is skipped
  }
  const itWithAimCore = aimCoreAvailable ? it : it.skip;
  let tmpHome: string | undefined;

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
    if (tmpHome) fs.rmSync(tmpHome, { recursive: true, force: true });
    tmpHome = undefined;
  });

  itWithAimCore('in the next steps `vault init` prints', async () => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-followups-410-vault-'));
    vi.stubEnv('HOME', tmpHome);
    vi.resetModules();
    const { vaultInit } = await import('./vault-core.js');
    const out: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    try {
      await vaultInit('test-agent');
    } finally {
      log.mockRestore();
    }
    const lines = out.join('\n').split('\n');
    expect(execLines(lines)).toHaveLength(1);
    expect(execLines(lines)[0].trim()).toBe(EXEC_EXAMPLE);
  });
});
