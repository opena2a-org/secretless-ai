import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AzureKeyVaultTarget } from './backends/azure-kv';
import type { AzureDeps } from './backends/azure-kv';
import { LocalBackend } from './backends/local';
import { runSecretPush } from './commands/secrets';
import { SecretStore } from './secret-store';

/**
 * #481: for an HTTP 409, which `secret push --to azure-kv` reports as a
 * deleted secret that Key Vault keeps for recovery, the `Fix:` block ended in
 * the `purge` command on a line of its own. The `recover` command shares its
 * line with the `Fix:` label, so an interactive bash given the whole block
 * ran the purge and no other `az` command. The purge now follows `or,` on its
 * line, as the access-policy alternative of an HTTP 403 does.
 *
 * Each case gives lines to `bash --norc --noprofile -i` on its standard input,
 * which it reads and runs one line at a time, going on after a line it
 * refuses. `az` is a shell function that prints the words it was called with,
 * and PATH is an empty directory, so an `az` on a line runs that function and
 * never the Azure CLI.
 *
 * The store is a `LocalBackend` with an explicit key in a temporary directory,
 * so no test reaches the OS keychain. Key Vault is a stand-in for `fetch`, and
 * the Azure CLI a stand-in for the child process.
 */

// The bash on PATH, by its full path: the shell each case starts has an empty PATH.
const BASH = spawnSync('bash', ['-c', 'printf %s "$BASH"'], { encoding: 'utf-8' }).stdout ?? '';

const PURGE = 'az keyvault secret purge --vault-name kv-demo --name API-KEY';

describe('secret push --to azure-kv: a shell given the HTTP 409 Fix block does not run the purge (#481)', () => {
  let tmp: string;
  let store: SecretStore;
  let out: string[];

  beforeEach(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-481-'));
    fs.mkdirSync(path.join(tmp, 'empty-path'));
    store = new SecretStore({ backend: new LocalBackend({ storeDir: path.join(tmp, 'store'), key: 'test-key' }) });
    await store.setSecret('API_KEY', 'FAKE-push-value-481');
    out = [];
    const capture = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
    vi.spyOn(console, 'log').mockImplementation(capture);
    vi.spyOn(console, 'error').mockImplementation(capture);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  /** The Azure CLI, signed in: `az account get-access-token` prints a token. */
  const azSignedIn: AzureDeps['runChild'] = async () => ({
    status: 0,
    signal: null,
    stdout: JSON.stringify({ accessToken: 'FAKE-az-cli-token-481', expiresOn: '2026-10-20 12:00:00' }),
    stderr: '',
    timedOut: false,
    spawnError: null,
  });

  /**
   * The lines from the `Verify:` label to the blank line that ends the block,
   * for `secret push API_KEY --to azure-kv --vault kv-demo --as API-KEY`
   * answered HTTP 409 by the vault.
   */
  async function deletedSecretBlock(): Promise<string[]> {
    vi.stubGlobal('fetch', async (url: string) => {
      // No managed identity: the VM metadata address does not answer.
      if (url.startsWith('http://169.254.169.254/')) throw new TypeError('fetch failed');
      return new Response(
        JSON.stringify({ error: { code: 'Conflict', message: 'FAKE detail', innererror: { code: 'ObjectIsDeletedButRecoverable' } } }),
        { status: 409, headers: { 'Content-Type': 'application/json' } },
      );
    });
    const code = await runSecretPush(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'API-KEY'], {
      store,
      createTarget: (_type, name) => new AzureKeyVaultTarget(name ?? '', { env: {}, runChild: azSignedIn }),
    });
    expect(code).toBe(1);
    const lines = out.join('\n').split('\n');
    const start = lines.findIndex((l) => l.startsWith('  Verify:'));
    expect(start, lines.join('\n')).toBeGreaterThan(-1);
    const end = lines.indexOf('', start);
    return lines.slice(start, end === -1 ? undefined : end);
  }

  /** The `az` commands, as their words joined by spaces, that an interactive bash runs when given `lines`. */
  function ran(lines: string[]): string[] {
    expect(BASH, 'no bash on PATH').not.toBe('');
    const r = spawnSync(BASH, ['--norc', '--noprofile', '-i'], {
      input: ['az() { echo RAN az "$*"; }', ...lines, ''].join('\n'),
      encoding: 'utf-8',
      env: { PATH: path.join(tmp, 'empty-path'), HOME: tmp, HISTFILE: path.join(tmp, 'history') },
      timeout: 30_000,
    });
    expect(r.error, 'bash did not run to the end of its input').toBeUndefined();
    return r.stdout.split('\n').filter((l) => l.startsWith('RAN ')).map((l) => l.slice('RAN '.length));
  }

  it('CONTROL: given the block printed before, bash runs the purge and no other command, so a block that runs none is a measurement', () => {
    expect(ran([
      '  Verify:  az keyvault secret show-deleted --vault-name kv-demo --name API-KEY --query recoveryId -o tsv',
      '  Fix:     az keyvault secret recover --vault-name kv-demo --name API-KEY',
      '           then push again',
      '           or remove the deleted versions for good:',
      `           ${PURGE}`,
    ])).toEqual([PURGE]);
  });

  it('given the block printed now, bash runs no az command', async () => {
    expect(ran(await deletedSecretBlock())).toEqual([]);
  });

  it('each command of the block, copied from the `az` on its line to the end, runs as printed', async () => {
    const commands = (await deletedSecretBlock()).flatMap((l) => /(?:^|\s)(az .*)$/.exec(l)?.[1] ?? []);

    expect(commands).toEqual([
      'az keyvault secret show-deleted --vault-name kv-demo --name API-KEY --query recoveryId -o tsv',
      'az keyvault secret recover --vault-name kv-demo --name API-KEY',
      PURGE,
    ]);
    for (const command of commands) expect(ran([command]), command).toEqual([command]);
  });
});
