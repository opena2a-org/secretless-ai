import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { LocalBackend } from './backends/local';
import type { BackendHealth, SecretBackend } from './backends/types';
import { SecretStore } from './secret-store';
import { runSecretSync } from './commands/secrets';
import { CLI } from './commands/utils';
import { findSecretValueProblem, unstorableMcpSecretError, unstorableSecretError } from './secret-value';

/**
 * #475: `Fix:` and `Verify:` lines that printed a remark in parentheses after
 * the command, as `Verify:  secretless-ai mcp-status   (shows the config file
 * for each client)` did. Pasted, bash refuses each such line with
 * ``syntax error near unexpected token `('``. Each remark is now a line of its
 * own, above or under its command. `scope check` is covered in
 * src/commands/scope.test.ts, `init` in src/followups-272.test.ts, and the
 * check of the source in src/followups-471.test.ts.
 *
 * Every store is a `LocalBackend` with an explicit key in a temporary
 * directory, so no test reaches the OS keychain.
 */

let tmp: string;
let store: SecretStore;
let out: string[];

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-475-'));
  store = new SecretStore({ backend: new LocalBackend({ storeDir: path.join(tmp, 'store'), key: 'test-key' }) });
  out = [];
  const capture = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
  vi.spyOn(console, 'log').mockImplementation(capture);
  vi.spyOn(console, 'error').mockImplementation(capture);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function printedLines(): string[] {
  return out.join('\n').split('\n');
}

describe('secret sync: each Fix line ends at its command (#475)', () => {
  /** A shared backend that holds API_KEY and nothing else. */
  const source: SecretBackend = {
    name: '1password',
    resolve: async (key): Promise<Record<string, string>> => (key === 'secret/API_KEY' ? { [key]: 'FAKE-shared-value' } : {}),
    healthCheck: async (): Promise<BackendHealth> => ({ healthy: true, latencyMs: 0 }),
  };

  function sync(only: string): Promise<number> {
    return runSecretSync(['--from', '1password', '--only', only], { store, createSource: () => source, cwd: tmp });
  }

  it('a value that differs: what the Fix does is said on the line above it', async () => {
    await store.setSecret('API_KEY', 'FAKE-local-value');

    expect(await sync('API_KEY')).toBe(1);

    const lines = printedLines();
    const fix = lines.indexOf(`  Fix:     ${CLI} secret sync --from 1password --only API_KEY --force`);
    expect(fix, lines.join('\n')).toBeGreaterThan(1);
    expect(lines.slice(fix - 2, fix + 1)).toEqual([
      "  The local value of API_KEY differs from 1password's and was left as is.",
      "  To replace it with 1password's:",
      `  Fix:     ${CLI} secret sync --from 1password --only API_KEY --force`,
    ]);
    expect(await store.getSecret('API_KEY')).toBe('FAKE-local-value');
  });

  it('a name in neither store: the other way to add it is the line under the Fix', async () => {
    expect(await sync('ABSENT')).toBe(1);

    const lines = printedLines();
    const fix = lines.indexOf(`  Fix:     ${CLI} secret set ABSENT`);
    expect(fix, lines.join('\n')).toBeGreaterThan(0);
    expect(lines.slice(fix, fix + 3)).toEqual([
      `  Fix:     ${CLI} secret set ABSENT`,
      '           or add it to 1password and sync again',
      '',
    ]);
  });
});

describe('a value that cannot be stored: the remark is a line of its own (#475)', () => {
  /** What a paste with the terminal's bracketed-paste markers captures. */
  const PASTED = '\u001b[200~FAKE-pasted-value\u001b[201~';

  it('secret set: the way to give the value is said on the line above the Fix', () => {
    const lines = unstorableSecretError('API_KEY', findSecretValueProblem(PASTED)!).message.split('\n');

    expect(lines.slice(-4)).toEqual([
      '  Verify:  secretless-ai secret list',
      '  Give the value as an argument, not a paste:',
      '  Fix:     secretless-ai secret set API_KEY=<value>',
      '           or pipe it:  cat token.txt | secretless-ai secret set API_KEY',
    ]);
  });

  it('an MCP server value: what mcp-status shows is the line under the Verify', () => {
    const lines = unstorableMcpSecretError('cursor', 'github', 'GITHUB_TOKEN', findSecretValueProblem(PASTED)!).message.split('\n');

    expect(lines.slice(-4)).toEqual([
      '  Verify:  secretless-ai mcp-status',
      '           shows the config file for each client',
      '  Fix:     correct GITHUB_TOKEN in the "github" env block of that file,',
      '           then run: secretless-ai protect-mcp',
    ]);
  });
});

describe('a local store this build cannot decrypt: each remark is the line under its command (#475)', () => {
  it('the Verify and Fix commands each end at the command', async () => {
    const dir = path.join(tmp, 'unreadable');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, 'secrets.enc'), Buffer.from('not a valid aes-256-gcm payload at all'));

    const err = await new LocalBackend({ storeDir: dir, key: 'test-key' }).resolve('secret').then(() => null, (e: unknown) => e);

    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message.split('\n').slice(-5)).toEqual([
      '  Verify:  printf \'%s %s\\n\' "$HOME" "$USER"',
      '           the key derives from these',
      '  Fix:     run under the account that wrote the store — or start a new one:',
      '           secretless-ai backend set keychain',
      '           then re-add your secrets',
    ]);
  });
});
