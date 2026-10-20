import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PassThrough } from 'stream';
import { LocalBackend } from './backends/local';
import type { BackendHealth, SecretBackend } from './backends/types';
import { Clipboard } from './clipboard';
import type { TtyInput } from './hidden-line';
import { runWithSecrets } from './run';
import { SecretStore, isSettableSecretName } from './secret-store';
import { runSecret, runSecretSync } from './commands/secrets';
import type { RunSecretOptions } from './commands/secrets';
import { CLI, CLI_BARE } from './commands/utils';

/**
 * Follow-ups to #324 (#325): a line offers `secret set NAME` only for a name
 * `secret set` takes. The store holds names that start with a digit, '_' or
 * '-' (a sync or an import writes them) and `secret set` takes a leading
 * letter only, so `run --only 9z` on a store without 9z printed
 * `Fix: secretless-ai secret set 9Z`, and that line, run as printed, was
 * refused with `Invalid secret name. ... Must start with a letter.` The same
 * held for `secret sync`, `secret show`, `secret exposed` and the refusal `run`
 * gives a stored value that holds a null byte. Also here: the leading-letter
 * rule of `secret set` itself, which no test asserted.
 *
 * Every store is a `LocalBackend` with an explicit key in a temporary
 * directory, so no test reaches the OS keychain.
 */

const INVALID_NAME = '  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n';

/** The clause that stands where `secret set NAME` would be offered. */
const cannotSet = (name: string): string =>
  `"${name}" cannot be stored by \`secret set\`, which takes a letter, then letters, digits, '_' or '-'`;

/**
 * The names a text offers to `secret set`. The clause above names the command
 * in backticks with no name after it, so it offers none.
 */
function offered(text: string): string[] {
  return [...text.matchAll(/secret set ([^\s`]+)/g)].map((m) => m[1]);
}

const fixLines = (lines: string[]): string[] => lines.filter((l) => l.startsWith('  Fix:'));

let tmp: string;
let backend: LocalBackend;
let store: SecretStore;
let out: string[];
let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-followups-325-'));
  backend = new LocalBackend({ storeDir: path.join(tmp, 'store'), key: 'test-key' });
  store = new SecretStore({ backend });
  out = [];
  const capture = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
  logSpy = vi.spyOn(console, 'log').mockImplementation(capture);
  errSpy = vi.spyOn(console, 'error').mockImplementation(capture);
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function printed(): string {
  return out.join('\n');
}

function secret(args: string[], options: Partial<RunSecretOptions> = {}): Promise<number> {
  return runSecret(args, { createStore: () => store, afterSet: () => {}, stdinIsPiped: () => false, ...options });
}

/** `secret set <name>` as a Fix line prints it, with a value on standard input. */
function setAsPrinted(name: string): Promise<number> {
  const stdin = new PassThrough();
  stdin.end('FAKE-followups-325-value\n');
  return secret(['set', name], { stdin: stdin as TtyInput, stdinIsPiped: () => true });
}

describe('`run --only` offers `secret set` only for a missing name `secret set` takes (#325)', () => {
  /** What `run --only <names>` prints: the message `loadSecrets` throws. */
  async function unmatched(only: string[]): Promise<string> {
    try {
      await store.loadSecrets(only);
    } catch (e) {
      return (e as Error).message;
    }
    throw new Error('loadSecrets resolved, but a requested name is not stored');
  }

  it('a missing name that starts with a digit gets no `secret set` Fix, and a line says why', async () => {
    const message = await unmatched(['9z']);
    const lines = message.split('\n');
    expect(lines[0]).toBe('Requested secret not found in the store: 9Z');
    expect(lines).toContain(`  ${cannotSet('9Z')}; give the name the secret is stored under.`);
    expect(lines).toContain('  Verify:  secretless-ai secret list');
    expect(fixLines(lines)).toEqual([]);
    expect(offered(message)).toEqual([]);
  });

  it('beside names `secret set` cannot take, the Fix names the first it can, and run as printed it stores that one', async () => {
    const message = await unmatched(['9z', '_y', '-x', 'a.b', 'NOT_STORED']);
    const lines = message.split('\n');
    for (const name of ['9Z', '_Y', '-X', 'A.B']) {
      expect(lines).toContain(`  ${cannotSet(name)}; give the name the secret is stored under.`);
    }
    expect(message).not.toContain(cannotSet('NOT_STORED'));
    expect(fixLines(lines)).toEqual(['  Fix:     secretless-ai secret set NOT_STORED']);
    expect(offered(message)).toEqual(['NOT_STORED']);

    expect(await setAsPrinted('NOT_STORED'), printed()).toBe(0);
    expect(await store.listSecrets()).toContain('NOT_STORED');
  });

  it('a name `secret set` takes is offered as before, with no line about the names it cannot take', async () => {
    expect(await unmatched(['NOT_STORED'])).toBe([
      'Requested secret not found in the store: NOT_STORED',
      '',
      '  Nothing was injected and the command was not run.',
      '',
      '  Verify:  secretless-ai secret list',
      '  Fix:     secretless-ai secret set NOT_STORED',
    ].join('\n'));
  });
});

describe('`run` on a stored value that holds a null byte offers `secret set` only for a name it takes (#325)', () => {
  const NUL = String.fromCharCode(0);

  /** `run -- node -e ''` against the store, and what it wrote to stderr. The child is never started. */
  async function refusal(): Promise<{ code: number; stderr: string }> {
    let stderr = '';
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      stderr += String(chunk);
      return true;
    });
    try {
      const code = await runWithSecrets('node', ['-e', ''], { backend });
      return { code, stderr };
    } finally {
      spy.mockRestore();
    }
  }

  it('a stored name that starts with a digit gets no `secret set` Fix, and a line says why', async () => {
    await backend.store('secret/9z', `FAKE-mangled${NUL}value`);
    const { code, stderr } = await refusal();
    const lines = stderr.split('\n');
    expect(code).toBe(1);
    expect(lines[0]).toBe('secretless: 9z cannot be passed in an environment variable.');
    expect(lines).toContain(`  ${cannotSet('9z')}; store it again the way it was first stored.`);
    expect(lines).toContain('  Verify:  secretless-ai secret list');
    expect(fixLines(lines)).toEqual([]);
    expect(offered(stderr)).toEqual([]);
  });

  it('beside a name `secret set` cannot take, the Fix names the first it can', async () => {
    await backend.store('secret/9z', `FAKE-mangled${NUL}value`);
    await backend.store('secret/_y', `FAKE-mangled${NUL}value`);
    await backend.store('secret/ALPHA', `FAKE-mangled${NUL}value`);
    const { code, stderr } = await refusal();
    const lines = stderr.split('\n');
    expect(code).toBe(1);
    for (const name of ['9z', '_y']) {
      expect(lines).toContain(`  ${cannotSet(name)}; store it again the way it was first stored.`);
    }
    expect(stderr).not.toContain(cannotSet('ALPHA'));
    expect(fixLines(lines)).toEqual(['  Fix:     secretless-ai secret set ALPHA']);
    expect(offered(stderr)).toEqual(['ALPHA']);
  });

  it('a name `secret set` takes is offered as before, with no line about the names it cannot take', async () => {
    await backend.store('secret/ALPHA', `FAKE-mangled${NUL}value`);
    const { code, stderr } = await refusal();
    expect(code).toBe(1);
    expect(stderr).not.toContain('cannot be stored by `secret set`');
    expect(stderr.endsWith([
      '',
      '  Verify:  secretless-ai secret list',
      '  Fix:     secretless-ai secret set ALPHA',
      '',
    ].join('\n'))).toBe(true);
  });
});

describe('`secret sync` offers `secret set` only for a missing name `secret set` takes (#325)', () => {
  /** A shared backend that holds nothing, so every selected name is in neither store. */
  const empty: SecretBackend = {
    name: '1password',
    resolve: async () => ({}),
    healthCheck: async (): Promise<BackendHealth> => ({ healthy: true, latencyMs: 0 }),
  };

  function sync(only: string): Promise<number> {
    return runSecretSync(['--from', '1password', '--only', only], { store, createSource: () => empty, cwd: tmp });
  }

  it('a missing name that starts with a digit gets no `secret set` Fix, and a line gives the half of the Fix that applies', async () => {
    expect(await sync('9z')).toBe(1);
    const lines = printed().split('\n');
    expect(lines).toContain('  Not in 1password and not stored on this machine: 9z');
    expect(lines).toContain(`  ${cannotSet('9z')}; add it to 1password and sync again.`);
    expect(lines).toContain('  Verify:  op account get');
    expect(fixLines(lines)).toEqual([]);
    expect(offered(printed())).toEqual([]);
  });

  it('beside names `secret set` cannot take, the Fix names the first it can, and run as printed it stores that one', async () => {
    expect(await sync('9z,_y,ABSENT')).toBe(1);
    const said = printed();
    const lines = said.split('\n');
    expect(lines).toContain('  Not in 1password and not stored on this machine: 9z, _y, ABSENT');
    for (const name of ['9z', '_y']) {
      expect(lines).toContain(`  ${cannotSet(name)}; add it to 1password and sync again.`);
    }
    expect(said).not.toContain(cannotSet('ABSENT'));
    expect(fixLines(lines)).toEqual([`  Fix:     ${CLI} secret set ABSENT`]);
    expect(offered(said)).toEqual(['ABSENT']);

    out.length = 0;
    expect(await setAsPrinted('ABSENT'), printed()).toBe(0);
    expect(await store.listSecrets()).toContain('ABSENT');
  });

  it('a name `secret set` takes is offered as before, with no line about the names it cannot take', async () => {
    expect(await sync('ABSENT')).toBe(1);
    expect(printed()).not.toContain('cannot be stored by `secret set`');
    expect(fixLines(printed().split('\n'))).toEqual([`  Fix:     ${CLI} secret set ABSENT`]);
  });
});

describe('`secret show` and `secret exposed` offer `secret set` only for a name it takes (#325)', () => {
  for (const name of ['9z', '_y']) {
    it(`\`secret show ${name}\`, stored with no description: no \`Record one:\` line, and a line says why`, async () => {
      await store.setSecret(name, 'FAKE-stored-by-a-sync');
      expect(await secret(['show', name])).toBe(0);
      const lines = printed().split('\n');
      expect(lines).toContain(`  ${cannotSet(name)}; no description can be recorded for it.`);
      expect(lines.filter((l) => l.startsWith('  Record one:'))).toEqual([]);
      expect(offered(printed())).toEqual([]);
    });

    it(`\`secret exposed ${name}\`, stored: the Next line offers no \`secret set\`, and storing a new value under the name closes the exposure`, async () => {
      await store.setSecret(name, 'FAKE-stored-by-a-sync');
      expect(await secret(['exposed', name, '--where', 'pasted into a chat'])).toBe(0);
      const lines = printed().split('\n');
      const next = lines.indexOf('  Next:     rotate it at the provider, then store the new value the way this one was first stored');
      expect(next, printed()).toBeGreaterThan(-1);
      expect(lines[next + 1]).toBe(`            ${cannotSet(name)}.`);
      expect(lines).toContain(`  Open:     ${CLI_BARE} secret list --needs-rotation`);
      expect(offered(printed())).toEqual([]);

      // What the Next line points at: any command that stores a new value
      // under the name ends at `setSecret`, as a sync or an import does.
      const { rotation } = await store.setSecret(name, 'FAKE-rotated-at-the-provider');
      expect(rotation.kind).toBe('closed');
    });

    it(`\`secret exposed ${name}\`, not stored: no \`secret set\` Fix, and a line says why`, async () => {
      expect(await secret(['exposed', name, '--where', 'pasted into a chat'])).toBe(1);
      const lines = printed().split('\n');
      expect(lines).toContain(`  Error: Secret not found: ${name}`);
      expect(lines).toContain(`  ${cannotSet(name)}; give the name the secret is stored under.`);
      expect(lines).toContain('  Verify:  secretless-ai secret list');
      expect(fixLines(lines)).toEqual([]);
      expect(offered(printed())).toEqual([]);
    });
  }

  it('`secret show` on a stored name `secret set` takes offers `Record one:` as before', async () => {
    await store.setSecret('API_KEY', 'FAKE-stored-value');
    expect(await secret(['show', 'API_KEY'])).toBe(0);
    expect(printed().split('\n')).toContain(`  Record one:  ${CLI} secret set API_KEY --description "what it is for" --meta app=<name>`);
    expect(printed()).not.toContain('cannot be stored by `secret set`');
  });

  it('`secret exposed` on a stored name `secret set` takes offers it as before, and run as printed it closes the exposure', async () => {
    await store.setSecret('API_KEY', 'FAKE-stored-value');
    expect(await secret(['exposed', 'API_KEY', '--where', 'pasted into a chat'])).toBe(0);
    expect(printed().split('\n')).toContain(`  Next:     rotate it at the provider, then  ${CLI_BARE} secret set API_KEY`);
    expect(printed()).not.toContain('cannot be stored by `secret set`');

    out.length = 0;
    expect(await setAsPrinted('API_KEY'), printed()).toBe(0);
    expect(printed()).toContain('  Rotated: the exposure recorded ');
  });

  it('`secret exposed` on a name that is not stored and `secret set` takes offers it as before', async () => {
    expect(await secret(['exposed', 'NOT_STORED', '--where', 'pasted into a chat'])).toBe(1);
    const lines = printed().split('\n');
    expect(fixLines(lines)).toEqual(['  Fix:     secretless-ai secret set NOT_STORED']);
    expect(printed()).not.toContain('cannot be stored by `secret set`');
  });
});

describe('`secret set` takes a name that starts with a letter (#325)', () => {
  /** A clipboard that records every command run against it. */
  function recordingClipboard() {
    const commands: string[][] = [];
    const clipboard = new Clipboard({
      platform: 'darwin',
      env: {},
      run: (command, args) => {
        commands.push([command, ...args]);
        return { status: 0, stdout: 'FAKE-clipboard-value-325' };
      },
    });
    return { clipboard, commands };
  }

  for (const name of ['9z', '_y']) {
    it(`\`secret set ${name}\` exits 1 with the refusal line, and the value on standard input is not stored`, async () => {
      expect(await setAsPrinted(name)).toBe(1);
      expect(out).toEqual([INVALID_NAME]);
      expect(await store.listSecrets()).toEqual([]);
    });

    it(`\`secret set ${name}=VALUE\` exits 1 with the refusal line, and nothing is stored`, async () => {
      expect(await secret(['set', `${name}=FAKE-inline-value-325`])).toBe(1);
      expect(out).toEqual([INVALID_NAME]);
      expect(await store.listSecrets()).toEqual([]);
    });

    it(`\`secret set ${name} --from-clipboard\` exits 1 with the refusal line, and the clipboard is not read`, async () => {
      const { clipboard, commands } = recordingClipboard();
      expect(await secret(['set', name, '--from-clipboard'], { clipboard })).toBe(1);
      expect(out).toEqual([INVALID_NAME]);
      expect(commands).toEqual([]);
      expect(await store.listSecrets()).toEqual([]);
    });
  }

  it('the exported rule is the one `secret set` applies: a name it accepts is stored, a name it refuses is not', async () => {
    const takes = ['A', 'z9', 'API_KEY', 'a-b', 'a_'];
    const refuses = ['9z', '_y', '-x', '', 'a.b', 'a b'];
    for (const name of takes) expect(isSettableSecretName(name), name).toBe(true);
    for (const name of refuses) expect(isSettableSecretName(name), name).toBe(false);

    for (const name of takes) expect(await secret(['set', `${name}=FAKE-inline-value-325`]), name).toBe(0);
    expect(await store.listSecrets()).toEqual([...takes].sort());
    out.length = 0;
    for (const name of ['9z', '_y', 'a.b', 'a b']) {
      expect(await secret(['set', `${name}=FAKE-inline-value-325`]), name).toBe(1);
    }
    expect(out).toEqual(Array(4).fill(INVALID_NAME));
    expect(await store.listSecrets()).toEqual([...takes].sort());
  });
});
