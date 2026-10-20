/**
 * Ctrl-D at a prompt read with echo off (#474). Read through readline, Ctrl-D
 * at an empty `setup` prompt ended the input: that prompt and every later one
 * were answered with nothing, and the summary was printed at once. The reader
 * that turns echo off took Ctrl-D for Enter, so `setup` showed the next prompt
 * and took one Ctrl-D for each.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PassThrough } from 'stream';
import { readHiddenLine } from './hidden-line';
import type { TtyInput } from './hidden-line';
import { runSetup } from './setup';
import { runSecret } from './commands/secrets';
import { readCredentialFromStdin } from './vault-core';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';

const dirs: string[] = [];
function tmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-474-'));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

/** A terminal's input: `setRawMode` is what turns echo off. */
function fakeTty(): { input: TtyInput & PassThrough; rawModes: boolean[] } {
  const rawModes: boolean[] = [];
  const input = new PassThrough() as TtyInput & PassThrough;
  input.isTTY = true;
  input.isRaw = false;
  input.setRawMode = (mode: boolean) => { rawModes.push(mode); input.isRaw = mode; return input; };
  return { input, rawModes };
}

/** One `readHiddenLine` at a fake terminal; `keys` are typed once the prompt is shown. */
async function readAt(keys: string) {
  const { input, rawModes } = fakeTty();
  let screen = '';
  const output = {
    write: (text: string) => {
      screen += text;
      if (text.endsWith(': ')) setImmediate(() => input.write(keys));
      return true;
    },
  };
  const result = await readHiddenLine(input, output, '  Value: ');
  return { result, screen, rawModes };
}

describe('readHiddenLine: Ctrl-D (#474)', () => {
  it('on an empty line ends the input, restores the terminal, and writes only the prompt and a newline', async () => {
    const { result, screen, rawModes } = await readAt('\u0004');
    expect(result).toEqual({ kind: 'ended' });
    expect(screen).toBe('  Value: \n');
    expect(rawModes).toEqual([true, false]);
  });

  it('on a line emptied with Backspace or Ctrl-U ends the input as well', async () => {
    expect((await readAt('ab\u007f\u007f\u0004')).result).toEqual({ kind: 'ended' });
    expect((await readAt('abc\u0015\u0004')).result).toEqual({ kind: 'ended' });
  });

  it('on a line that holds something answers with it, as Enter does', async () => {
    expect((await readAt('FAKE-typed-value-2\u0004')).result).toEqual({ kind: 'line', value: 'FAKE-typed-value-2' });
    expect((await readAt('FAKE-typed-value-2\r')).result).toEqual({ kind: 'line', value: 'FAKE-typed-value-2' });
  });

  it('Enter on an empty line is an empty answer, not the end of the input', async () => {
    expect((await readAt('\r')).result).toEqual({ kind: 'line', value: '' });
  });
});

describe('setup: Ctrl-D at an empty prompt ends the input, as it did through readline (#474)', () => {
  /** Runs setup at a fake terminal; at each prompt the next of `keys` is typed, as given (Enter when none is left). */
  async function setupAt(manifest: string, keys: string[]) {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, '.secretless'), manifest);
    const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
    const { input, rawModes } = fakeTty();
    let screen = '';
    let prompts = 0;
    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
      const text = String(chunk);
      screen += text;
      if (text.endsWith(': ')) {
        prompts++;
        const typed = keys.shift() ?? '\r';
        setImmediate(() => input.write(typed));
      }
      return true;
    }) as typeof process.stderr.write);
    const result = await runSetup(dir, { backend, interactive: true, env: {}, input });
    vi.restoreAllMocks();
    return { result, screen, prompts, rawModes, store: new SecretStore({ backend }) };
  }

  it('at the first of two required prompts: both names are missing, the second prompt is not shown, nothing is stored', async () => {
    const { result, screen, prompts, rawModes, store } = await setupAt('STRIPE_KEY\nDATABASE_URL\n', ['\u0004']);
    expect(prompts).toBe(1);
    expect(screen).toContain('  STRIPE_KEY: \n');
    expect(screen).not.toContain('DATABASE_URL');
    expect(result.set).toBe(0);
    expect(result.complete).toBe(false);
    expect(result.missingNames).toEqual(['STRIPE_KEY', 'DATABASE_URL']);
    expect(rawModes).toEqual([true, false]);
    expect(await store.listSecrets()).toEqual([]);
  });

  it('after a stored value: the open prompt and the optional one after it are answered with nothing', async () => {
    const { result, screen, prompts, store } = await setupAt(
      'STRIPE_KEY\nDATABASE_URL\nSENTRY_DSN  optional\n',
      ['FAKE-typed-value-3\r', '\u0004'],
    );
    expect(prompts).toBe(2);
    expect(screen).toContain('  DATABASE_URL: \n');
    expect(screen).not.toContain('SENTRY_DSN');
    expect(result.set).toBe(1);
    expect(result.missingNames).toEqual(['DATABASE_URL']);
    expect(result.skipped).toBe(1);
    expect(await store.getSecret('STRIPE_KEY')).toBe('FAKE-typed-value-3');
  });

  it('Ctrl-D after a typed value answers that prompt with the value, and the next prompt is shown', async () => {
    const { result, prompts, store } = await setupAt('STRIPE_KEY\nDATABASE_URL\n', ['FAKE-typed-value-4\u0004', '\r']);
    expect(prompts).toBe(2);
    expect(result.set).toBe(1);
    expect(result.missingNames).toEqual(['DATABASE_URL']);
    expect(await store.getSecret('STRIPE_KEY')).toBe('FAKE-typed-value-4');
  });

  it('input that ends answers the open prompt with what was typed and every later one with nothing', async () => {
    for (const typed of ['', 'FAKE-typed-value-6']) {
      const dir = tmpDir();
      fs.writeFileSync(path.join(dir, '.secretless'), 'STRIPE_KEY\nDATABASE_URL\n');
      const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
      const { input } = fakeTty();
      let screen = '';
      vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
        screen += String(chunk);
        if (String(chunk).endsWith(': ')) setImmediate(() => input.end(typed));
        return true;
      }) as typeof process.stderr.write);
      const result = await runSetup(dir, { backend, interactive: true, env: {}, input });
      vi.restoreAllMocks();
      expect(screen).not.toContain('DATABASE_URL');
      expect(result.missingNames).toEqual(typed ? ['DATABASE_URL'] : ['STRIPE_KEY', 'DATABASE_URL']);
      expect(await new SecretStore({ backend }).getSecret('STRIPE_KEY')).toBe(typed || undefined);
    }
  });
});

describe('secret set and vault answer Ctrl-D as they did (#474)', () => {
  function store(dir: string): SecretStore {
    const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
    return new SecretStore({ backend, annotationsPath: path.join(dir, 'secret-annotations.json') });
  }

  async function secretSetAt(keys: string) {
    const dir = tmpDir();
    const { input, rawModes } = fakeTty();
    let err = '';
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err += `${a.join(' ')}\n`; });
    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
      err += String(chunk);
      return true;
    }) as typeof process.stderr.write);
    const pending = runSecret(['set', 'API_KEY'], {
      createStore: () => store(dir),
      afterSet: () => {},
      stdinIsPiped: () => false,
      stdin: input,
    });
    input.write(keys);
    const code = await pending;
    vi.restoreAllMocks();
    return { code, err, rawModes, stored: await store(dir).getSecret('API_KEY') };
  }

  it('secret set: Ctrl-D on an empty line stores nothing and exits 1 with no value provided, as Enter on one does', async () => {
    for (const keys of ['\u0004', '\r']) {
      const res = await secretSetAt(keys);
      expect(res.code, res.err).toBe(1);
      expect(res.err).toContain('Error: no value provided.');
      expect(res.rawModes).toEqual([true, false]);
      expect(res.stored).toBeUndefined();
    }
  });

  it('secret set: Ctrl-D after a typed value stores it', async () => {
    const res = await secretSetAt('FAKE-typed-value-5\u0004');
    expect(res.code, res.err).toBe(0);
    expect(res.stored).toBe('FAKE-typed-value-5');
    expect(res.err).not.toContain('FAKE-typed-value-5');
  });

  it('vault: Ctrl-D on an empty line answers nothing, and after a typed value answers with it', async () => {
    for (const [keys, expected] of [['\u0004', ''], ['FAKE-credential-3\u0004', 'FAKE-credential-3']]) {
      const { input } = fakeTty();
      const output = { write: (text: string) => { if (text.endsWith(': ')) setImmediate(() => input.write(keys)); return true; } };
      expect(await readCredentialFromStdin('npmreg', input, output)).toBe(expected);
    }
  });
});
