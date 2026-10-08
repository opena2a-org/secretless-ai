/**
 * `secret set NAME --from-clipboard` stores a key copied from a web page
 * without it reaching argv, the screen or shell history, and clears the
 * clipboard afterwards; `secret set NAME` on a terminal prompts with echo
 * off (#234).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PassThrough } from 'stream';
import { runSecret } from './secrets';
import type { RunSecretOptions } from './secrets';
import { SecretStore } from '../secret-store';
import { LocalBackend } from '../backends/local';
import { prepareArgv } from '../argv';
import { Clipboard } from '../clipboard';
import type { ClipboardRunner } from '../clipboard';
import { PASTE_END, PASTE_START } from '../hidden-line';
import type { TtyInput } from '../hidden-line';

/** 40 characters, the length of the token pasted in #104. */
const TOKEN = 'FAKEtoken0123456789abcdefghijklmnopqrstu';

let dir: string;

function store(): SecretStore {
  const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
  return new SecretStore({ backend, annotationsPath: path.join(dir, 'secret-annotations.json') });
}

interface Captured { code: number; out: string; err: string }

async function run(args: string[], options: Partial<RunSecretOptions> = {}): Promise<Captured> {
  const out: string[] = [];
  const err: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  const error = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
  const write = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => { err.push(String(chunk)); return true; });
  try {
    const code = await runSecret(args, { createStore: store, afterSet: () => {}, stdinIsPiped: () => false, ...options });
    return { code, out: out.join('\n'), err: err.join('') };
  } finally {
    log.mockRestore();
    error.mockRestore();
    write.mockRestore();
  }
}

/** A clipboard held in memory, recording every command line run against it. */
function fakeClipboard(initial: string, opts: { missing?: boolean; afterFirstRead?: string; platform?: NodeJS.Platform } = {}) {
  const state = { text: initial, reads: 0, clears: 0, commands: [] as string[][] };
  const run: ClipboardRunner = (command, args, capture) => {
    state.commands.push([command, ...args]);
    if (opts.missing) return { status: null, stdout: '', errorCode: 'ENOENT' };
    if (capture) {
      const text = state.text;
      state.reads++;
      if (state.reads === 1 && opts.afterFirstRead !== undefined) state.text = opts.afterFirstRead;
      return { status: 0, stdout: text };
    }
    state.clears++;
    state.text = '';
    return { status: 0, stdout: '' };
  };
  return { state, clipboard: new Clipboard({ platform: opts.platform ?? 'darwin', env: {}, run }) };
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-set-input-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('secret set --from-clipboard', () => {
  it('stores the clipboard value; it is absent from argv, stdout and stderr, and the clipboard is cleared', async () => {
    const { state, clipboard } = fakeClipboard(`${TOKEN}\n`);
    const args = ['set', 'STRIPE_SECRET_KEY', '--from-clipboard'];
    const res = await run(args, { clipboard });

    expect(res.code, res.err).toBe(0);
    expect(await store().getSecret('STRIPE_SECRET_KEY')).toBe(TOKEN);
    expect(res.out).toContain('Stored: STRIPE_SECRET_KEY (40 chars, alphanumeric, from the clipboard)');
    expect(res.out).toContain('Clipboard: cleared.');
    expect(state.text).toBe('');
    // Absent from every stream: the command line typed, every command line run, and both outputs.
    expect(args.join(' ')).not.toContain(TOKEN);
    expect(state.commands.flat().join(' ')).not.toContain(TOKEN);
    expect(res.out).not.toContain(TOKEN);
    expect(res.err).not.toContain(TOKEN);
  });

  it('reports an open exposure like the typed form: the same value says Still exposed, a new value says Rotated', async () => {
    const rotated = 'FAKEtokenZYXWVUTSRQPONMLKJIHGFEDCBA9876543';
    expect((await run(['set', `API_KEY=${TOKEN}`])).code).toBe(0);
    expect((await run(['exposed', 'API_KEY', '--where', 'pasted into a chat'])).code).toBe(0);

    const same = await run(['set', 'API_KEY', '--from-clipboard'], { clipboard: fakeClipboard(TOKEN).clipboard });
    expect(same.code, same.err).toBe(0);
    expect(same.out).toContain('Stored: API_KEY (40 chars, alphanumeric, from the clipboard)');
    expect(same.out).toMatch(/Still exposed: this is the value that was already stored/);
    // The Fix line repeats the form the user ran, so a paste is answered with a paste.
    expect(same.out).toMatch(/Fix: +replace the key at its provider, then +secretless-ai secret set API_KEY --from-clipboard +with the new value/);
    expect(store().getAnnotation('API_KEY')!.meta.exposedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    const fresh = await run(['set', 'API_KEY', '--from-clipboard'], { clipboard: fakeClipboard(rotated).clipboard });
    expect(fresh.code, fresh.err).toBe(0);
    expect(fresh.out).toMatch(/Rotated: the exposure recorded .* is closed \(rotatedAt /);
    const meta = store().getAnnotation('API_KEY')!.meta;
    expect(meta.exposedAt).toBeUndefined();
    expect(meta.rotatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(await store().getSecret('API_KEY')).toBe(rotated);

    for (const res of [same, fresh]) {
      expect(res.out + res.err).not.toContain(TOKEN);
      expect(res.out + res.err).not.toContain(rotated);
    }
  });

  it('leaves the clipboard alone when it changed after the value was read', async () => {
    const { state, clipboard } = fakeClipboard(TOKEN, { afterFirstRead: 'a newer copy' });
    const res = await run(['set', 'API_KEY', '--from-clipboard'], { clipboard });
    expect(res.code, res.err).toBe(0);
    expect(await store().getSecret('API_KEY')).toBe(TOKEN);
    expect(state.clears).toBe(0);
    expect(state.text).toBe('a newer copy');
    expect(res.out).toContain('Clipboard: left as is. It changed after the value was read.');
  });

  it('--keep-clipboard leaves the value in the clipboard', async () => {
    const { state, clipboard } = fakeClipboard(TOKEN);
    const res = await run(['set', 'API_KEY', '--from-clipboard', '--keep-clipboard'], { clipboard });
    expect(res.code, res.err).toBe(0);
    expect(await store().getSecret('API_KEY')).toBe(TOKEN);
    expect(state.clears).toBe(0);
    expect(state.text).toBe(TOKEN);
  });

  it('an empty clipboard exits 1 with a Fix line and stores nothing', async () => {
    const { clipboard } = fakeClipboard(' \n');
    const res = await run(['set', 'API_KEY', '--from-clipboard'], { clipboard });
    expect(res.code).toBe(1);
    expect(res.err).toContain('The clipboard is empty. Nothing was stored.');
    expect(res.err).toMatch(/Fix: +copy the key again, then run: secretless-ai secret set API_KEY --from-clipboard/);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });

  it('a missing clipboard tool exits 1 with a Fix line naming the tool to install, and stores nothing', async () => {
    const { state, clipboard } = fakeClipboard(TOKEN, { missing: true, platform: 'linux' });
    const res = await run(['set', 'API_KEY', '--from-clipboard'], { clipboard });
    expect(res.code).toBe(1);
    expect(res.err).toContain('No clipboard tool was found (tried xclip, xsel, wl-paste). Nothing was stored.');
    expect(res.err).toMatch(/Fix: +install wl-clipboard \(Wayland\) or xclip \(X11\)/);
    expect(state.commands.map((c) => c[0])).toEqual(['xclip', 'xsel', 'wl-paste']);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });

  it('is refused together with NAME=VALUE, and nothing is read or stored', async () => {
    const { state, clipboard } = fakeClipboard(TOKEN);
    const res = await run(['set', 'API_KEY=typed-value-123', '--from-clipboard'], { clipboard });
    expect(res.code).toBe(2);
    expect(res.err).toContain('NAME=VALUE cannot also give one. Nothing was stored.');
    expect(state.reads).toBe(0);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });

  it('is refused together with piped stdin, and nothing is read or stored', async () => {
    const { state, clipboard } = fakeClipboard(TOKEN);
    const res = await run(['set', 'API_KEY', '--from-clipboard'], { clipboard, stdinIsPiped: () => true });
    expect(res.code).toBe(2);
    expect(res.err).toContain('stdin is a pipe or a file that may carry another one. Nothing was stored.');
    expect(state.reads).toBe(0);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });

  it('--keep-clipboard without --from-clipboard is refused rather than ignored', async () => {
    const res = await run(['set', 'API_KEY=typed-value-123', '--keep-clipboard']);
    expect(res.code).toBe(2);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });

  it('is refused on a subcommand that does not read it', async () => {
    const res = await run(['list', '--from-clipboard']);
    expect(res.code).toBe(2);
    expect(res.err).toMatch(/--from-clipboard is read by `secret set`, not by `secret list`/);
  });

  it('argv accepts both flags for `secret`', () => {
    const p = prepareArgv('secret', ['secret', 'set', 'A', '--from-clipboard', '--keep-clipboard']);
    expect(p.errors).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')('reads and clears through the platform tool, with the value only on its pipes', async () => {
    // Stand-ins for pbpaste and pbcopy on PATH. Each logs its own argv.
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const clip = path.join(dir, 'clip');
    const argvLog = path.join(dir, 'argv.log');
    fs.writeFileSync(clip, TOKEN);
    fs.writeFileSync(path.join(bin, 'pbpaste'), `#!/bin/sh\necho "pbpaste $*" >> "${argvLog}"\ncat "${clip}"\n`, { mode: 0o755 });
    fs.writeFileSync(path.join(bin, 'pbcopy'), `#!/bin/sh\necho "pbcopy $*" >> "${argvLog}"\ncat > "${clip}"\n`, { mode: 0o755 });
    const clipboard = new Clipboard({ platform: 'darwin', env: { PATH: `${bin}:/usr/bin:/bin` } });

    const res = await run(['set', 'API_KEY', '--from-clipboard'], { clipboard });
    expect(res.code, res.err).toBe(0);
    expect(await store().getSecret('API_KEY')).toBe(TOKEN);
    expect(fs.readFileSync(clip, 'utf-8')).toBe('');
    const argv = fs.readFileSync(argvLog, 'utf-8');
    expect(argv).toContain('pbcopy');
    expect(argv).not.toContain(TOKEN);
    expect(res.out + res.err).not.toContain(TOKEN);
  });
});

/** A terminal that the test types into. */
function fakeTty(): { input: TtyInput & PassThrough; rawModes: boolean[] } {
  const rawModes: boolean[] = [];
  const input = new PassThrough() as TtyInput & PassThrough;
  input.isTTY = true;
  input.isRaw = false;
  input.setRawMode = (mode: boolean) => { rawModes.push(mode); input.isRaw = mode; return input; };
  return { input, rawModes };
}

describe('secret set NAME at a terminal prompt', () => {
  it('stores a bracketed paste of a 40-character token as exactly 40 characters, with nothing echoed', async () => {
    const { input, rawModes } = fakeTty();
    const pending = run(['set', 'API_KEY'], { stdin: input });
    input.write(`${PASTE_START}${TOKEN}${PASTE_END}`);
    input.write('\r');
    const res = await pending;

    expect(res.code, res.err).toBe(0);
    const stored = await store().getSecret('API_KEY');
    expect(stored).toBe(TOKEN);
    expect(stored).toHaveLength(40);
    expect(rawModes).toEqual([true, false]);
    expect(res.err).toContain('Enter value for API_KEY (input hidden): ');
    // No typed or pasted character reached the terminal.
    expect(res.err).not.toContain(TOKEN.slice(0, 8));
    expect(res.out).not.toContain(TOKEN);
  });

  it('strips a paste marker split across two reads, and applies Backspace', async () => {
    const { input } = fakeTty();
    const pending = run(['set', 'API_KEY'], { stdin: input });
    input.write(`${PASTE_START.slice(0, 3)}`);
    input.write(`${PASTE_START.slice(3)}${TOKEN}x\u007f${PASTE_END.slice(0, 2)}`);
    input.write(`${PASTE_END.slice(2)}\r`);
    const res = await pending;
    expect(res.code, res.err).toBe(0);
    expect(await store().getSecret('API_KEY')).toBe(TOKEN);
  });

  it('Ctrl-C cancels, restores the terminal and stores nothing', async () => {
    const { input, rawModes } = fakeTty();
    const pending = run(['set', 'API_KEY'], { stdin: input });
    input.write(`${TOKEN.slice(0, 10)}\u0003`);
    const res = await pending;
    expect(res.code).toBe(130);
    expect(res.err).toContain('Cancelled. Nothing was stored.');
    expect(rawModes).toEqual([true, false]);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });
});
