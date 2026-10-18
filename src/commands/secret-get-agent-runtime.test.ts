/**
 * `secret get --force` inside an AI-agent runtime (#445). `--force` overrides
 * the terminal check of `secret get`, for a user who pipes a value on purpose.
 * With one of the variables an AI agent sets in the commands it runs, `env`
 * and `export` refused while `secret get NAME --force` printed the value. It
 * now refuses on the same check, with the runtime line `env` prints, before a
 * store is opened, whether stdout is a pipe or a terminal.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runSecret } from './secrets';
import { runEnv } from './env-run';
import { SecretStore } from '../secret-store';
import { LocalBackend } from '../backends/local';

const VALUE = 'FAKE-VALUE-1234';
const MARKERS = ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CURSOR_TRACE_ID', 'AIDER_MODEL'];

let dir: string;
let opened: number;
let stdoutIsTTY: PropertyDescriptor | undefined;

function createStore(): SecretStore {
  opened++;
  const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
  return new SecretStore({ backend, annotationsPath: path.join(dir, 'secret-annotations.json') });
}

/** `secret get <args>` with `env` as the environment and stdout a terminal or not. */
async function get(args: string[], env: NodeJS.ProcessEnv, isTTY: boolean): Promise<{ code: number; out: string; err: string }> {
  Object.defineProperty(process.stdout, 'isTTY', { value: isTTY, configurable: true });
  const out: string[] = [];
  const err: string[] = [];
  const write = vi.spyOn(process.stdout, 'write').mockImplementation((c: unknown) => { out.push(String(c)); return true; });
  const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  const error = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
  try {
    const code = await runSecret(['get', ...args], { createStore, env });
    return { code, out: out.join(''), err: err.join('\n') };
  } finally {
    write.mockRestore();
    log.mockRestore();
    error.mockRestore();
  }
}

/** The line naming the runtime, as printed, without its indent. */
function runtimeLine(text: string): string | undefined {
  return text.split('\n').map((l) => l.trim()).find((l) => l.startsWith('An AI agent runtime is set'));
}

beforeEach(async () => {
  stdoutIsTTY = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-get-agent-'));
  await createStore().setSecret('API_KEY', VALUE);
  opened = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  if (stdoutIsTTY) Object.defineProperty(process.stdout, 'isTTY', stdoutIsTTY);
  else delete (process.stdout as { isTTY?: boolean }).isTTY;
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('secret get --force inside an AI agent runtime (#445)', () => {
  for (const marker of MARKERS) {
    for (const isTTY of [false, true]) {
      it(`refuses with ${marker} set and stdout ${isTTY ? 'a terminal' : 'a pipe'}: exit 1, no value, no store opened`, async () => {
        const res = await get(['API_KEY', '--force'], { [marker]: '1' }, isTTY);
        expect(res.code).toBe(1);
        expect(res.out).toBe('');
        expect(res.err).not.toContain(VALUE);
        expect(res.err).toContain("Refused: 'secretless-ai secret get --force' prints a secret value.");
        expect(runtimeLine(res.err)).toBe(`An AI agent runtime is set (${marker}), so this output would enter the agent's context.`);
        expect(res.err).toContain('secretless-ai run --only API_KEY -- <command>');
        expect(opened).toBe(0);
      });
    }
  }

  it('refuses --force given before the name', async () => {
    const res = await get(['--force', 'API_KEY'], { CLAUDECODE: '1' }, false);
    expect(res.code).toBe(1);
    expect(res.out).toBe('');
    expect(res.err).toContain('Refused');
    expect(opened).toBe(0);
  });

  it('offers NAME in place of a name `secret set` would not store', async () => {
    const res = await get(['\u001b[31mX', '--force'], { CLAUDECODE: '1' }, false);
    expect(res.code).toBe(1);
    expect(res.err).toContain('secretless-ai run --only NAME -- <command>');
    expect(res.err).not.toContain('\u001b');
  });

  it('names the runtime in the line `env` prints under the same marker', async () => {
    const res = await get(['API_KEY', '--force'], { CLAUDECODE: '1' }, false);

    vi.stubEnv('CLAUDECODE', '1');
    const envErr: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((c: unknown) => { envErr.push(String(c)); return true; });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    expect(await runEnv([])).toBe(1);

    expect(runtimeLine(envErr.join(''))).toBe("An AI agent runtime is set (CLAUDECODE), so this output would enter the agent's context.");
    expect(runtimeLine(res.err)).toBe(runtimeLine(envErr.join('')));
  });

  it('CONTROL: with no marker set, --force prints the value', async () => {
    const res = await get(['API_KEY', '--force'], {}, false);
    expect(res.code).toBe(0);
    expect(res.out).toBe(VALUE);
    expect(opened).toBe(1);
  });

  it('without --force, the blocked message does not offer --force inside an agent runtime', async () => {
    const res = await get(['API_KEY'], { CLAUDECODE: '1' }, false);
    expect(res.code).toBe(1);
    expect(res.out).toBe('');
    expect(res.err).toContain('secret values cannot be read in non-interactive contexts');
    expect(res.err).toContain('run -- <command>');
    expect(res.err).not.toContain('--force');
    expect(opened).toBe(0);
  });

  it('CONTROL: without --force and with no marker set, the blocked message offers --force', async () => {
    const res = await get(['API_KEY'], {}, false);
    expect(res.code).toBe(1);
    expect(res.out).toBe('');
    expect(res.err).toContain('secret get <NAME> --force');
  });
});
