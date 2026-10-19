/**
 * The prompt check (#237): `hook --check-prompt` refuses a prompt that holds a
 * credential before it is sent, names the pattern or the stored secret and
 * never the value, lets a variable reference or a documented example key
 * through, and does its work in this process.
 *
 * Values are assembled at run time so the tree never carries a
 * provider-shaped literal. The CLI cases spawn the built entry point with a
 * fresh HOME; a missing build is an error naming `npm run build`, not a skip.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import { Readable } from 'stream';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  checkPromptText, matchedPatterns, storedValuesIn, refusalReason, promptTextOf, runPromptCheck,
  PROMPT_REFUSED_EXIT, MIN_STORED_VALUE_LENGTH,
} from './prompt-check';
import { SecretStore } from './secret-store';
import { LocalBackend } from './backends/local';

const CLI = path.resolve(__dirname, '..', 'dist', 'cli.js');

const GH_TOKEN = ['ghp', '_', 'Q7wZk2Lm9Rt4'.repeat(3)].join('');
const AWS_KEY = ['AK', 'IA', 'Q3MZ7TRW2XNP5KDL'].join('');
/** A stored value of no catalog format: only the stored-value comparison can find it. */
const STORED_VALUE = ['stored', 'value', 'of', 'a', 'format', 'outside', 'the', 'catalog', '0042'].join('-');

const dirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

/** A store on the local encrypted file under `dir`, holding `secrets`. */
async function storeWith(dir: string, secrets: Record<string, string>): Promise<SecretStore> {
  const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'prompt-check-test' });
  const store = new SecretStore({ backend, annotationsPath: path.join(dir, 'annotations.json') });
  for (const [name, value] of Object.entries(secrets)) await store.setSecret(name, value);
  return store;
}

interface Run { code: number; stdout: string; stderr: string }

/** `runPromptCheck` on `input`, with its streams captured. */
async function check(input: string, createStore?: () => SecretStore): Promise<Run> {
  let stdout = '';
  let stderr = '';
  const code = await runPromptCheck({
    input: Readable.from([input]),
    createStore,
    stdout: { write: (chunk: string) => { stdout += chunk; return true; } },
    stderr: { write: (chunk: string) => { stderr += chunk; return true; } },
  });
  return { code, stdout, stderr };
}

describe('matchedPatterns', () => {
  it('names the catalog pattern a value in the prompt matches, once each', () => {
    const found = matchedPatterns(`first ${GH_TOKEN} then again ${GH_TOKEN} and ${AWS_KEY}`);
    expect(found).toEqual([
      { id: 'aws-access', name: 'AWS Access Key', envPrefix: 'AWS_ACCESS_KEY_ID' },
      { id: 'github-pat', name: 'GitHub Token', envPrefix: 'GITHUB_TOKEN' },
    ]);
  });

  it('matches nothing in a variable reference, an env accessor or ordinary prose', () => {
    expect(matchedPatterns('use $GITHUB_TOKEN and ${AWS_ACCESS_KEY_ID} and process.env.OPENAI_API_KEY')).toEqual([]);
    expect(matchedPatterns('Please review this config and the notes that follow.')).toEqual([]);
  });

  it('leaves a documented example key and a placeholder-marked value through', () => {
    // The access key id the AWS docs use in their examples (patterns.ts KNOWN_EXAMPLE_KEYS).
    const docsExample = ['AK', 'IA', 'IOSFODNN7', 'EXAMPLE'].join('');
    expect(matchedPatterns(`the AWS docs use ${docsExample} as the sample id`)).toEqual([]);
    expect(matchedPatterns(`token: ${['ghp', '_', 'EXAMPLE'.repeat(6)].join('')}`)).toEqual([]);
  });

  it('finds a value that starts near the end of one scanning window and ends in the next', () => {
    const filler = 'a'.repeat(16384 - 10);
    expect(matchedPatterns(filler + GH_TOKEN).map((p) => p.id)).toEqual(['github-pat']);
  });
});

describe('storedValuesIn', () => {
  it('names the stored secrets whose value is in the text, sorted by name', () => {
    const stored = { ZETA: STORED_VALUE, ALPHA: STORED_VALUE, OTHER: 'another-stored-value-9' };
    expect(storedValuesIn(`here: ${STORED_VALUE}`, stored)).toEqual(['ALPHA', 'ZETA']);
  });

  it(`does not look for a stored value shorter than ${MIN_STORED_VALUE_LENGTH} characters`, () => {
    const short = 'abc1234';
    expect(short.length).toBeLessThan(MIN_STORED_VALUE_LENGTH);
    expect(storedValuesIn(`the word ${short} appears`, { SHORT: short })).toEqual([]);
  });
});

describe('refusalReason', () => {
  it('names the pattern and the variable to write instead, never the value', () => {
    const reason = refusalReason(checkPromptText(`key ${GH_TOKEN}`));
    expect(reason).toBe(
      'Secretless: prompt not sent: it holds a value that matches the GitHub Token pattern. '
      + 'Store the value and refer to it by name: secretless-ai secret set GITHUB_TOKEN, then write $GITHUB_TOKEN in the prompt.',
    );
    expect(reason).not.toContain(GH_TOKEN);
  });

  it('names a stored secret and the reference to write, never the value', () => {
    const reason = refusalReason(checkPromptText(`paste ${STORED_VALUE}`, { PAYMENT_KEY: STORED_VALUE }));
    expect(reason).toBe(
      'Secretless: prompt not sent: it holds the value of your stored secret PAYMENT_KEY. '
      + 'Refer to it by name instead: write $PAYMENT_KEY in the prompt.',
    );
    expect(reason).not.toContain(STORED_VALUE);
  });

  it('counts several patterns and several stored secrets, and is empty with nothing found', () => {
    const reason = refusalReason(checkPromptText(
      `${GH_TOKEN} ${AWS_KEY} ${STORED_VALUE}`,
      { A_KEY: STORED_VALUE, B_KEY: STORED_VALUE },
    ));
    expect(reason).toContain('values that match 2 credential patterns (AWS Access Key, GitHub Token)');
    expect(reason).toContain('the values of your stored secrets A_KEY, B_KEY');
    expect(reason).toContain('write $A_KEY and $B_KEY in the prompt');
    expect(refusalReason(checkPromptText('nothing here', { A_KEY: STORED_VALUE }))).toBe('');
  });
});

describe('promptTextOf', () => {
  it('takes the prompt member of the hook JSON, and otherwise the whole input', () => {
    expect(promptTextOf(JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt: 'hello' }))).toBe('hello');
    expect(promptTextOf('plain text {not json')).toBe('plain text {not json');
    expect(promptTextOf('{"other": 1}')).toBe('{"other": 1}');
  });
});

describe('runPromptCheck', () => {
  it('refuses a prompt with a credential: exit 2, the decision on stdout, the reason on stderr, no value', async () => {
    const res = await check(JSON.stringify({ prompt: `use ${GH_TOKEN}` }));
    expect(res.code).toBe(PROMPT_REFUSED_EXIT);
    const lines = res.stdout.split('\n').filter((l) => l !== '');
    expect(lines).toHaveLength(1);
    const decision = JSON.parse(lines[0]);
    expect(decision.decision).toBe('block');
    expect(decision.reason).toContain('GitHub Token');
    expect(res.stderr).toBe(decision.reason + '\n');
    expect(res.stdout + res.stderr).not.toContain(GH_TOKEN);
  });

  it('lets a prompt with a variable reference through: exit 0 and nothing written', async () => {
    const res = await check(JSON.stringify({ prompt: 'use $GITHUB_TOKEN for the request' }));
    expect(res).toEqual({ code: 0, stdout: '', stderr: '' });
  });

  it('refuses a prompt that holds a stored value of a format outside the catalog, naming the secret', async () => {
    const store = await storeWith(tempDir('secretless-prompt-'), { PAYMENT_KEY: STORED_VALUE });
    const res = await check(JSON.stringify({ prompt: `the key is ${STORED_VALUE}` }), () => store);
    expect(res.code).toBe(PROMPT_REFUSED_EXIT);
    expect(res.stderr).toContain('stored secret PAYMENT_KEY');
    expect(res.stderr).toContain('write $PAYMENT_KEY');
    expect(res.stdout + res.stderr).not.toContain(STORED_VALUE);
  });

  it('still refuses on the catalog when the store cannot be read, and lets a stored-only value through then', async () => {
    const unreadable = () => { throw new Error('keychain locked'); };
    const refused = await check(JSON.stringify({ prompt: `use ${GH_TOKEN}` }), unreadable);
    expect(refused.code).toBe(PROMPT_REFUSED_EXIT);
    const through = await check(JSON.stringify({ prompt: `use ${STORED_VALUE}` }), unreadable);
    expect(through).toEqual({ code: 0, stdout: '', stderr: '' });
  });

  it('checks plain text on stdin as the prompt, and an empty input as nothing', async () => {
    expect((await check(`raw ${AWS_KEY}`)).code).toBe(PROMPT_REFUSED_EXIT);
    expect(await check('')).toEqual({ code: 0, stdout: '', stderr: '' });
  });
});

describe('latency', () => {
  it('checks a 10 KB prompt against the catalog and 20 stored values in under 50 ms (median of 31 runs)', () => {
    const text = 'Please review this config and the notes that follow. '.repeat(200).slice(0, 10240);
    expect(Buffer.byteLength(text)).toBe(10240);
    const stored: Record<string, string> = {};
    for (let i = 0; i < 20; i++) stored[`SECRET_${i}`] = `value-${i}-${'x'.repeat(30)}`;
    const times: number[] = [];
    for (let i = 0; i < 31; i++) {
      const started = process.hrtime.bigint();
      checkPromptText(text, stored);
      times.push(Number(process.hrtime.bigint() - started) / 1e6);
    }
    times.sort((a, b) => a - b);
    expect(times[15]).toBeLessThan(50);
  });
});

describe('secretless-ai hook --check-prompt (built CLI)', () => {
  beforeAll(() => {
    if (!fs.existsSync(CLI)) {
      throw new Error(`dist/cli.js is missing at ${CLI}; run \`npm run build\` first.`);
    }
  });

  function cli(input: string, home: string): { status: number | null; stdout: string; stderr: string } {
    const res = spawnSync(process.execPath, [CLI, 'hook', '--check-prompt'], {
      input,
      env: { ...process.env, HOME: home, NO_COLOR: '1' },
      encoding: 'utf-8',
      timeout: 20_000,
    });
    return { status: res.status, stdout: res.stdout, stderr: res.stderr };
  }

  it('refuses a prompt with a credential as a UserPromptSubmit hook: exit 2, block decision, reason, no value', () => {
    const home = tempDir('secretless-prompt-cli-');
    const res = cli(JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt: `deploy with ${GH_TOKEN}` }), home);
    expect(res.status).toBe(2);
    const lines = res.stdout.split('\n').filter((l) => l !== '');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toEqual({ decision: 'block', reason: res.stderr.trimEnd() });
    expect(res.stderr).toContain('GitHub Token');
    expect(res.stdout + res.stderr).not.toContain(GH_TOKEN);
  });

  it('lets a prompt with a variable reference through with exit 0 and no output', () => {
    const home = tempDir('secretless-prompt-cli-');
    const res = cli(JSON.stringify({ prompt: 'read $GITHUB_TOKEN from the environment' }), home);
    expect(res).toEqual({ status: 0, stdout: '', stderr: '' });
  });

  it('refuses the value of a secret stored in the local file backend under HOME, naming it', async () => {
    const home = tempDir('secretless-prompt-cli-');
    // The CLI child reads its store from HOME; `local` in the config keeps it
    // on the encrypted file, whose key is derived from HOME and USER.
    fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: 'local' }));
    const savedHome = process.env.HOME;
    process.env.HOME = home;
    try {
      const store = new SecretStore({ backend: new LocalBackend(), annotationsPath: path.join(home, 'annotations.json') });
      await store.setSecret('PAYMENT_KEY', STORED_VALUE);
    } finally {
      if (savedHome === undefined) delete process.env.HOME;
      else process.env.HOME = savedHome;
    }
    const res = cli(JSON.stringify({ prompt: `charge with ${STORED_VALUE}` }), home);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain('stored secret PAYMENT_KEY');
    expect(res.stdout + res.stderr).not.toContain(STORED_VALUE);
  });
});
