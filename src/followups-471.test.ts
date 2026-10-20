import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawn, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { PassThrough } from 'stream';
import { scanToSarif } from './sarif';
import type { ScanFinding } from './scan';
import { probeCredential, type ProbeFetch } from './validity';
import { runSecret } from './commands/secrets';
import { runBackend } from './commands/backend';
import { CLI } from './commands/utils';
import { exportBundle, importBundle } from './bundle-transfer';
import type { KdfParams } from './bundle';
import type { WritableSecretBackend } from './backends/types';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';
import { runSetup, HIDDEN_INPUT_NOTE } from './setup';
import { readCredentialFromStdin } from './vault-core';
import type { TtyInput } from './hidden-line';

/**
 * Follow-ups from a walkthrough of the 0.23.1 package (#471), the ones that
 * change what the tool prints:
 *
 * - docs/scanning.md gave `9.0` for a `critical` finding and `7.0` for a
 *   `high` one, and did not say that a SARIF rule carries the highest
 *   severity of its findings, so a `high` finding of a pattern also found at
 *   `critical` is shown in the Critical band.
 * - `scan --check-validity` named the class `TypeError` where a proxy had
 *   refused the request.
 * - `Fix:` and `Verify:` lines ended in a `# remark`, which an interactive zsh
 *   passes to the command as arguments.
 * - `secret get NAME`, refused without a terminal, offered `<NAME>`, and a
 *   second `import` of a bundle offered `import <bundle> --force`; pasted,
 *   each placeholder is a shell redirection.
 * - `backend set` offered a bare `migrate`, which prints only its usage line.
 * - `env --help` and `setup --help` kept a layout of their own.
 * - The README sample of `init` did not say where it was captured.
 * - `setup`, `vault register` and `vault rotate` read a typed value with echo
 *   on, so it stayed on the screen.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const CLI_PATH = path.join(REPO_ROOT, 'dist', 'cli.js');
const VALIDITY_PATH = path.join(REPO_ROOT, 'dist', 'validity.js');
const itIfBuilt = fs.existsSync(CLI_PATH) && fs.existsSync(VALIDITY_PATH) ? it : it.skip;

const dirs: string[] = [];
function tmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-471-'));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

/** console.log, console.error and process.stderr.write, collected in order, while `run` runs. */
async function captured(run: () => Promise<number>): Promise<{ code: number; text: string }> {
  let text = '';
  const line = (...a: unknown[]): void => { text += `${a.map(String).join(' ')}\n`; };
  vi.spyOn(console, 'log').mockImplementation(line);
  vi.spyOn(console, 'error').mockImplementation(line);
  vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    text += String(chunk);
    return true;
  }) as typeof process.stderr.write);
  try {
    return { code: await run(), text };
  } finally {
    vi.restoreAllMocks();
  }
}

describe('scan --format sarif: a rule carries the highest severity of its findings (#471)', () => {
  const finding = (over: Partial<ScanFinding>): ScanFinding => ({
    file: 'client.js',
    line: 1,
    patternId: 'openai-proj',
    patternName: 'OpenAI Project Key',
    severity: 'high',
    preview: '',
    fix: 'Move to env var OPENAI_API_KEY.',
    confidence: 0.9,
    confidenceTier: 'high',
    looksLikeFixture: false,
    ...over,
  });

  it('one pattern in .env (critical) and client.js (high) is one rule at 9.0, and the client.js result says high', () => {
    const doc = scanToSarif({
      version: '0.0.0-test',
      projectDir: os.tmpdir(),
      findings: [finding({ file: '.env', severity: 'critical' }), finding({})],
      summary: { total: 2, truncated: false },
    });
    const { rules } = doc.runs[0].tool.driver;
    expect(rules).toHaveLength(1);
    expect(rules[0].properties['security-severity']).toBe('9.0');
    expect(doc.runs[0].results.map((r) => [r.locations[0].physicalLocation.artifactLocation.uri, r.properties.severity]))
      .toEqual([['.env', 'critical'], ['client.js', 'high']]);
  });

  it('docs/scanning.md says that, and where the finding\'s own severity is', () => {
    const doc = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'scanning.md'), 'utf-8');
    expect(doc).toContain('a rule carries the highest severity of its findings in the scan');
    expect(doc).toContain('`9.0` when one of them is `critical`, and `7.0` when all are `high`');
    expect(doc).toContain("the finding's own severity is its result's `properties.severity`");
  });
});

describe('scan --check-validity names why a request got no answer (#471)', () => {
  const VALUE = 'not-a-real-token';
  const failing = (err: unknown): ProbeFetch => async () => { throw err; };
  /** `err` with `cause` set, as fetch sets it; ES2020 has no `cause` option. */
  const causedBy = <T extends Error>(err: T, cause: unknown): T => Object.assign(err, { cause });

  it('a proxy that refuses the tunnel: the status it answered, where the class TypeError was named', async () => {
    // The chain Node's fetch throws for a local proxy that answers CONNECT
    // with 403 (Node 26): `TypeError: fetch failed`, caused by an error whose
    // code is the number 0, caused by undici's AbortError naming the status.
    const tunnel = Object.assign(new Error('Proxy response (403) !== 200 when HTTP Tunneling'), { name: 'AbortError', code: 'UND_ERR_ABORTED' });
    const cancelled = Object.assign(causedBy(new Error('Request was cancelled.'), tunnel), { code: 0 });
    const result = await probeCredential('github-pat', VALUE, { fetchImpl: failing(causedBy(new TypeError('fetch failed'), cancelled)) });
    expect(result).toEqual({ state: 'unknown', host: 'api.github.com', detail: 'no answer from api.github.com (the proxy answered 403)' });
  });

  it('a network error two causes down is named by its code', async () => {
    const refused = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:9'), { code: 'ECONNREFUSED' });
    const err = causedBy(new TypeError('fetch failed'), causedBy(new Error('wrapped'), refused));
    expect((await probeCredential('github-pat', VALUE, { fetchImpl: failing(err) })).detail)
      .toBe('no answer from api.github.com (ECONNREFUSED)');
  });

  it('with no code in the chain, the reason is not the class name TypeError', async () => {
    const err = causedBy(new TypeError('fetch failed'), new Error('bad port'));
    expect((await probeCredential('github-pat', VALUE, { fetchImpl: failing(err) })).detail)
      .toBe('no answer from api.github.com (error)');
  });

  /**
   * The same through Node's own fetch: a child process sends one request
   * through a proxy on 127.0.0.1 that answers CONNECT with 403, to a `.invalid`
   * host that resolves nowhere, and hands the error it gets to the probe. No
   * value is sent: the probe's fetch only rethrows that error. A Node that
   * does not route fetch through HTTPS_PROXY under NODE_USE_ENV_PROXY sends
   * the proxy nothing, and the case is skipped there.
   */
  itIfBuilt('through Node fetch and a local proxy that answers CONNECT with 403', async (ctx) => {
    const connects: string[] = [];
    const proxy = net.createServer((socket) => {
      socket.once('data', (chunk) => {
        connects.push(String(chunk).split('\r\n')[0]);
        socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
      });
      socket.on('error', () => {});
    });
    await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
    const port = (proxy.address() as net.AddressInfo).port;
    const child = [
      'const { probeCredential } = require(process.argv[1]);',
      '(async () => {',
      '  let failure;',
      "  try { await fetch('https://api.sendgrid.invalid/v3/scopes', { redirect: 'manual' }); } catch (err) { failure = err; }",
      "  const result = await probeCredential('github-pat', 'not-a-real-token', { fetchImpl: async () => { throw failure; } });",
      '  process.stdout.write(JSON.stringify(result));',
      '})();',
    ].join('\n');
    try {
      const stdout = await new Promise<string>((resolve, reject) => {
        const proc = spawn(process.execPath, ['-e', child, VALIDITY_PATH], {
          env: { PATH: process.env.PATH ?? '', NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: `http://127.0.0.1:${port}` },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        let out = '';
        proc.stdout.on('data', (chunk) => { out += String(chunk); });
        const timer = setTimeout(() => proc.kill(), 20_000);
        proc.on('error', reject);
        proc.on('close', () => { clearTimeout(timer); resolve(out); });
      });
      if (connects.length === 0) ctx.skip();
      expect(connects[0]).toMatch(/^CONNECT api\.sendgrid\.invalid:443 /);
      expect(JSON.parse(stdout)).toEqual({
        state: 'unknown',
        host: 'api.github.com',
        detail: 'no answer from api.github.com (the proxy answered 403)',
      });
    } finally {
      proxy.close();
    }
  }, 30_000);
});

describe('Fix and Verify lines in the source have no space-separated `#` remark after the command (#471)', () => {
  function sourceFiles(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) return sourceFiles(full);
      return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') && !entry.name.endsWith('.test-support.ts') ? [full] : [];
    });
  }

  it('no Fix or Verify line in the source has a space-separated `#` remark after its command', () => {
    // An interactive zsh does not take `#` as a comment unless
    // INTERACTIVE_COMMENTS is set, so pasted, the remark's words become
    // arguments of the command: `npm install   # and check node -v is
    // >= 20.19.0` also wrote its output to a file named `=`.
    const hits = sourceFiles(path.join(REPO_ROOT, 'src')).flatMap((file) => fs.readFileSync(file, 'utf-8')
      .split('\n')
      .flatMap((line, i) => (/(Fix|Verify):.*\s#\s/.test(line) ? [`${path.relative(REPO_ROOT, file)}:${i + 1}`] : [])));
    expect(hits).toEqual([]);
  });
});

describe('secret get, refused without a terminal, names the secret asked for (#471)', () => {
  async function get(name: string): Promise<{ code: number; text: string }> {
    const saved = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
    Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
    try {
      return await captured(() => runSecret(['get', name], { env: {}, createStore: () => { throw new Error('the store was opened'); } }));
    } finally {
      if (saved) Object.defineProperty(process.stdout, 'isTTY', saved);
      else delete (process.stdout as { isTTY?: boolean }).isTTY;
    }
  }

  it('offers `get --force` and `show` for that name, not `<NAME>`', async () => {
    const res = await get('STRIPE_SECRET_KEY');
    expect(res.code).toBe(1);
    expect(res.text).toContain(`    ${CLI} secret get STRIPE_SECRET_KEY --force\n`);
    expect(res.text).toContain(`    ${CLI} secret show STRIPE_SECRET_KEY\n`);
    expect(res.text).not.toContain('<NAME>');
  });

  it('a name the store cannot hold is offered as a quoted placeholder, never as given', async () => {
    const res = await get('a;b');
    expect(res.code).toBe(1);
    expect(res.text).toContain(`    ${CLI} secret show '<name>'\n`);
    expect(res.text).not.toContain('a;b');
  });
});

describe('import of a bundle whose names this machine holds names that bundle (#471)', () => {
  /** The cheapest scrypt cost `openBundle` accepts, so the case stays fast. */
  const FAST: KdfParams = { n: 2 ** 14, r: 8, p: 1 };
  const PASS = 'correct horse battery staple';

  function memoryStore(initial: Record<string, string>): WritableSecretBackend {
    const data = new Map(Object.entries(initial).map(([k, v]) => [`secret/${k}`, v]));
    return {
      name: 'memory',
      resolve: async (p) => Object.fromEntries([...data].filter(([k]) => k === p || k.startsWith(`${p}/`))),
      healthCheck: async () => ({ healthy: true, latencyMs: 0 }),
      store: async (k, v) => { data.set(k, v); },
      delete: async (k) => data.delete(k),
    };
  }

  async function refusal(bundle: string, cwd: string): Promise<string[]> {
    await exportBundle(bundle, PASS, { backend: memoryStore({ BETA_KEY: 'FAKE-value' }), kdf: FAST, projectDir: path.dirname(bundle) });
    vi.spyOn(process, 'cwd').mockReturnValue(cwd);
    const err = await importBundle(bundle, PASS, { backend: memoryStore({ BETA_KEY: 'FAKE-older' }) }).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    return (err as Error).message.split('\n');
  }

  it('a bundle in the working directory: its name as given, and the remark on a line of its own', async () => {
    const dir = tmpDir();
    const lines = await refusal(path.join(dir, 'team.secretless-bundle'), dir);
    expect(lines[0]).toBe("Already in this machine's store: BETA_KEY.");
    expect(lines).toContain('  To replace those names with the values in the bundle:');
    expect(lines).toContain(`  Fix:     ${CLI} import team.secretless-bundle --force`);
    expect(lines.join('\n')).not.toContain('<bundle>');
  });

  it('a bundle outside it: its absolute path, quoted for the shell', async () => {
    const dir = tmpDir();
    const bundle = path.join(dir, 'from laptop', 'team.secretless-bundle');
    fs.mkdirSync(path.dirname(bundle));
    const lines = await refusal(bundle, tmpDir());
    expect(lines).toContain(`  Fix:     ${CLI} import '${bundle}' --force`);
  });
});

describe('backend set names both backends in the migrate it offers (#471)', () => {
  function homeWith(configured: string): void {
    const home = tmpDir();
    fs.mkdirSync(path.join(home, '.secretless-ai'));
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: configured }));
    vi.stubEnv('HOME', home);
    // `backend set vault` checks that both are set; nothing is sent to them.
    vi.stubEnv('VAULT_ADDR', 'http://127.0.0.1:1');
    vi.stubEnv('VAULT_TOKEN', 'not-a-real-token');
  }

  it.each([
    ['local', 'vault'],
    ['vault', 'local'],
  ])('from the configured %s to %s', async (from, to) => {
    homeWith(from);
    const res = await captured(() => runBackend(['set', to]));
    expect(res.code).toBe(0);
    expect(res.text).toContain(`  Or use \`npx secretless-ai migrate --from ${from} --to ${to}\` to migrate existing secrets.\n`);
  });

  it('no migrate line when the backend set is the one configured, which migrate refuses', async () => {
    homeWith('local');
    const res = await captured(() => runBackend(['set', 'local']));
    expect(res.code).toBe(0);
    expect(res.text).toContain('Backend set to: local');
    expect(res.text).not.toContain('migrate');
  });
});

describe('env --help and setup --help have the layout of the other commands (#471)', () => {
  function cli(args: string[], extra: Record<string, string> = {}) {
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: tmpDir(), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1', ...extra };
    if (!('SECRETLESS_CLI_PREFIX' in extra)) delete env.SECRETLESS_CLI_PREFIX;
    return spawnSync(process.execPath, [CLI_PATH, ...args], { encoding: 'utf-8', cwd: tmpDir(), env });
  }

  for (const verb of ['env', 'setup']) {
    itIfBuilt(`${verb} --help: the usage through the CLI prefix, the -h line and the pointer to the full help`, () => {
      const res = cli([verb, '--help']);
      expect(res.status, res.stderr).toBe(0);
      expect(res.stdout).toMatch(/Secretless v/);
      expect(res.stdout).toContain(`  Usage:\n    npx secretless-ai ${verb} [`);
      expect(res.stdout).toMatch(/^ {4}-h, --help +Show this help$/m);
      expect(res.stdout).toContain('  Run `npx secretless-ai --help` for every command.');

      const embedded = cli([verb, '--help'], { SECRETLESS_CLI_PREFIX: 'opena2a secrets' });
      expect(embedded.status, embedded.stderr).toBe(0);
      expect(embedded.stdout).toContain(`    opena2a secrets ${verb} [`);
      expect(embedded.stdout).not.toMatch(/npx secretless-ai|Secretless v/);
      expect(embedded.stdout).not.toMatch(/^\s*secretless-ai\s/m);
    });
  }

  itIfBuilt('env --help says env is refused in an AI agent runtime, and drops the eval usage line', () => {
    const res = cli(['env', '--help']);
    expect(res.stdout).toContain("    Refused in an AI agent runtime, where the output would enter the agent's\n    context.");
    expect(res.stdout).toContain('      secretless-ai run --only NAME -- <command>');
    expect(res.stdout).not.toContain('Usage: eval $(');
  });

  itIfBuilt('setup --help keeps what it said about prompting and the manifest format', () => {
    const res = cli(['setup', '--help']);
    expect(res.stdout).toContain('    Reads .secretless and prompts for each declared secret not yet stored.');
    expect(res.stdout).toContain('    Expected one secret name per line, no wrapper:');
    expect(res.stdout).toContain("It is not YAML, JSON, or dotenv.");
    expect(res.stdout).not.toContain('Secretless Setup');
  });
});

describe('the README quick start says where its sample was captured (#471)', () => {
  it('the line under the sample names the fixture docs/captures/quick-start.json records', () => {
    const lines = fs.readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf-8').split('\n');
    const provenance = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'docs', 'captures', 'quick-start.json'), 'utf-8'));
    expect(provenance.fixture).toContain('holding an empty .claude/ directory');

    const fences = lines.flatMap((line, i) => (line.startsWith('```') ? [i] : []));
    // The first block runs `init`, the second is its sample; the line after
    // the sample's closing fence, past one blank line, is the one under it.
    const under = lines[fences[3] + 2];
    expect(lines[fences[0] + 1]).toBe('npx secretless-ai init');
    expect(under).toMatch(/^Captured in a project holding an empty `\.claude\/` directory\. /);
  });
});

describe('setup, vault register and vault rotate read a typed value with echo off (#471)', () => {
  /** A terminal's input: `setRawMode` is what turns echo off. */
  function fakeTty(): { input: TtyInput & PassThrough; rawModes: boolean[] } {
    const rawModes: boolean[] = [];
    const input = new PassThrough() as TtyInput & PassThrough;
    input.isTTY = true;
    input.isRaw = false;
    input.setRawMode = (mode: boolean) => { rawModes.push(mode); input.isRaw = mode; return input; };
    return { input, rawModes };
  }

  /** What reaches stderr while setup runs; each answer is typed once its prompt is shown, then Enter. */
  async function setupAt(manifest: string, answers: string[]) {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, '.secretless'), manifest);
    const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
    const { input, rawModes } = fakeTty();
    let screen = '';
    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
      const text = String(chunk);
      screen += text;
      if (text.endsWith(': ')) setImmediate(() => input.write(`${answers.shift() ?? ''}\r`));
      return true;
    }) as typeof process.stderr.write);
    const result = await runSetup(dir, { backend, interactive: true, env: {}, input });
    vi.restoreAllMocks();
    return { result, screen, rawModes, store: new SecretStore({ backend }) };
  }

  it('setup: a typed value is stored and never written to the terminal', async () => {
    const { result, screen, rawModes, store } = await setupAt('STRIPE_KEY\nSENTRY_DSN  optional\n', ['FAKE-typed-value-1', '']);
    expect(result.set).toBe(1);
    expect(result.skipped).toBe(1);
    expect(await store.getSecret('STRIPE_KEY')).toBe('FAKE-typed-value-1');
    expect(screen).not.toContain('FAKE-typed-value-1');
    expect(screen).toContain(`  Store: local\n  ${HIDDEN_INPUT_NOTE}\n\n`);
    expect(screen).toContain('  STRIPE_KEY: \n');
    expect(screen).toContain('  SENTRY_DSN [optional, press Enter to skip]: \n');
    expect(rawModes).toEqual([true, false, true, false]);
  });

  it('setup: Ctrl-C answers that prompt and every later one with nothing, as readline closing on it did', async () => {
    const { result, screen, store } = await setupAt('STRIPE_KEY\nDATABASE_URL\n', ['\u0003']);
    expect(result.set).toBe(0);
    expect(result.complete).toBe(false);
    expect(result.missingNames).toEqual(['STRIPE_KEY', 'DATABASE_URL']);
    expect(screen).toContain('  STRIPE_KEY: \n');
    expect(screen).not.toContain('DATABASE_URL');
    expect(await store.listSecrets()).toEqual([]);
  });

  it('vault: the credential typed at the prompt is returned, and only the prompt is written', async () => {
    const { input, rawModes } = fakeTty();
    let screen = '';
    const output = {
      write: (text: string) => {
        screen += text;
        if (text.endsWith(': ')) setImmediate(() => input.write('FAKE-credential-1\r'));
        return true;
      },
    };
    expect(await readCredentialFromStdin('npmreg', input, output)).toBe('FAKE-credential-1');
    expect(screen).toBe('  Enter credential for "npmreg" (input hidden): \n');
    expect(rawModes).toEqual([true, false]);
  });

  it('vault: Ctrl-C at the prompt answers nothing, which register and rotate refuse as an empty value', async () => {
    const { input } = fakeTty();
    const output = { write: (text: string) => { if (text.endsWith(': ')) setImmediate(() => input.write('\u0003')); return true; } };
    expect(await readCredentialFromStdin('npmreg', input, output)).toBe('');
  });

  it('vault: a stdin that is not a terminal is still read to its end', async () => {
    const input = new PassThrough() as TtyInput & PassThrough;
    const pending = readCredentialFromStdin('npmreg', input, { write: () => true });
    input.end('FAKE-credential-2\n');
    expect(await pending).toBe('FAKE-credential-2');
  });
});
