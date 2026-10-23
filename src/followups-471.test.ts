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
import { runVault } from './commands/vault';
import { runProtectMcp } from './commands/mcp';
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
 * - `clean`, `doctor` and `init` ran as if an argument they do not take was
 *   not there, at exit 0; those words are what an interactive zsh passes on
 *   from a `# remark` pasted after a command.
 * - `warm --ttl`, `broker start --port`, `rules test`,
 *   `vault exec <namespace> --` and `protect-mcp --backend` refused a command
 *   line at exit 1, where docs/scanning.md gives 2 for one refused before
 *   anything ran.
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

describe('Fix and Verify lines in the source have no `#` or parenthesized remark after the command (#471, #475)', () => {
  function sourceFiles(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) return sourceFiles(full);
      return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') && !entry.name.endsWith('.test-support.ts') ? [full] : [];
    });
  }

  // An interactive zsh does not take `#` as a comment unless
  // INTERACTIVE_COMMENTS is set, so pasted, the remark's words become
  // arguments of the command: `npm install   # and check node -v is
  // >= 20.19.0` also wrote its output to a file named `=`. Bash refuses a
  // remark in parentheses: ``syntax error near unexpected token `('``. A `(` one
  // space after a word is prose (`for export (prompted, ...)`), so a
  // parenthesized remark is one set off from the command by two or more
  // spaces. Either kind is also caught inside a style call,
  // `${c.dim('# ...')}`, which printed the same remark (#475).
  const REMARK_AFTER_COMMAND = /(Fix|Verify):.*(\s#\s|\S\s{2,}(\$\{c\.\w+\(['"`])?[#(])/;

  it('the check finds a remark of either form, written plainly or in a style call, and passes prose', () => {
    for (const line of [
      '    `  Fix:    npm install   # and check node -v is >= 20.19.0\\n` +',
      "        console.error(`  Fix:    ${CLI_BARE} scope reset ${credentialName}   (the credential is gone: remove the baseline)`);",
      "      '  Verify:  secretless-ai mcp-status   (shows the config file for each client)',",
      "      console.error(`  Fix:    ${CLI} init   ${c.dim('# run from inside your project')}\\n`);",
    ]) {
      expect(REMARK_AFTER_COMMAND.test(line), line).toBe(true);
    }
    for (const line of [
      "      `  Fix:     run the import again with the passphrase used for export (prompted, or ${PASSPHRASE_ENV})`,",
      "    `  Verify: node -e \"import('@opena2a/atx-verify').then(() => console.log('ok'))\"\\n` +",
      "      console.error(`  Fix:    ${CLI} init`);",
    ]) {
      expect(REMARK_AFTER_COMMAND.test(line), line).toBe(false);
    }
  });

  it('no Fix or Verify line in the source has a `#` or parenthesized remark after its command', () => {
    const hits = sourceFiles(path.join(REPO_ROOT, 'src')).flatMap((file) => fs.readFileSync(file, 'utf-8')
      .split('\n')
      .flatMap((line, i) => (REMARK_AFTER_COMMAND.test(line) ? [`${path.relative(REPO_ROOT, file)}:${i + 1}`] : [])));
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

/** The built CLI, run with `home` as HOME and in `cwd`. */
function cliIn(args: string[], home: string = tmpDir(), cwd: string = tmpDir()) {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' };
  delete env.SECRETLESS_CLI_PREFIX;
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], { encoding: 'utf-8', cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** Every path under `dir`, to show that a refused run wrote nothing there. */
function tree(dir: string): string[] {
  return fs.readdirSync(dir, { recursive: true }).map(String).sort();
}

describe('clean, doctor and init refuse an argument they do not take (#471)', () => {
  itIfBuilt('clean --dry-run: the words of a remark pasted after it are refused with exit 2, each named', () => {
    // `# reads the transcripts under ~/.claude/projects`, which an interactive
    // zsh with default options passes to the command as these words.
    const res = cliIn(['clean', '--dry-run', '#', 'reads', 'the', 'transcripts', 'under', '~/.claude/projects']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(
      "  `clean` takes no argument but the path after --path; leave the arguments out: '#', reads, the, transcripts, under, '~/.claude/projects'\n",
    );
    expect(res.stderr).toContain('  `clean` was not run. Nothing was changed.\n');
    expect(res.stderr).toContain('  Supported: --dry-run, --help, --last, --path <value>\n');
  });

  itIfBuilt('clean: one argument is refused with exit 2 before a transcript is read, and the home is left as it was', () => {
    const home = tmpDir();
    const transcript = path.join(home, '.claude', 'projects', 'app', 'session.jsonl');
    fs.mkdirSync(path.dirname(transcript), { recursive: true });
    fs.writeFileSync(transcript, '{"type":"user","message":"hello"}\n');
    const before = tree(home);

    const res = cliIn(['clean', 'transcripts'], home);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(
      '  `clean` takes no argument but the path after --path; leave the argument out, or give it after --path: transcripts\n',
    );
    expect(tree(home)).toEqual(before);
    expect(fs.readFileSync(transcript, 'utf-8')).toBe('{"type":"user","message":"hello"}\n');
  });

  itIfBuilt('CONTROL: clean --dry-run with the path after --path reads that transcript', () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'session.jsonl'), '{"type":"user","message":"hello"}\n');
    const res = cliIn(['clean', '--dry-run', '--path', dir]);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain(`Scanning transcripts at ${dir}...`);
  });

  itIfBuilt('doctor: an argument is refused with exit 2, and the checks do not run', () => {
    const res = cliIn(['doctor', 'profiles']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('  `doctor` takes no argument; leave the argument out: profiles\n');
    expect(res.stderr).toContain('  `doctor` was not run. Nothing was changed.\n');
    expect(res.stderr).toContain('  Supported: --fix, --help\n');
  });

  itIfBuilt('doctor: several arguments are each named, and a line feed in one is escaped on its line', () => {
    const res = cliIn(['doctor', '#', 'checks', 'a\nb']);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain("  `doctor` takes no argument; leave the arguments out: '#', checks, $'a\\nb'\n");
    expect(res.stderr.split('\n').filter((line) => line.startsWith('b'))).toEqual([]);
  });

  itIfBuilt('CONTROL: doctor with no argument runs its checks', () => {
    const res = cliIn(['doctor']);
    expect(res.status).not.toBe(2);
    expect(res.stdout).toContain('Secretless Doctor');
  });

  itIfBuilt('init: a second argument is refused with exit 2, and nothing is written to the project', () => {
    const project = tmpDir();
    const res = cliIn(['init', '.', 'stray', '--no-watch'], tmpDir(), project);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain(
      '  `init` takes one project directory, but 2 were given; give one, or none for the current directory: ., stray\n',
    );
    expect(res.stderr).toContain('  `init` was not run. Nothing was changed.\n');
    expect(res.stderr).toContain('  Supported: --help, --no-watch\n');
    expect(tree(project)).toEqual([]);
  });

  itIfBuilt('CONTROL: init with one directory sets that project up', () => {
    const project = tmpDir();
    const res = cliIn(['init', '.', '--no-watch'], tmpDir(), project);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Configured: Claude Code');
    expect(tree(project)).toContain('CLAUDE.md');
  });
});

describe('a usage refusal exits 2, the code docs/scanning.md gives a command line refused before anything ran (#471)', () => {
  // [command line, its refusal, a line printed only once the command runs]
  const cases: Array<[string[], string, string]> = [
    [['warm', '--ttl', 'soon'], '  Invalid TTL: soon. Examples: 300, 5m, 1h, 1d', 'Warming session'],
    [['broker', 'start', '--port', '0'], '  Invalid port: 0. Must be 1-65535.', 'Starting credential broker daemon'],
    [['rules', 'test', 'a;b'], '  Invalid pattern: a;b', 'Testing pattern'],
  ];
  for (const [args, refusal, ran] of cases) {
    itIfBuilt(`\`${args.join(' ')}\` is refused with exit 2`, () => {
      const res = cliIn(args);
      expect(res.status).toBe(2);
      expect(res.stderr.split('\n')).toContain(refusal);
      expect(res.stdout).not.toContain(ran);
    });
  }

  itIfBuilt('CONTROL: `rules test` with a pattern it takes runs at exit 0', () => {
    const res = cliIn(['rules', 'test', 'ACME_*']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Testing pattern: ACME_*');
  });

  it('`vault exec <namespace> --` with no command after -- is refused with exit 2', async () => {
    vi.stubEnv('HOME', tmpDir());
    const res = await captured(() => runVault(['exec', 'demo', '--']));
    expect(res.code).toBe(2);
    expect(res.text).toContain('  Error: a command is required after --\n');
    expect(res.text).toContain('  Usage: secretless-ai vault exec <namespace> -- <command> [args...]\n');
  });

  it('`protect-mcp --backend` with a backend type it does not take is refused with exit 2', async () => {
    vi.stubEnv('HOME', tmpDir());
    const res = await captured(() => runProtectMcp(['--backend', 'bogus']));
    expect(res.code).toBe(2);
    expect(res.text).toContain("  Unknown backend type: bogus. Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.\n");
  });

  for (const doc of ['commands.md', 'scanning.md']) {
    it(`docs/${doc} names an argument clean, doctor or init does not take, and a rules test pattern, among the cases of 2`, () => {
      const text = fs.readFileSync(path.join(REPO_ROOT, 'docs', doc), 'utf-8');
      const line = text.split('\n').find((l) => l.startsWith('Exit codes: '));
      // From the first `2` on, which is the code's own clause.
      const two = line?.slice(line.indexOf('`2`'));
      expect(two).toContain('an argument `clean`, `doctor` or `init` does not take');
      expect(two).toContain('a `rules test` pattern it does not take');
    });
  }
});
