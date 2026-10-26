import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawn, spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { formatAimStatus, routeRows } from './broker';
import { socketPathMaxBytes } from '../broker/daemon';

describe('formatAimStatus', () => {
  it('reports "not configured" when aimConfigured is false', () => {
    expect(formatAimStatus(false, false)).toBe('not configured');
    // reachable flag is ignored when not configured
    expect(formatAimStatus(false, true)).toBe('not configured');
  });

  it('reports "configured (reachable)" when AIM responded at startup', () => {
    expect(formatAimStatus(true, true)).toBe('configured (reachable)');
  });

  it('reports "configured (unreachable)" when AIM was set but did not respond', () => {
    expect(formatAimStatus(true, false)).toBe('configured (unreachable)');
  });
});

/**
 * `broker start --grant-file` through the built CLI, so the flag crosses the argument table
 * the dispatcher checks before `runBroker` sees it. Each case runs under a HOME of its own:
 * no broker of another suite is running there, and nothing is left in the caller's.
 */
describe('broker start --grant-file (built CLI)', () => {
  const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
  let home: string;

  /** A port nothing is listening on, for the broker's HTTP listener. */
  function freePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const { port } = probe.address() as net.AddressInfo;
        probe.close(() => resolve(port));
      });
    });
  }

  function post(
    socketPath: string,
    urlPath: string,
    token: string,
    body: unknown,
  ): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(body);
      const req = http.request(
        {
          socketPath,
          path: urlPath,
          method: 'POST',
          agent: false,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data),
            Authorization: `Bearer ${token}`,
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf-8') });
          });
        },
      );
      req.on('error', reject);
      req.end(data);
    });
  }

  beforeAll(() => {
    if (!fs.existsSync(CLI)) {
      throw new Error(`dist/cli.js is missing at ${CLI}; run \`npm run build\` before this suite`);
    }
  });

  beforeEach(() => {
    // Under /tmp on POSIX rather than os.tmpdir(): the broker's socket path is 45 bytes longer
    // than the directory this is made in, and `broker start` refuses a socket path past the
    // platform's limit (104 bytes on macOS under a libuv before 1.53.0), so a long TMPDIR would
    // decide these cases.
    home = fs.mkdtempSync(path.join(process.platform === 'win32' ? os.tmpdir() : '/tmp', 'broker-cli-'));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  function brokerStart(
    args: string[],
    underHome: string = home,
  ): { status: number | null; stdout: string; stderr: string } {
    const res = spawnSync(process.execPath, [CLI, 'broker', 'start', ...args], {
      env: { ...process.env, HOME: underHome, OPENA2A_TELEMETRY: 'off' },
      encoding: 'utf-8',
      timeout: 30_000,
    });
    return { status: res.status, stdout: res.stdout, stderr: res.stderr };
  }

  // The socket path limit `broker start` checks under this platform and Node; undefined where it
  // checks none.
  const socketPathMax = socketPathMaxBytes();

  it.skipIf(socketPathMax === undefined)(
    'refuses to start under a HOME that puts the socket path past the limit: exit 1, the length and the limit named, no config directory made',
    () => {
      // A HOME that puts broker.sock one byte past the limit of the running Node: 104 bytes on
      // macOS under a libuv before 1.53.0, 253 under 1.53.0 (#441), 108 on Linux.
      const suffixBytes = Buffer.byteLength('/.secretless-ai/broker.sock');
      const longHome = path.join(
        home,
        'h'.repeat(socketPathMax! + 1 - suffixBytes - Buffer.byteLength(home) - 1),
      );
      fs.mkdirSync(longHome);
      const socketPath = path.join(longHome, '.secretless-ai', 'broker.sock');
      expect(Buffer.byteLength(socketPath)).toBe(socketPathMax! + 1);
      const homeMax = socketPathMax! - suffixBytes;

      const res = brokerStart([], longHome);

      expect(res.status).toBe(1);
      expect(res.stderr).toContain(
        `Error: Broker socket path ${socketPath} is ${Buffer.byteLength(socketPath)} bytes long, ` +
        `and a Unix socket path on this platform can be at most ${socketPathMax} bytes. ` +
        'The broker was not started.\n' +
        `  Verify: printf %s '${socketPath}' | wc -c\n` +
        '  Fix:    HOME=<directory> secretless-ai broker start   (a directory whose path is at ' +
        `most ${homeMax} bytes; the broker then keeps its files in <directory>/.secretless-ai)`,
      );
      expect(res.stderr).not.toContain('EINVAL');
      expect(res.stdout).not.toContain('Broker is running');
      expect(fs.existsSync(path.join(longHome, '.secretless-ai'))).toBe(false);
    },
  );

  it('refuses to start on a grant file that does not exist: exit 1, the file named, no broker left', () => {
    const missing = path.join(home, 'grants.json');

    const res = brokerStart(['--grant-file', missing]);

    // Exit 1 from the daemon, not the usage exit an unknown flag gets.
    expect(res.status).toBe(1);
    expect(res.stderr).toContain(`Grant file ${missing} does not exist`);
    expect(res.stderr).not.toContain('Unknown option');
    expect(res.stdout).not.toContain('Broker is running');
    expect(fs.existsSync(path.join(home, '.secretless-ai', 'broker.pid'))).toBe(false);
  });

  it('refuses to start on a grant file it cannot apply, with the reason', () => {
    const grantFile = path.join(home, 'grants.json');
    fs.writeFileSync(grantFile, JSON.stringify({ bindings: [] }));

    const res = brokerStart(['--grant-file', grantFile]);

    expect(res.status).toBe(1);
    expect(res.stderr).toContain(`Failed to load grants from ${grantFile}: trust must be an object`);
    expect(fs.existsSync(path.join(home, '.secretless-ai', 'broker.pid'))).toBe(false);
  });

  it('starts a broker that decides /grant requests, reports what it loaded, and stops on SIGTERM', async () => {
    const issuer = crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as { x: string };
    const grantFile = path.join(home, 'grants.json');
    fs.writeFileSync(
      grantFile,
      JSON.stringify({
        trust: {
          trustedIssuers: ['did:opena2a:authority:issuer.test'],
          publicKeys: [
            { algorithm: 'Ed25519', publicKeyHex: Buffer.from(issuer.x, 'base64url').toString('hex') },
          ],
        },
        assertion: { issuer: 'https://broker.example.test', keyId: 'broker-key-1' },
        providers: {},
        bindings: [],
      }),
    );
    const configDir = path.join(home, '.secretless-ai');
    const port = await freePort();

    const child = spawn(
      process.execPath,
      [CLI, 'broker', 'start', '--port', String(port), '--grant-file', grantFile],
      { env: { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off' }, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => { stdout += c.toString('utf-8'); });
    child.stderr.on('data', (c: Buffer) => { stderr += c.toString('utf-8'); });
    const exited = new Promise<void>((resolve) => { child.once('exit', () => resolve()); });

    try {
      const deadline = Date.now() + 20_000;
      while (!stdout.includes('Broker is running.')) {
        if (child.exitCode !== null || Date.now() > deadline) {
          throw new Error(`the broker did not start (exit code ${child.exitCode}):\n${stdout}\n${stderr}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }

      // The credential is not one any issuer signed, so the answer is the uniform denial. A
      // broker with no grant resolver answers 404 here instead.
      const res = await post(
        path.join(configDir, 'broker.sock'),
        '/grant',
        fs.readFileSync(path.join(configDir, 'broker.token'), 'utf-8'),
        { agentId: 'orders-reader', atx: {}, grant: 'grant://orders-db', operation: { method: 'GET', path: '/orders' } },
      );
      expect(res.status).toBe(403);
      expect(res.text).toBe('{"error":"denied"}');

      // What was loaded is reported as rows of the block: the grant file with its counts, the
      // public key directly under it, and the note for a key this start created.
      expect(stdout).toContain(
        `\n  Grants:       on, grant file ${grantFile} (0 bindings, 0 providers)\n` +
        `  Public key:   ${path.join(configDir, 'broker-assertion.key.pub.json')}\n` +
        '                Register this new key with each provider in the grant file.\n',
      );
    } finally {
      // Stop the one process this test started, by its pid.
      if (child.pid !== undefined && child.exitCode === null) process.kill(child.pid, 'SIGTERM');
      const forced = setTimeout(() => {
        if (child.pid !== undefined && child.exitCode === null) process.kill(child.pid, 'SIGKILL');
      }, 10_000);
      await exited;
      clearTimeout(forced);
    }

    expect(child.exitCode).toBe(0);
    expect(fs.existsSync(path.join(configDir, 'broker.pid'))).toBe(false);
  }, 40_000);
});

describe('routeRows: the Grants: and Resolve: rows', () => {
  const SOURCE = {
    file: '/srv/bank/broker-grants.json',
    bindingCount: 2,
    providerCount: 1,
    assertionPublicKeyFile: '/srv/bank/broker-assertion.key.pub.json',
    assertionKeyCreated: true,
  };

  it('names the file, the counts and the reason on a 14-character label, value at column 17', () => {
    expect(routeRows(
      { grant: { served: true, source: SOURCE }, resolve: { served: true, policyFile: '/srv/bank/broker-policies.json' } },
      1,
    )).toEqual([
      '  Grants:       on, grant file /srv/bank/broker-grants.json (2 bindings, 1 provider)',
      '  Resolve:      on, policy file /srv/bank/broker-policies.json (1 rule)',
    ]);
    expect(routeRows({ grant: { served: false }, resolve: { served: false, reason: 'noPolicyFile' } }, 0)).toEqual([
      '  Grants:       off, no grant file',
      '  Resolve:      off, no policy file',
    ]);
    expect(routeRows({ grant: { served: false }, resolve: { served: false, reason: 'disabled' } }, 0)[1])
      .toBe('  Resolve:      off, --no-resolve');
  });

  it('adds the public key row, its new-key note and the --no-resolve note on the start screen only', () => {
    const routes = { grant: { served: true as const, source: SOURCE }, resolve: { served: true as const, policyFile: '/home/op/.secretless-ai/broker-policies.json' } };

    expect(routeRows(routes, 3, { policyFileNamed: false })).toEqual([
      '  Grants:       on, grant file /srv/bank/broker-grants.json (2 bindings, 1 provider)',
      '  Public key:   /srv/bank/broker-assertion.key.pub.json',
      '                Register this new key with each provider in the grant file.',
      '  Resolve:      on, policy file /home/op/.secretless-ai/broker-policies.json (3 rules)',
      '                Pass --no-resolve to serve grants only.',
    ]);
    // A policy file named on the command line states its intent: no note.
    expect(routeRows(routes, 3, { policyFileNamed: true })).not.toContain('                Pass --no-resolve to serve grants only.');
    // The status screen: the two rows alone.
    expect(routeRows(routes, 3)).toHaveLength(2);
  });

  it('prints no file, count or reason the routes did not carry', () => {
    expect(routeRows(
      { grant: { served: true, source: null }, resolve: { served: true, policyFile: null } },
      0,
      { policyFileNamed: false },
    )).toEqual([
      '  Grants:       on',
      '  Resolve:      on (0 rules)',
      '                Pass --no-resolve to serve grants only.',
    ]);
    // A reason another build sent: `off` alone, never the reply's string.
    const unknown = { grant: { served: false }, resolve: { served: false, reason: 'quarantined\nby-peer' } } as never;
    const rows = routeRows(unknown, 0);
    expect(rows[1]).toBe('  Resolve:      off');
    expect(rows.join('\n')).not.toContain('quarantined');
    // A source whose members are not in shape names nothing.
    const odd = { grant: { served: true, source: { file: 7, bindingCount: '2' } }, resolve: { served: false, reason: 'disabled' } } as never;
    expect(routeRows(odd, 0, { policyFileNamed: false })[0]).toBe('  Grants:       on');
  });

  it('shows a line feed in a path as an escape, so it cannot print a second row', () => {
    const rows = routeRows(
      { grant: { served: false }, resolve: { served: true, policyFile: '/tmp/p\n  Resolve:      off, --no-resolve' } },
      0,
    );
    expect(rows).toHaveLength(2);
    expect(rows.join('\n').split('\n')).toHaveLength(2);
  });
});

/**
 * Which routes `broker start` serves, through the built CLI, each case under a HOME of its own.
 * `/resolve` is on only when the broker loads a policy file: the one `--policy-file` names, or
 * `~/.secretless-ai/broker-policies.json` when it exists. `--no-resolve` keeps it off.
 */
describe('broker start serves POST /resolve only when it loads a policy file (built CLI)', () => {
  const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
  const TIMEOUT_MS = 40_000;
  let home: string;
  const children: Array<ReturnType<typeof spawn>> = [];

  beforeAll(() => {
    if (!fs.existsSync(CLI)) {
      throw new Error(`dist/cli.js is missing at ${CLI}; run \`npm run build\` before this suite`);
    }
  });

  beforeEach(() => {
    // Under /tmp on POSIX, so broker.sock under it fits the socket path limit.
    home = fs.mkdtempSync(path.join(process.platform === 'win32' ? os.tmpdir() : '/tmp', 'broker-route-'));
  });

  afterEach(async () => {
    for (const child of children.splice(0)) await stop(child);
    fs.rmSync(home, { recursive: true, force: true });
  });

  function env(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
    return { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1', ...extra };
  }

  function freePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const { port } = probe.address() as net.AddressInfo;
        probe.close(() => resolve(port));
      });
    });
  }

  async function stop(child: ReturnType<typeof spawn>): Promise<void> {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise<void>((resolve) => { child.once('exit', () => resolve()); });
    child.kill('SIGTERM');
    const forced = setTimeout(() => { if (child.exitCode === null) child.kill('SIGKILL'); }, 10_000);
    await exited;
    clearTimeout(forced);
  }

  /** `command` (the entry point and its arguments) until the screen says the broker runs. */
  async function start(command: string[], extraEnv: Record<string, string> = {}): Promise<string> {
    const child = spawn(command[0], command.slice(1), { env: env(extraEnv), stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    let stdout = '';
    let stderr = '';
    child.stdout!.on('data', (c: Buffer) => { stdout += c.toString('utf-8'); });
    child.stderr!.on('data', (c: Buffer) => { stderr += c.toString('utf-8'); });
    const deadline = Date.now() + 20_000;
    while (!stdout.includes('Press Ctrl+C to stop.')) {
      if (child.exitCode !== null || Date.now() > deadline) {
        throw new Error(`the broker did not start (exit code ${child.exitCode}):\n${stdout}\n${stderr}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return stdout;
  }

  async function brokerStart(args: string[], extraEnv: Record<string, string> = {}): Promise<string> {
    return start([process.execPath, CLI, 'broker', 'start', '--port', String(await freePort()), ...args], extraEnv);
  }

  function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
    const res = spawnSync(process.execPath, [CLI, ...args], { env: env(), encoding: 'utf-8', timeout: 30_000 });
    return { status: res.status, stdout: res.stdout, stderr: res.stderr };
  }

  function ask(method: string, urlPath: string, body?: unknown): Promise<{ status: number; text: string }> {
    const configDir = path.join(home, '.secretless-ai');
    const token = fs.readFileSync(path.join(configDir, 'broker.token'), 'utf-8');
    return new Promise((resolve, reject) => {
      const data = body === undefined ? '' : JSON.stringify(body);
      const req = http.request(
        {
          socketPath: path.join(configDir, 'broker.sock'),
          path: urlPath,
          method,
          agent: false,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data),
            Authorization: `Bearer ${token}`,
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf-8') }));
        },
      );
      req.on('error', reject);
      req.end(data);
    });
  }

  async function routes(): Promise<Record<string, any>> {
    const res = await ask('GET', '/status');
    expect(res.status).toBe(200);
    return JSON.parse(res.text).routes;
  }

  /** A credential name and value set in the broker's environment, which no off route may return. */
  function planted(): { name: string; value: string; env: Record<string, string> } {
    const name = `ROUTE_CHECK_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const value = crypto.randomBytes(16).toString('hex');
    return { name, value, env: { [name]: value } };
  }

  function writeDefaultPolicy(credentialSelector: string): string {
    const file = path.join(home, '.secretless-ai', 'broker-policies.json');
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, JSON.stringify({
      version: 1,
      rules: [{ id: 'allow-agent', agentSelector: 'agent-*', credentialSelector, constraints: {}, effect: 'allow' }],
    }));
    return file;
  }

  /** A grant file with one binding served through one provider, outside the config directory. */
  function writeGrantFile(): string {
    const issuer = crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as { x: string };
    const file = path.join(home, 'grants.json');
    fs.writeFileSync(file, JSON.stringify({
      version: 1,
      trust: {
        trustedIssuers: ['did:opena2a:authority:issuer.test'],
        publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: Buffer.from(issuer.x, 'base64url').toString('hex') }],
      },
      assertion: { issuer: 'https://broker.example.test', keyId: 'broker-key-1' },
      providers: { 'orders-idp': { mode: 'exchange', tokenEndpoint: 'https://idp.example.test/oauth2/v1/token' } },
      bindings: [{
        grant: 'grant://orders-db',
        match: { trustClass: 'orders:read', minTrustLevel: 3, oasbLevel: '>=L2' },
        resolve: { mode: 'exchange', providerId: 'orders-idp', scope: 'orders.read', audience: 'https://api.orders.example.test', ttlSeconds: 300 },
      }],
    }));
    return file;
  }

  /** The row after `label` in `screen`, or undefined. */
  function rowAfter(screen: string, label: string): string | undefined {
    const lines = screen.split('\n');
    const at = lines.findIndex((l) => l.startsWith(`  ${label}`));
    return at === -1 ? undefined : lines[at + 1];
  }

  it('(a) with no policy file: /resolve answers 404 and never returns a value set in the broker environment', async () => {
    const secret = planted();

    const screen = await brokerStart([], secret.env);

    expect(screen).toContain('\n  Resolve:      off, no policy file\n');
    expect(await routes()).toMatchObject({ resolve: { served: false, reason: 'noPolicyFile' } });
    const res = await ask('POST', '/resolve', { agentId: 'agent-1', credentialName: secret.name });
    expect(res.status).toBe(404);
    expect(res.text).toBe('{"error":"Not found"}');
    expect(res.text).not.toContain(secret.value);

    const status = run(['broker', 'status']);
    expect(status.stdout).toContain('\n  Resolve:      off, no policy file\n  Policies:     0\n');
  }, TIMEOUT_MS);

  it('(b) with the default policy file and --no-resolve: /resolve answers 404', async () => {
    const secret = planted();
    writeDefaultPolicy(secret.name);

    const screen = await brokerStart(['--no-resolve'], secret.env);

    expect(screen).toContain('\n  Resolve:      off, --no-resolve\n');
    expect(screen).not.toContain('Pass --no-resolve');
    expect(await routes()).toMatchObject({ resolve: { served: false, reason: 'disabled' } });
    const res = await ask('POST', '/resolve', { agentId: 'agent-1', credentialName: secret.name });
    expect(res.status).toBe(404);
    expect(res.text).not.toContain(secret.value);

    const status = run(['broker', 'status']);
    expect(status.stdout).toContain('\n  Resolve:      off, --no-resolve\n  Policies:     0\n');
  }, TIMEOUT_MS);

  it('(c) with the default policy file and no flag: a request it allows is served as before', async () => {
    const secret = planted();
    const policyFile = writeDefaultPolicy(secret.name);

    const screen = await brokerStart([], secret.env);

    expect(screen).toContain(`\n  Resolve:      on, policy file ${policyFile} (1 rule)\n`);
    // No grants are served, so no note.
    expect(screen).not.toContain('Pass --no-resolve');
    expect(await routes()).toMatchObject({ resolve: { served: true, policyFile } });
    const res = await ask('POST', '/resolve', { agentId: 'agent-1', credentialName: secret.name });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.text)).toEqual({ value: secret.value });
  }, TIMEOUT_MS);

  it('(d) refuses a --policy-file that does not exist, and leaves no PID file, socket or token', () => {
    const missing = path.join(home, 'no-such-policies.json');

    const res = run(['broker', 'start', '--policy-file', missing]);

    expect(res.status).toBe(1);
    expect(res.stderr).toContain(`Policy file ${missing} does not exist. The broker was not started`);
    expect(res.stdout).not.toContain('Broker is running');
    for (const file of ['broker.pid', 'broker.sock', 'broker.token']) {
      expect(fs.existsSync(path.join(home, '.secretless-ai', file))).toBe(false);
    }
  }, TIMEOUT_MS);

  it('(e) refuses --no-resolve together with --policy-file with exit 2, in either order, before starting', () => {
    const policyFile = path.join(home, 'policies.json');
    fs.writeFileSync(policyFile, JSON.stringify({ version: 1, rules: [] }));

    for (const args of [['--no-resolve', '--policy-file', policyFile], ['--policy-file', policyFile, '--no-resolve']]) {
      const res = run(['broker', 'start', ...args]);

      expect(res.status).toBe(2);
      expect(res.stderr).toContain('--no-resolve together with --policy-file is refused');
      expect(res.stdout).not.toContain('Starting credential broker daemon');
      expect(fs.existsSync(path.join(home, '.secretless-ai', 'broker.pid'))).toBe(false);
    }
  }, TIMEOUT_MS);

  it('(g) the grants-only command `broker --help` prints starts a broker that serves /grant and answers 404 on /resolve', async () => {
    const secret = planted();
    writeDefaultPolicy(secret.name);
    const grantFile = writeGrantFile();
    const help = run(['broker', '--help']);
    const line = help.stdout.split('\n').map((l) => l.trim()).find((l) => l.endsWith('broker start --grant-file <path> --no-resolve'));
    expect(line).toBe('npx secretless-ai broker start --grant-file <path> --no-resolve');

    // Its prefix is replaced by the built entry point and <path> by the fixture; the port is
    // a free one, so the run cannot meet a broker already on the default port.
    const words = line!.split(' ').slice(2).map((w) => (w === '<path>' ? grantFile : w));
    await start([process.execPath, CLI, ...words, '--port', String(await freePort())], secret.env);

    const served = await routes();
    expect(served.grant).toEqual({
      served: true,
      source: {
        file: grantFile,
        bindingCount: 1,
        providerCount: 1,
        assertionPublicKeyFile: path.join(home, '.secretless-ai', 'broker-assertion.key.pub.json'),
        assertionKeyCreated: true,
      },
    });
    expect(served.resolve).toEqual({ served: false, reason: 'disabled' });
    const res = await ask('POST', '/resolve', { agentId: 'agent-1', credentialName: secret.name });
    expect(res.status).toBe(404);
    expect(res.text).not.toContain(secret.value);
  }, TIMEOUT_MS);

  it('(h) broker status prints the Grants: and Resolve: rows of the start screen byte for byte, without its notes', async () => {
    writeDefaultPolicy('ROUTE_CHECK_*');
    const grantFile = writeGrantFile();

    const screen = await brokerStart(['--grant-file', grantFile]);
    const status = run(['broker', 'status']);

    const startRows = screen.split('\n').filter((l) => /^ {2}(Grants|Resolve): /.test(l));
    const statusRows = status.stdout.split('\n').filter((l) => /^ {2}(Grants|Resolve): /.test(l));
    expect(startRows).toHaveLength(2);
    expect(statusRows).toEqual(startRows);
    // The note is printed under the value column on the start screen, and never in status.
    const note = screen.split('\n').find((l) => l.endsWith('--no-resolve to serve grants only.'));
    expect(note).toBe('                Pass --no-resolve to serve grants only.');
    expect(note!.indexOf('Pass')).toBe(16);
    expect(note!.length).toBe(55);
    expect(rowAfter(screen, 'Resolve:')).toBe(note);
    expect(status.stdout.split('\n').filter((l) => l.startsWith('                '))).toEqual([]);
    expect(rowAfter(status.stdout, 'Resolve:')).toBe('  Policies:     1');
  }, TIMEOUT_MS);
});

describe('broker help names the switch and the rule (built CLI)', () => {
  const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
  const RULE =
    'POST /grant and POST /resolve are on only when their files load. With no path given, the broker ' +
    'loads ~/.secretless-ai/broker-grants.json and ~/.secretless-ai/broker-policies.json when they ' +
    'exist. A path named on the command line must exist.';
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-help-'));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
    const res = spawnSync(process.execPath, [CLI, ...args], {
      env: { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
      encoding: 'utf-8',
      timeout: 30_000,
    });
    return { status: res.status, stdout: res.stdout, stderr: res.stderr };
  }

  const collapse = (text: string) => text.replace(/\s+/g, ' ');

  it('`broker --help` states the rule and the grants-only command after its own prefix', () => {
    const res = run(['broker', '--help']);

    expect(res.status).toBe(0);
    expect(collapse(res.stdout)).toContain(RULE);
    expect(res.stdout).toContain('\n      npx secretless-ai broker start --grant-file <path> --no-resolve\n');
    expect(res.stdout).toContain('    --policy-file <path>   Policy file path (turns on POST /resolve)\n');
    expect(res.stdout).toContain('    --no-resolve           Keep POST /resolve off (default policy file not read)\n');
    expect(res.stdout.split('\n').filter((l) => l.includes('--no-resolve'))).toHaveLength(2);
  });

  it('`broker start --help` describes --no-resolve once and gives it no value', () => {
    const res = run(['broker', 'start', '--help']);

    expect(res.stdout.split('Keep POST /resolve off (default policy file not read)')).toHaveLength(2);
    expect(res.stdout).not.toContain('--no-resolve <value>');
  });

  it('the usage bare `broker` prints states the rule, wrapped inside 80 columns, and the grants-only command', () => {
    const res = run(['broker']);

    expect(res.status).toBe(2);
    expect(collapse(res.stdout)).toContain(RULE);
    expect(res.stdout).toContain(
      '\n  POST /grant and POST /resolve are on only when their files load. With no path\n' +
      '  given, the broker loads ~/.secretless-ai/broker-grants.json and\n' +
      '  ~/.secretless-ai/broker-policies.json when they exist. A path named on the\n' +
      '  command line must exist.\n\n' +
      '  Serve grants only:\n' +
      '    secretless-ai broker start --grant-file <path> --no-resolve\n',
    );
    expect(res.stdout).toContain(
      '    --policy-file <path>   Policy file path (turns on POST /resolve)\n' +
      '    --no-resolve           Keep POST /resolve off (default policy file not read)\n',
    );
    // Option descriptions start at column 28; the paragraph's lines stay inside 80 columns.
    const options = res.stdout.split('\n').filter((l) => l.startsWith('    --'));
    expect(options).toHaveLength(6);
    for (const l of options) expect(l[26] === ' ' && l[27] !== ' ').toBe(true);
    const paragraph = res.stdout.split('\n').filter((l) => /^ {2}(POST|given|~|command)/.test(l));
    expect(paragraph).toHaveLength(4);
    for (const l of paragraph) expect(l.length).toBeLessThanOrEqual(80);
  });
});
