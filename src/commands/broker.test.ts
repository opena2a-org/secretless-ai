import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawn, spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { formatAimStatus } from './broker';

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
    // platform's limit (104 bytes on macOS), so a long TMPDIR would decide these cases.
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

  // The socket path limit `broker start` checks on this platform; undefined where it checks none.
  const socketPathMax = ({ darwin: 104, linux: 108 } as Partial<Record<NodeJS.Platform, number>>)[
    process.platform
  ];

  it.skipIf(socketPathMax === undefined)(
    'refuses to start under a HOME that puts the socket path past the limit: exit 1, the length and the limit named, no config directory made',
    () => {
      const longHome = path.join(home, 'h'.repeat(120));
      fs.mkdirSync(longHome);
      const socketPath = path.join(longHome, '.secretless-ai', 'broker.sock');
      const homeMax = socketPathMax! - Buffer.byteLength('/.secretless-ai/broker.sock');

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

      expect(stdout).toContain(`Grant file: ${grantFile} (0 bindings, 0 providers)`);
      expect(stdout).toContain(
        `Broker assertion public key: ${path.join(configDir, 'broker-assertion.key.pub.json')} ` +
        '(new key: register it with each identity provider in the grant file)',
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
