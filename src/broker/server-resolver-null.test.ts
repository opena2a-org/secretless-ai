/**
 * A broker built with `resolver: null` serves `POST /grant` and not `POST /resolve`.
 *
 * It builds no credential resolver and no policy engine, reads no policy file (named or
 * default), and answers `POST /resolve` before the request body is read, with the body an
 * unknown route gets. `/health` and `/status` say which capability routes the broker serves.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from 'vitest';
import { spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as path from 'path';

import { BrokerServer } from './server';
import type { CredentialResolver } from './resolver';
import type { GrantResolver } from './grant-resolver';
import type { BrokerConfig, GrantRouteSource } from './types';

/**
 * policy.ts fixes the default policy file under ~/.secretless-ai when it loads, so HOME is a
 * temporary directory set before the modules load (the form of daemon.test.ts). A broker here
 * never reads the policy file of whoever runs the suite.
 */
const testHome = vi.hoisted(() => {
  const fs = require('fs') as typeof import('fs');
  const os = require('os') as typeof import('os');
  const path = require('path') as typeof import('path');
  const original = process.env.HOME;
  // Under /tmp on POSIX: the socket paths below are made in this directory.
  const dir = fs.mkdtempSync(path.join(process.platform === 'win32' ? os.tmpdir() : '/tmp', 'sl-rnull-'));
  process.env.HOME = dir;
  return { dir, original };
});

const DEFAULT_POLICY_FILE = path.join(testHome.dir, '.secretless-ai', 'broker-policies.json');

afterAll(() => {
  if (testHome.original === undefined) delete process.env.HOME;
  else process.env.HOME = testHome.original;
  fs.rmSync(testHome.dir, { recursive: true, force: true });
});

/** A resolver that opens no store: it answers every name from `answer`. */
function stubResolver(answer: (name: string) => string | undefined = () => 'stub-value'): CredentialResolver {
  return {
    resolve: async (name: string) => answer(name),
    exists: async (name: string) => answer(name) !== undefined,
  } as unknown as CredentialResolver;
}

/** A grant resolver that is never asked: these brokers are only built and read. */
function stubGrantResolver(): GrantResolver {
  return {
    resolve: async () => {
      throw new Error('not called');
    },
  } as unknown as GrantResolver;
}

const SOURCE: GrantRouteSource = {
  file: '/srv/bank/broker-grants.json',
  bindingCount: 2,
  providerCount: 1,
  assertionPublicKeyFile: '/srv/bank/broker-assertion.key.pub.json',
  assertionKeyCreated: false,
};

function oneRulePolicy(file: string, credentialSelector = 'F8_*'): void {
  fs.writeFileSync(
    file,
    JSON.stringify({
      version: 1,
      rules: [{ id: 'allow-f8', agentSelector: 'agent-*', credentialSelector, constraints: {}, effect: 'allow' }],
    }),
  );
}

function request(
  socketPath: string,
  method: string,
  urlPath: string,
  token: string,
  body?: unknown,
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    const req = http.request(
      {
        socketPath,
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

function readAudit(file: string): Array<Record<string, unknown>> {
  return fs
    .readFileSync(file, 'utf-8')
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe('BrokerServer built with resolver: null', () => {
  let dir: string;
  let server: BrokerServer | undefined;

  /** Every path the broker writes, inside this test's own directory. */
  function config(extra: Partial<BrokerConfig> = {}): BrokerConfig {
    return {
      socketPath: path.join(dir, 'b.sock'),
      httpPort: 0,
      auditLog: path.join(dir, 'audit.log'),
      tokenFile: path.join(dir, 'broker.token'),
      ...extra,
    };
  }

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(testHome.dir, 'b-'));
    server = undefined;
  });

  afterEach(async () => {
    if (server) await server.stop();
    fs.rmSync(path.join(testHome.dir, '.secretless-ai'), { recursive: true, force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('A1: start() reads no policy file, so a malformed default policy file does not stop it', async () => {
    fs.mkdirSync(path.dirname(DEFAULT_POLICY_FILE), { recursive: true });
    fs.writeFileSync(DEFAULT_POLICY_FILE, '{');

    server = new BrokerServer(config(), { resolver: null, aimClient: null });
    await server.start();

    expect(server.getStatus().policyCount).toBe(0);
    expect(server.getStatus().routes.resolve).toEqual({ served: false, reason: 'disabled' });
  });

  it('A1c (control): the same malformed file, named as policyFile on a broker with a resolver, refuses the start', async () => {
    fs.mkdirSync(path.dirname(DEFAULT_POLICY_FILE), { recursive: true });
    fs.writeFileSync(DEFAULT_POLICY_FILE, '{');

    const withResolver = new BrokerServer(
      config({ policyFile: DEFAULT_POLICY_FILE }),
      { resolver: stubResolver(), aimClient: null },
    );

    await expect(withResolver.start()).rejects.toThrow(`Failed to load policies from ${DEFAULT_POLICY_FILE}`);
    expect(fs.existsSync(config().tokenFile!)).toBe(false);
  });

  it('A2: refuses config.policyFile together with resolver: null, naming policyFile', () => {
    const construct = () =>
      new BrokerServer(config({ policyFile: path.join(dir, 'policies.json') }), { resolver: null, aimClient: null });

    expect(construct).toThrow(TypeError);
    expect(construct).toThrow(
      'BrokerServer built with resolver: null does not accept config.policyFile: the broker serves no ' +
      'POST /resolve, so the file would not be read. Remove config.policyFile, or remove resolver: null.',
    );
  });

  it('A2: refuses resolveOff on a broker that has a resolver, passed or built by default', () => {
    const message =
      'BrokerServer built with a resolver does not accept resolveOff: the member describes a broker built ' +
      'with resolver: null, and this one has a resolver. Remove resolveOff, or pass resolver: null.';
    const policyFile = path.join(dir, 'policies.json');

    expect(
      () => new BrokerServer(config({ policyFile }), { resolver: stubResolver(), resolveOff: 'disabled', aimClient: null }),
    ).toThrow(new TypeError(message));
    expect(
      () => new BrokerServer(config({ policyFile }), { resolveOff: 'noPolicyFile', aimClient: null }),
    ).toThrow(new TypeError(message));
  });

  it('A2: refuses grantSource without a grantResolver', () => {
    const message =
      'BrokerServer built without a grantResolver does not accept grantSource: the member describes a served ' +
      'POST /grant, and this broker serves none. Remove grantSource, or pass the grantResolver loaded from the same file.';

    expect(
      () => new BrokerServer(config(), { resolver: null, grantSource: SOURCE, aimClient: null }),
    ).toThrow(new TypeError(message));
    expect(
      () => new BrokerServer(config(), { resolver: null, grantResolver: null, grantSource: SOURCE, aimClient: null }),
    ).toThrow(new TypeError(message));
  });

  it('A3: /resolve answers 404, the unknown-route body, and never a value set in the broker environment', async () => {
    // The broker runs in this process, so this is the broker's environment.
    const name = `F8_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const value = crypto.randomBytes(16).toString('hex');
    process.env[name] = value;
    try {
      server = new BrokerServer(config(), { resolver: null, aimClient: null });
      await server.start();
      const token = fs.readFileSync(config().tokenFile!, 'utf-8');

      const resolved = await request(config().socketPath, 'POST', '/resolve', token, {
        agentId: 'agent-1',
        credentialName: name,
      });
      const unknown = await request(config().socketPath, 'GET', '/no-such-route', token);

      expect(resolved.status).toBe(404);
      expect(unknown.status).toBe(404);
      expect(resolved.text).toBe(unknown.text);
      expect(resolved.text).not.toContain(value);

      const audit = readAudit(config().auditLog!);
      expect(audit.some((e) => e.eventType === 'startup')).toBe(true);
      expect(audit.filter((e) => e.eventType === 'resolve')).toEqual([]);
    } finally {
      delete process.env[name];
    }
  });

  it('A3c (control): the same request on a broker with a resolver and an allowing policy returns the value', async () => {
    const name = `F8_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const value = crypto.randomBytes(16).toString('hex');
    process.env[name] = value;
    try {
      const policyFile = path.join(dir, 'policies.json');
      oneRulePolicy(policyFile);
      server = new BrokerServer(
        config({ policyFile }),
        { resolver: stubResolver((n) => process.env[n]), aimClient: null },
      );
      await server.start();
      const token = fs.readFileSync(config().tokenFile!, 'utf-8');

      const resolved = await request(config().socketPath, 'POST', '/resolve', token, {
        agentId: 'agent-1',
        credentialName: name,
      });

      expect(resolved.status).toBe(200);
      expect(JSON.parse(resolved.text)).toEqual({ value });
    } finally {
      delete process.env[name];
    }
  });

  it('A4: /health carries grantServed and resolveServed after policyCount, on the object and on the wire', async () => {
    const keys = [
      'healthy', 'uptimeSeconds', 'requestCount', 'aimConfigured', 'aimReachable',
      'policyCount', 'grantServed', 'resolveServed',
    ];
    server = new BrokerServer(config(), { resolver: null, aimClient: null });
    expect(Object.keys(server.getHealth())).toEqual(keys);

    await server.start();
    const token = fs.readFileSync(config().tokenFile!, 'utf-8');
    const health = await request(config().socketPath, 'GET', '/health', token);
    expect(Object.keys(JSON.parse(health.text))).toEqual(keys);
    expect(JSON.parse(health.text)).toMatchObject({ policyCount: 0, grantServed: false, resolveServed: false });
  });

  describe('A5 and A6: /status routes, and the /health booleans that match them', () => {
    async function routesOf(
      cfg: BrokerConfig,
      deps: NonNullable<ConstructorParameters<typeof BrokerServer>[1]>,
      started: boolean,
    ) {
      server = new BrokerServer(cfg, deps);
      if (started) await server.start();
      const status = server.getStatus();
      const health = server.getHealth();
      // A6: the booleans on /health and the entries on /status are read from the same fields.
      expect(health.grantServed).toBe(status.routes.grant.served);
      expect(health.resolveServed).toBe(status.routes.resolve.served);
      expect(status.grantServed).toBe(status.routes.grant.served);
      expect(status.resolveServed).toBe(status.routes.resolve.served);
      return status;
    }

    it('resolver: null with no reason: both routes off, resolve disabled', async () => {
      const status = await routesOf(config(), { resolver: null, aimClient: null }, false);
      expect(status.routes).toEqual({ grant: { served: false }, resolve: { served: false, reason: 'disabled' } });
      expect(status.policyCount).toBe(0);
    });

    it('resolver: null with resolveOff noPolicyFile', async () => {
      const status = await routesOf(config(), { resolver: null, resolveOff: 'noPolicyFile', aimClient: null }, false);
      expect(status.routes.resolve).toEqual({ served: false, reason: 'noPolicyFile' });
    });

    it('a resolver and a one-rule policy file: served, from that file, one rule', async () => {
      const policyFile = path.join(dir, 'policies.json');
      oneRulePolicy(policyFile);
      const status = await routesOf(config({ policyFile }), { resolver: stubResolver(), aimClient: null }, true);
      expect(status.routes.resolve).toEqual({ served: true, policyFile });
      expect(status.policyCount).toBe(1);
    });

    it('a resolver and a policy file that is absent: served, no file, zero rules', async () => {
      const policyFile = path.join(dir, 'no-such-policies.json');
      const status = await routesOf(config({ policyFile }), { resolver: stubResolver(), aimClient: null }, true);
      expect(status.routes.resolve).toEqual({ served: true, policyFile: null });
      expect(status.policyCount).toBe(0);
    });

    it('a grant resolver with a source: the five reportable members, and never the private key path', async () => {
      const grantConfigLike = {
        ...SOURCE,
        assertionKeyFile: '/srv/bank/broker-assertion.key',
        verifier: { verify: () => true },
      };
      const status = await routesOf(
        config(),
        { resolver: null, grantResolver: stubGrantResolver(), grantSource: grantConfigLike, aimClient: null },
        false,
      );
      expect(status.routes.grant).toEqual({ served: true, source: SOURCE });
      expect(JSON.stringify(status)).not.toContain('assertionKeyFile');
      expect(JSON.stringify(status)).not.toContain('broker-assertion.key"');
    });

    it('a grant resolver without a source: served, source null', async () => {
      const status = await routesOf(config(), { resolver: null, grantResolver: stubGrantResolver(), aimClient: null }, false);
      expect(status.routes.grant).toEqual({ served: true, source: null });
    });
  });
});

/**
 * HOME after a broker built with `resolver: null` has run: started, sent `POST /grant` and
 * `POST /resolve`, and stopped, in a process of its own whose HOME is fixed before any module
 * loads and whose every configured path is outside HOME.
 */
describe('a broker built with resolver: null leaves HOME as it found it', () => {
  const DIST_SERVER = path.resolve(__dirname, '..', '..', 'dist', 'broker', 'server.js');
  const CHILD_TIMEOUT_MS = 40_000;

  /** The broker's process: one start, one /grant, one /resolve, one stop, the answers on stdout. */
  const CHILD = `
const fs = require('fs');
const http = require('http');
const [serverModule, configJson, mode, credentialName] = process.argv.slice(1);
const { BrokerServer } = require(serverModule);
const config = JSON.parse(configJson);

function ask(token, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({
      socketPath: config.socketPath, path: urlPath, method: 'POST', agent: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), Authorization: 'Bearer ' + token },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf-8') }));
    });
    req.on('error', reject);
    req.end(data);
  });
}

(async () => {
  const server = mode === 'null'
    ? new BrokerServer(config, { resolver: null, aimClient: null })
    : new BrokerServer({ ...config, policyFile: config.policyFile }, { aimClient: null });
  await server.start();
  const token = fs.readFileSync(config.tokenFile, 'utf-8');
  const grant = await ask(token, '/grant', {
    agentId: 'agent-1', atx: {}, grant: 'grant://orders-db', operation: { method: 'GET', path: '/orders' },
  });
  const resolved = await ask(token, '/resolve', { agentId: 'agent-1', credentialName });
  await server.stop();
  // stop() leaves its force-close timer running; the answer is written, so end here.
  process.stdout.write(JSON.stringify({ grant, resolved }), () => process.exit(0));
})().catch((err) => {
  process.stderr.write(String((err && err.stack) || err));
  process.exit(1);
});
`;

  let home: string;
  let work: string;

  beforeAll(() => {
    if (!fs.existsSync(DIST_SERVER)) {
      throw new Error(`dist/broker/server.js is missing at ${DIST_SERVER}; run \`npm run build\` before this suite`);
    }
  });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(testHome.dir, 'h-'));
    work = fs.mkdtempSync(path.join(testHome.dir, 'w-'));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(work, { recursive: true, force: true });
  });

  /** Every file and directory under `dir`, relative to it, with the bytes of each file. */
  function tree(dir: string): Record<string, string> {
    const out: Record<string, string> = {};
    const walk = (at: string) => {
      for (const entry of fs.readdirSync(at, { withFileTypes: true })) {
        const full = path.join(at, entry.name);
        const rel = path.relative(dir, full);
        if (entry.isDirectory()) {
          out[`${rel}/`] = '';
          walk(full);
        } else {
          out[rel] = fs.readFileSync(full).toString('hex');
        }
      }
    };
    walk(dir);
    return out;
  }

  function runBroker(mode: 'null' | 'default'): {
    name: string;
    value: string;
    grant: { status: number; text: string };
    resolved: { status: number; text: string };
  } {
    const name = `F8_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const value = crypto.randomBytes(16).toString('hex');
    const config: BrokerConfig = {
      socketPath: path.join(work, 'b.sock'),
      httpPort: 0,
      auditLog: path.join(work, 'audit.log'),
      tokenFile: path.join(work, 'broker.token'),
    };
    if (mode === 'default') {
      config.policyFile = path.join(work, 'policies.json');
      oneRulePolicy(config.policyFile, name);
    }
    const res = spawnSync(
      process.execPath,
      ['-e', CHILD, DIST_SERVER, JSON.stringify(config), mode, name],
      { env: { ...process.env, HOME: home, [name]: value }, encoding: 'utf-8', timeout: 30_000 },
    );
    if (res.status !== 0) throw new Error(`the broker process failed (exit ${res.status}):\n${res.stderr}`);
    return { name, value, ...(JSON.parse(res.stdout) as { grant: { status: number; text: string }; resolved: { status: number; text: string } }) };
  }

  it('HOME set empty at spawn holds 0 entries afterwards, and /resolve never returns the value in the environment', () => {
    const run = runBroker('null');

    expect(fs.readdirSync(home)).toEqual([]);
    expect(run.grant.status).toBe(404);
    expect(run.resolved.status).toBe(404);
    expect(run.resolved.text).toBe('{"error":"Not found"}');
    expect(run.resolved.text).not.toContain(run.value);
  }, CHILD_TIMEOUT_MS);

  it('a cache file in HOME that this broker could not decrypt is left present and byte-identical', () => {
    const cacheDir = path.join(home, '.secretless-ai', 'cache');
    fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(cacheDir, '.secret-cache'), crypto.randomBytes(64), { mode: 0o600 });
    const before = tree(home);

    runBroker('null');

    expect(fs.existsSync(path.join(cacheDir, '.secret-cache'))).toBe(true);
    expect(tree(home)).toEqual(before);
  }, CHILD_TIMEOUT_MS);

  it('control: the same run with the default resolver and an allowing policy writes under HOME and returns the value', () => {
    const run = runBroker('default');

    expect(run.resolved.status).toBe(200);
    expect(JSON.parse(run.resolved.text)).toEqual({ value: run.value });
    expect(fs.readdirSync(home).length).toBeGreaterThan(0);
  }, CHILD_TIMEOUT_MS);
});
