import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { BrokerServer } from './server';
import type { CredentialResolver } from './resolver';
import type { GrantResolver } from './grant-resolver';
import type { AuditEntry, PolicyConstraints, PolicyRule } from './types';
import { armChannelSpies, type ChannelSpies } from './audit-record.test-support';

/**
 * Every record the broker server writes carries a code from AUDIT_REASONS. No AIM URL or status
 * text, no address, no loader or backend message and no policy text is written as its reason,
 * and the text a code replaces is written to no other channel. The legacy /resolve record writes
 * the agent id and the credential name as sent only in parsed form, otherwise as
 * `unparsed:<length>`.
 *
 * Every listener here binds 127.0.0.1 or a Unix socket in the test's own temporary directory.
 */

const PLANTED_AGENT = 'Planted Payee Odalys Brennecke';

interface Broker {
  server: BrokerServer;
  dir: string;
  socketPath: string;
  httpPort: number;
  token: string;
  auditLog: string;
  stopped: boolean;
}

let brokers: Broker[] = [];
let closers: Array<() => Promise<void>> = [];
let spies: ChannelSpies;
/** Text the broker must write nowhere: checked against the channel spies after each test (T12). */
let planted: string[] = [];

/**
 * Each test below starts its brokers with the channel spies armed, and after it stops them, the
 * spies must hold no planted text (T12).
 */
function withBrokerHooks(): void {
  beforeEach(() => {
    brokers = [];
    closers = [];
    planted = ['Odalys', 'Brennecke'];
    spies = armChannelSpies();
  });

  afterEach(async () => {
    try {
      for (const b of brokers) await stopBroker(b);
      for (const close of closers) await close();
      const elsewhere = spies.text();
      for (const word of planted) {
        expect(elsewhere.includes(word), 'T12: planted text reached stdout, stderr or the console').toBe(false);
      }
    } finally {
      spies.restore();
      for (const b of brokers) fs.rmSync(b.dir, { recursive: true, force: true });
    }
  });
}

function rule(
  id: string,
  agentSelector: string,
  credentialSelector: string,
  effect: 'allow' | 'deny',
  constraints: PolicyConstraints = {},
): PolicyRule {
  return { id, agentSelector, credentialSelector, constraints, effect };
}

/** A resolver holding these names only. */
function values(entries: Record<string, string>): CredentialResolver {
  const held = new Map(Object.entries(entries));
  return { resolve: async (name: string) => held.get(name) } as unknown as CredentialResolver;
}

function throwing(err: Error): CredentialResolver {
  return {
    resolve: async () => {
      throw err;
    },
  } as unknown as CredentialResolver;
}

function fakeValue(): string {
  return `FAKE-${crypto.randomBytes(8).toString('hex')}`;
}

function listenerPort(server: BrokerServer): number {
  const httpServer = (server as unknown as { httpServer: http.Server }).httpServer;
  return (httpServer.address() as net.AddressInfo).port;
}

async function startBroker(opts: {
  rules?: PolicyRule[];
  resolver: CredentialResolver;
  aimUrl?: string;
  grantResolver?: GrantResolver;
  Server?: typeof BrokerServer;
}): Promise<Broker> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sar-'));
  const socketPath = path.join(dir, 'b.sock');
  const auditLog = path.join(dir, 'audit.log');
  const tokenFile = path.join(dir, 'broker.token');
  // Absent unless rules are given: a broker with no policy file loads no scanner at start.
  const policyFile = path.join(dir, 'broker-policies.json');
  if (opts.rules) fs.writeFileSync(policyFile, JSON.stringify({ rules: opts.rules }));
  const Server = opts.Server ?? BrokerServer;
  const server = new Server(
    { socketPath, httpPort: 0, auditLog, tokenFile, policyFile, ...(opts.aimUrl ? { aimUrl: opts.aimUrl } : {}) },
    { resolver: opts.resolver, ...(opts.grantResolver ? { grantResolver: opts.grantResolver } : {}) },
  );
  const b: Broker = { server, dir, socketPath, httpPort: 0, token: '', auditLog, stopped: true };
  brokers.push(b);
  await server.start();
  b.stopped = false;
  b.httpPort = listenerPort(server);
  b.token = fs.readFileSync(tokenFile, 'utf-8');
  return b;
}

async function stopBroker(b: Broker): Promise<void> {
  if (b.stopped) return;
  b.stopped = true;
  await b.server.stop();
}

/** A stand-in AIM on 127.0.0.1: `/health` answers 200, an agent lookup what `answer` says. */
async function startAim(answer: (url: string) => { status: number; body?: unknown }): Promise<string> {
  const aim = http.createServer((req, res) => {
    const { status, body } = req.url === '/health' ? { status: 200, body: {} } : answer(req.url ?? '');
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body ?? {}));
  });
  await new Promise<void>((resolve) => aim.listen(0, '127.0.0.1', resolve));
  closers.push(() => new Promise<void>((resolve) => aim.close(() => resolve())));
  return `http://127.0.0.1:${(aim.address() as net.AddressInfo).port}`;
}

/** A loopback port nothing listens on. */
async function closedPort(): Promise<number> {
  const probe = net.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as net.AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

function send(
  target: { socketPath: string } | { port: number },
  opts: { path: string; method?: string; token?: string; body?: string },
): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const body = opts.body ?? '';
    const headers: Record<string, string | number> = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    };
    if (opts.token !== undefined) headers.Authorization = `Bearer ${opts.token}`;
    const req = http.request(
      {
        ...('socketPath' in target ? { socketPath: target.socketPath } : { host: '127.0.0.1', port: target.port }),
        path: opts.path,
        method: opts.method ?? 'POST',
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          let json: unknown;
          try {
            json = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
          } catch {
            json = undefined;
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

function resolveOn(b: Broker, agentId: string, credentialName: string): Promise<{ status: number; json: any }> {
  return send({ socketPath: b.socketPath }, { path: '/resolve', token: b.token, body: JSON.stringify({ agentId, credentialName }) });
}

function logText(b: Broker): string {
  return fs.readFileSync(b.auditLog, 'utf-8');
}

function records(b: Broker, eventType?: string): AuditEntry[] {
  return logText(b)
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as AuditEntry)
    .filter((r) => eventType === undefined || r.eventType === eventType);
}

function lastResolve(b: Broker): AuditEntry {
  const resolves = records(b, 'resolve');
  return resolves[resolves.length - 1];
}

function expectAbsent(b: Broker, words: string[]): void {
  const text = logText(b);
  for (const word of words) expect(text.includes(word), `the audit log carries planted text`).toBe(false);
}

/** A time window two hours from now, one hour long, so the current time is outside it. */
function windowExcludingNow(): { start: string; end: string } {
  const now = new Date();
  const minutes = now.getHours() * 60 + now.getMinutes();
  const at = (m: number) => {
    const t = m % 1440;
    return `${String(Math.floor(t / 60)).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`;
  };
  return { start: at(minutes + 120), end: at(minutes + 180) };
}

describe('T4: the fixed-text writers write codes', () => {
  withBrokerHooks();

  it('T4: start and stop are recorded as broker-started and broker-stopping', async () => {
    const b = await startBroker({ rules: [], resolver: values({}) });
    await stopBroker(b);

    expect(records(b).map((r) => [r.eventType, r.reason])).toEqual([
      ['startup', 'broker-started'],
      ['shutdown', 'broker-stopping'],
    ]);
  });

  it('T4: an AIM that does not answer the reachability probe is recorded as aim-unreachable', async () => {
    const b = await startBroker({ rules: [], resolver: values({}), aimUrl: `http://127.0.0.1:${await closedPort()}` });

    expect(records(b, 'aim_unreachable').map((r) => r.reason)).toEqual(['aim-unreachable']);
  });

  it('T4: an allowed name the resolver holds no value for is recorded as credential-not-found', async () => {
    const b = await startBroker({ rules: [rule('allow-any', 'agent-any', '*', 'allow')], resolver: values({}) });

    expect(await resolveOn(b, 'agent-any', 'TEST_KEY')).toEqual({ status: 404, json: { error: 'Credential not found' } });
    expect(lastResolve(b)).toMatchObject({ result: 'denied', reason: 'credential-not-found' });
  });
});

describe('T5: a 4xx from AIM is recorded by status', () => {
  withBrokerHooks();

  it('T5: each status has its code, and the agent id the lookup URL carries is written nowhere', async () => {
    const statuses = [401, 403, 404, 429, 418];
    let next = 0;
    const aimUrl = await startAim(() => ({ status: statuses[next++] ?? 503 }));
    const b = await startBroker({ rules: [], resolver: values({}), aimUrl });

    for (const _ of statuses) {
      expect((await resolveOn(b, PLANTED_AGENT, 'NO_RULE_KEY')).status).toBe(403);
    }

    const aimRecords = records(b, 'aim_auth_error');
    expect(aimRecords.map((r) => r.reason)).toEqual([
      'aim-unauthorized',
      'aim-forbidden',
      'aim-not-found',
      'aim-rate-limited',
      'aim-client-error',
    ]);
    for (const r of aimRecords) {
      expect(r).toMatchObject({ agentId: 'broker', credentialName: '', policyId: '', result: 'denied' });
    }
    expect(records(b, 'resolve').map((r) => r.agentId)).toEqual(statuses.map(() => 'unparsed:30'));
    // Neither the id as sent nor the id as the lookup URL encodes it.
    expectAbsent(b, [PLANTED_AGENT, encodeURIComponent(PLANTED_AGENT), 'Odalys', 'Brennecke', '/api/v1/agents', '127.0.0.1']);
  });
});

describe('T6: a refused bearer token is recorded by transport', () => {
  withBrokerHooks();

  it('T6: the socket and the HTTP listener each write their code, and no address', async () => {
    const b = await startBroker({ rules: [], resolver: values({}) });
    const wrong = crypto.randomBytes(32).toString('hex');

    const answers = [
      await send({ socketPath: b.socketPath }, { path: '/resolve', token: wrong, body: '{}' }),
      await send({ port: b.httpPort }, { path: '/resolve', token: wrong, body: '{}' }),
      await send({ socketPath: b.socketPath }, { path: '/health', method: 'GET' }),
      await send({ port: b.httpPort }, { path: '/health', method: 'GET' }),
    ];

    expect(answers.map((a) => a.status)).toEqual([401, 401, 401, 401]);
    const auth = records(b, 'auth');
    expect(auth.map((r) => r.reason)).toEqual([
      'auth-refused-socket',
      'auth-refused-http',
      'auth-refused-socket',
      'auth-refused-http',
    ]);
    for (const r of auth) {
      expect(Object.keys(r)).toEqual([
        'timestamp',
        'eventType',
        'agentId',
        'credentialName',
        'policyId',
        'result',
        'reason',
        'latencyMs',
        'prevHash',
        'sig',
      ]);
      expect(r).toMatchObject({ agentId: 'unknown', credentialName: '', policyId: '', result: 'denied', latencyMs: 0 });
    }
    expectAbsent(b, ['127.0.0.1', '::1', 'ffff:']);
  });
});

describe('T7: the duplicate-member scanner did not load', () => {
  withBrokerHooks();

  const LOADER_TEXT = "Cannot find module '/home/planted-wexmoor/node_modules/@opena2a/atx-verify/dist/index.js'";

  afterEach(() => {
    vi.doUnmock('@opena2a/atx-verify');
    vi.resetModules();
  });

  it.each(['resolve', 'grant'] as const)(
    'T7: /%s records its code, and the loader message is written nowhere',
    async (endpoint) => {
      planted.push('wexmoor');
      vi.resetModules();
      vi.doMock('@opena2a/atx-verify', () => {
        throw new Error(LOADER_TEXT);
      });
      const { BrokerServer: FreshServer } = await import('./server.js');
      const b = await startBroker({
        Server: FreshServer as unknown as typeof BrokerServer,
        resolver: values({}),
        ...(endpoint === 'grant' ? { grantResolver: {} as GrantResolver } : {}),
      });

      const res = await send(
        { socketPath: b.socketPath },
        { path: `/${endpoint}`, token: b.token, body: '{"agentId":"agent-a","credentialName":"TEST_KEY"}' },
      );

      expect(res.status).toBe(503);
      expect(records(b, 'error').map((r) => r.reason)).toEqual([`scanner-unavailable-${endpoint}`]);
      expectAbsent(b, ['wexmoor', 'Cannot find module', 'node_modules']);
    },
  );
});

describe('T8: a legacy policy decision is recorded by the return that decided it', () => {
  withBrokerHooks();

  it('T8: each of the nine returns writes its code, and the 403 body keeps its text', async () => {
    const window = windowExcludingNow();
    const aimUrl = await startAim((url) => {
      if (url.endsWith('/agent-low-trust')) {
        return { status: 200, body: { agentId: 'agent-low-trust', trustScore: 0.2, capabilities: [], verified: true } };
      }
      if (url.endsWith('/agent-no-cap')) {
        return { status: 200, body: { agentId: 'agent-no-cap', trustScore: 0.9, capabilities: ['read'], verified: true } };
      }
      // No identity for any other agent, and no 4xx record.
      return { status: 503 };
    });
    const b = await startBroker({
      rules: [
        rule('deny-prod', 'agent-deny', 'DENIED_KEY', 'deny'),
        rule('allow-plain', 'agent-allow', 'ALLOWED_KEY', 'allow'),
        rule('allow-window', 'agent-window', 'WINDOW_KEY', 'allow', { timeWindow: window }),
        rule('allow-trust', 'agent-*', 'TRUST_KEY', 'allow', { minTrustScore: 0.5 }),
        rule('allow-cap', 'agent-*', 'CAP_KEY', 'allow', { requireCapability: 'deploy' }),
        rule('allow-rate', 'agent-rate', 'RATE_KEY', 'allow', { rateLimit: { maxPerMinute: 1 } }),
      ],
      resolver: values({ ALLOWED_KEY: fakeValue(), RATE_KEY: fakeValue() }),
      aimUrl,
    });

    const cases: Array<[string, string, string, string | null]> = [
      ['agent-deny', 'DENIED_KEY', 'rule-deny', 'Denied by rule "deny-prod"'],
      ['agent-allow', 'ALLOWED_KEY', 'rule-allow', null],
      ['agent-none', 'NO_RULE_KEY', 'rule-default-deny', 'No matching allow rule (default deny)'],
      ['agent-window', 'WINDOW_KEY', 'rule-outside-time-window', `Outside allowed time window (${window.start}-${window.end})`],
      ['agent-anon', 'TRUST_KEY', 'rule-trust-score-no-identity', 'Trust score required (min 0.5) but no agent identity available'],
      ['agent-low-trust', 'TRUST_KEY', 'rule-trust-score-below-minimum', 'Trust score 0.2 below minimum 0.5'],
      ['agent-anon', 'CAP_KEY', 'rule-capability-no-identity', 'Capability "deploy" required but no agent identity available'],
      ['agent-no-cap', 'CAP_KEY', 'rule-capability-missing', 'Agent lacks required capability "deploy"'],
      ['agent-rate', 'RATE_KEY', 'rule-allow', null],
      ['agent-rate', 'RATE_KEY', 'rule-rate-limit-exceeded', 'Rate limit exceeded (1/min)'],
    ];
    for (const [agent, credential, code, bodyReason] of cases) {
      const res = await resolveOn(b, agent, credential);
      if (bodyReason === null) {
        expect(res.status).toBe(200);
      } else {
        expect(res).toEqual({ status: 403, json: { error: 'Access denied', reason: bodyReason } });
      }
      expect(lastResolve(b).reason).toBe(code);
    }
    expect(records(b, 'resolve')).toHaveLength(cases.length);
  });
});

describe('T9: a backend exception is recorded as backend-error', () => {
  withBrokerHooks();

  it('T9: the code is written, and the exception message is written nowhere', async () => {
    const value = fakeValue();
    planted.push('Quillfeather', value);
    const b = await startBroker({
      rules: [rule('allow-any', 'agent-any', '*', 'allow')],
      resolver: throwing(new Error(`read refused for payee Quillfeather, store returned ${value}`)),
    });

    expect(await resolveOn(b, 'agent-any', 'TEST_KEY')).toEqual({ status: 500, json: { error: 'Internal error' } });
    expect(lastResolve(b)).toMatchObject({ result: 'denied', reason: 'backend-error' });
    expectAbsent(b, ['Quillfeather', value, 'read refused']);
  });
});

describe('T11: the legacy /resolve ids are written parsed or marked', () => {
  withBrokerHooks();

  it('T11: agentId is written as sent only as a DID or an agent name of at most 128 bytes', async () => {
    const b = await startBroker({ rules: [], resolver: values({}) });
    const uuid = crypto.randomUUID();
    const name129 = 'n'.repeat(129);
    const did129 = `did:web:${'x'.repeat(121)}`;
    planted.push(name129, did129);

    const cases: Array<[string, string]> = [
      ['scan-01', 'scan-01'],
      [uuid, uuid],
      ['did:web:example.com', 'did:web:example.com'],
      ['m'.repeat(128), 'm'.repeat(128)],
      [name129, 'unparsed:129'],
      [did129, 'unparsed:129'],
      [PLANTED_AGENT, 'unparsed:30'],
    ];
    for (const [sent, written] of cases) {
      expect((await resolveOn(b, sent, 'NO_RULE_KEY')).status).toBe(403);
      expect(lastResolve(b).agentId).toBe(written);
    }
    expectAbsent(b, [name129, did129, 'Odalys', 'Brennecke']);
  });

  it('T11: credentialName is written as sent only when resolved or named exactly by a rule', async () => {
    // Provider-token-shaped, built from fragments at run time: never a literal in this file.
    const tokenShaped = ['g', 'h', 'p', '_'].join('') + crypto.randomBytes(18).toString('hex');
    planted.push(tokenShaped, 'PROD_PLANTED_PAYEE');
    const b = await startBroker({
      rules: [
        rule('deny-prod', '*', 'PROD_*', 'deny'),
        rule('deny-blocked', '*', 'BLOCKED_KEY', 'deny'),
        rule('allow-scan', 'scan-*', 'GITHUB_*', 'allow'),
        rule('allow-any', 'agent-any', '*', 'allow'),
      ],
      resolver: values({ GITHUB_TOKEN: fakeValue() }),
    });

    expect((await resolveOn(b, 'scan-01', 'GITHUB_TOKEN')).status).toBe(200);
    expect(lastResolve(b)).toMatchObject({ credentialName: 'GITHUB_TOKEN', result: 'allowed', reason: 'rule-allow' });

    expect((await resolveOn(b, 'scan-01', 'PROD_PLANTED_PAYEE')).status).toBe(403);
    expect(lastResolve(b)).toMatchObject({ credentialName: 'unparsed:18', policyId: 'deny-prod', reason: 'rule-deny' });

    expect((await resolveOn(b, 'scan-01', 'BLOCKED_KEY')).status).toBe(403);
    expect(lastResolve(b)).toMatchObject({ credentialName: 'BLOCKED_KEY', policyId: 'deny-blocked', reason: 'rule-deny' });

    expect((await resolveOn(b, 'agent-any', tokenShaped)).status).toBe(404);
    expect(lastResolve(b)).toMatchObject({ credentialName: 'unparsed:40', reason: 'credential-not-found' });

    expectAbsent(b, [tokenShaped, 'PROD_PLANTED_PAYEE']);
  });
});

describe('T12: the channel spies', () => {
  it('T12: see what is written to stdout, stderr and each console method (control)', () => {
    const control = armChannelSpies({ swallow: true });
    try {
      process.stdout.write('spy-control-stdout');
      process.stderr.write(Buffer.from('spy-control-stderr'));
      console.log('spy-control-log');
      console.error('spy-control-error');
      console.warn('spy-control-warn');
      console.info('spy-control-info');
      console.debug('spy-control-debug');
      const text = control.text();
      for (const channel of ['stdout', 'stderr', 'log', 'error', 'warn', 'info', 'debug']) {
        expect(text).toContain(`spy-control-${channel}`);
      }
    } finally {
      control.restore();
    }
  });
});
