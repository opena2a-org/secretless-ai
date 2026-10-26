/**
 * `POST /grant` on the broker an operator starts.
 *
 * Every broker in this file is started by `startDaemon` from files on disk, the way
 * `broker start` does it. The test hands nothing to `BrokerServer`, so a daemon that builds
 * no grant resolver fails here with the 404 an operator would get. The identity provider, the
 * downstream API and AIM are local HTTP servers, so the token exchange and the downstream call
 * travel over the transports a deployment uses rather than over test doubles.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';

import { startDaemon, type DaemonOptions } from './daemon';
import type { BrokerServer } from './server';
import type { Atx } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };

// @opena2a/atx-verify is ESM-only and this file compiles as CommonJS, so its values load
// through require(esm), as in aap-conformance.test.ts.
const { canonicalPayload, canonicalPayloadV11 } = require('@opena2a/atx-verify') as typeof import(
  '@opena2a/atx-verify',
  { with: { 'resolution-mode': 'import' } }
);

const ISSUER = 'did:opena2a:authority:issuer.test';
const AGENT_ID = 'aim_orders_reader';
const BROKER_ISSUER = 'https://broker.example.test';
const BROKER_KEY_ID = 'broker-key-1';
// The value that must reach the downstream API and never the agent.
const SCOPED_TOKEN = 'scoped-token-must-not-leak';

interface IssuerKey {
  privateKey: crypto.KeyObject;
  pubHex: string;
}

function makeIssuerKey(): IssuerKey {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  return { privateKey, pubHex: Buffer.from(jwk.x, 'base64url').toString('hex') };
}

function isoSeconds(offsetMs: number): string {
  return new Date(Date.now() + offsetMs).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** A signed ATX that is valid on the wall clock, which is the clock a started daemon uses. */
function signedAtx(key: IssuerKey, overrides: Partial<Atx> = {}): Atx {
  const atx: Atx = {
    atcVersion: '1.1',
    agentId: AGENT_ID,
    agentDid: 'did:opena2a:agent:acme/orders-reader',
    version: '1.0.0',
    contentHash: 'sha256:abc123',
    buildAttestation: 'sha256:def456',
    issuerDid: ISSUER,
    issuerChain: [ISSUER],
    trustLevel: 4,
    trustScore: 0.95,
    issuedAt: isoSeconds(-3_600_000),
    expiresAt: isoSeconds(3_600_000),
    capabilities: ['orders:read'],
    scanSummary: { oasbLevel: 'L2' },
    signatures: [],
    ...overrides,
  };
  const payload = atx.atcVersion === '1.1' ? canonicalPayloadV11(atx) : canonicalPayload(atx);
  const sig = crypto.sign(null, payload, key.privateKey);
  atx.signatures = [{ keyId: 'test#ed25519', algorithm: 'Ed25519', value: sig.toString('base64') }];
  return atx;
}

type Handler = (req: http.IncomingMessage, body: string, res: http.ServerResponse) => void;

/** Start a local HTTP server on an ephemeral loopback port. */
async function listen(handler: Handler): Promise<{ server: http.Server; origin: string }> {
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => handler(req, Buffer.concat(chunks).toString('utf-8'), res));
  });
  await new Promise<void>((resolve) => { server.listen(0, '127.0.0.1', resolve); });
  const { port } = server.address() as { port: number };
  return { server, origin: `http://127.0.0.1:${port}` };
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function brokerRequest(
  socketPath: string,
  method: string,
  urlPath: string,
  token: string,
  body?: unknown,
): Promise<{ status: number; text: string; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    const req = http.request(
      {
        socketPath,
        path: urlPath,
        method,
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
          const text = Buffer.concat(chunks).toString('utf-8');
          let json: unknown;
          try {
            json = JSON.parse(text);
          } catch {
            json = undefined;
          }
          resolve({ status: res.statusCode ?? 0, text, json });
        });
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

describe('POST /grant on a broker started by startDaemon', () => {
  let dir: string;
  let issuerKey: IssuerKey;
  let idp: { server: http.Server; origin: string };
  let api: { server: http.Server; origin: string };
  let tokenRequests: URLSearchParams[];
  let apiCalls: Array<{ method: string; url: string; authorization: string }>;
  let server: BrokerServer | undefined;
  const extraServers: http.Server[] = [];

  /**
   * Every path the daemon writes, inside this test's own directory. The broker serves grants
   * only, so it reads no policy file, the default under the HOME of the run included.
   */
  function daemonOptions(extra: Partial<DaemonOptions> = {}): DaemonOptions {
    return {
      httpPort: 0,
      socketPath: path.join(dir, 'broker.sock'),
      noResolve: true,
      auditLog: path.join(dir, 'audit.log'),
      pidFile: path.join(dir, 'broker.pid'),
      tokenFile: path.join(dir, 'broker.token'),
      ...extra,
    };
  }

  /** The grant file an operator would write for one grant served through one provider. */
  function grantFileContent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      version: 1,
      trust: {
        trustedIssuers: [ISSUER],
        publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: issuerKey.pubHex }],
      },
      assertion: {
        issuer: BROKER_ISSUER,
        keyId: BROKER_KEY_ID,
        keyFile: path.join(dir, 'assertion.key'),
      },
      providers: {
        'orders-idp': { mode: 'exchange', tokenEndpoint: `${idp.origin}/oauth2/v1/token` },
      },
      bindings: [
        {
          grant: 'grant://orders-db',
          match: { trustClass: 'orders:read', minTrustLevel: 3, oasbLevel: '>=L2' },
          resolve: {
            mode: 'exchange',
            providerId: 'orders-idp',
            scope: 'orders.read',
            audience: api.origin,
            ttlSeconds: 300,
          },
        },
      ],
      ...overrides,
    };
  }

  function writeGrantFile(content: unknown = grantFileContent()): string {
    const file = path.join(dir, 'grants.json');
    fs.writeFileSync(file, JSON.stringify(content, null, 2));
    return file;
  }

  function grantRequest(atx: Atx): Record<string, unknown> {
    return {
      agentId: AGENT_ID,
      atx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/orders', query: { customer: 'c-123' } },
    };
  }

  function brokerToken(): string {
    return fs.readFileSync(path.join(dir, 'broker.token'), 'utf-8');
  }

  beforeEach(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grant-daemon-'));
    issuerKey = makeIssuerKey();
    tokenRequests = [];
    apiCalls = [];
    server = undefined;

    idp = await listen((req, body, res) => {
      if (req.method !== 'POST' || req.url !== '/oauth2/v1/token') {
        sendJson(res, 404, { error: 'not_found' });
        return;
      }
      tokenRequests.push(new URLSearchParams(body));
      sendJson(res, 200, { access_token: SCOPED_TOKEN, token_type: 'Bearer', expires_in: 300 });
    });
    api = await listen((req, _body, res) => {
      apiCalls.push({
        method: req.method ?? '',
        url: req.url ?? '',
        authorization: String(req.headers.authorization ?? ''),
      });
      sendJson(res, 200, { rows: [{ id: 1, customer: 'c-123', total: 42 }] });
    });
  });

  afterEach(async () => {
    if (server) await server.stop();
    for (const s of [idp.server, api.server, ...extraServers.splice(0)]) {
      await new Promise<void>((resolve) => { s.close(() => resolve()); });
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('serves a grant end to end from a grant file, and only the result reaches the agent', async () => {
    const grantFile = writeGrantFile();
    server = await startDaemon(daemonOptions({ grantFile }));
    const socketPath = path.join(dir, 'broker.sock');

    // Same server, same token: /health answers, so a 404 on /grant would be an endpoint that
    // is switched off and not a broker that is down.
    expect((await brokerRequest(socketPath, 'GET', '/health', brokerToken())).status).toBe(200);

    const request = grantRequest(signedAtx(issuerKey));
    const res = await brokerRequest(socketPath, 'POST', '/grant', brokerToken(), request);

    expect(res.status).toBe(200);
    expect(res.json.result.status).toBe(200);
    expect(res.json.result.body.rows).toEqual([{ id: 1, customer: 'c-123', total: 42 }]);

    // The scoped token reached the downstream API, on the operation the agent asked for.
    expect(apiCalls).toEqual([
      { method: 'GET', url: '/orders?customer=c-123', authorization: `Bearer ${SCOPED_TOKEN}` },
    ]);

    // One RFC 8693 exchange, carrying a broker assertion signed by the key whose public half
    // the daemon wrote beside the key file for the operator to register.
    expect(tokenRequests).toHaveLength(1);
    const exchange = tokenRequests[0];
    expect(exchange.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(exchange.get('scope')).toBe('orders.read');
    expect(exchange.get('audience')).toBe(api.origin);
    const assertion = exchange.get('subject_token') ?? '';
    const [headerPart, claimsPart, signaturePart] = assertion.split('.');
    const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf-8'));
    const claims = JSON.parse(Buffer.from(claimsPart, 'base64url').toString('utf-8'));
    expect(header).toEqual({ alg: 'EdDSA', typ: 'JWT', kid: BROKER_KEY_ID });
    expect(claims.iss).toBe(BROKER_ISSUER);
    expect(claims.sub).toBe('did:opena2a:agent:acme/orders-reader');
    expect(claims.aud).toBe(api.origin);
    expect(claims.trust_class).toBe('orders:read');
    const publicJwk = JSON.parse(
      fs.readFileSync(path.join(dir, 'assertion.key.pub.json'), 'utf-8'),
    );
    expect(publicJwk.kid).toBe(BROKER_KEY_ID);
    expect(
      crypto.verify(
        null,
        Buffer.from(`${headerPart}.${claimsPart}`),
        crypto.createPublicKey({ key: publicJwk, format: 'jwk' }),
        Buffer.from(signaturePart, 'base64url'),
      ),
    ).toBe(true);

    // What the agent sent and received carries neither the scoped token, nor the assertion,
    // nor where the downstream or the identity provider live.
    const agentVisible = JSON.stringify(request) + res.text;
    expect(agentVisible).not.toContain(SCOPED_TOKEN);
    expect(agentVisible).not.toContain(assertion);
    expect(agentVisible).not.toContain(api.origin);
    expect(agentVisible).not.toContain(idp.origin);

    // The decision is in the broker's own audit log, beside its startup record, attributed to
    // the verified agent and to the binding that granted it.
    const audit = readAudit(path.join(dir, 'audit.log'));
    expect(audit.some((e) => e.eventType === 'startup')).toBe(true);
    const granted = audit.filter((e) => e.eventType === 'grant');
    expect(granted).toHaveLength(1);
    expect(granted[0]).toMatchObject({
      agentId: AGENT_ID,
      credentialName: 'grant://orders-db',
      policyId: 'grant://orders-db',
      result: 'allowed',
    });
    expect(JSON.stringify(audit)).not.toContain(SCOPED_TOKEN);
  });

  it('denies a credential signed by a key the grant file does not name', async () => {
    server = await startDaemon(daemonOptions({ grantFile: writeGrantFile() }));

    const res = await brokerRequest(
      path.join(dir, 'broker.sock'), 'POST', '/grant', brokerToken(),
      grantRequest(signedAtx(makeIssuerKey())),
    );

    expect(res.status).toBe(403);
    expect(res.json).toEqual({ error: 'denied' });
    expect(tokenRequests).toHaveLength(0);
    expect(apiCalls).toHaveLength(0);
  });

  it('denies an agent the grant file lists as revoked', async () => {
    const content = grantFileContent();
    (content.trust as Record<string, unknown>).crl = {
      entries: [{ agentId: AGENT_ID, reason: 'key compromise' }],
    };
    server = await startDaemon(daemonOptions({ grantFile: writeGrantFile(content) }));

    const res = await brokerRequest(
      path.join(dir, 'broker.sock'), 'POST', '/grant', brokerToken(),
      grantRequest(signedAtx(issuerKey)),
    );

    expect(res.status).toBe(403);
    expect(apiCalls).toHaveLength(0);
    const denied = readAudit(path.join(dir, 'audit.log')).filter((e) => e.eventType === 'grant');
    expect(denied).toHaveLength(1);
    expect(denied[0].result).toBe('denied');
    expect(String(denied[0].reason)).toContain('REVOKED');
  });

  it('denies an agent AIM reports as not verified when the broker is started with an AIM URL', async () => {
    const aimLookups: string[] = [];
    const aim = await listen((req, _body, res) => {
      if (req.url === '/health') {
        sendJson(res, 200, { status: 'healthy' });
        return;
      }
      aimLookups.push(req.url ?? '');
      sendJson(res, 200, { agentId: AGENT_ID, trustScore: 0.9, capabilities: [], verified: false });
    });
    extraServers.push(aim.server);
    server = await startDaemon(daemonOptions({ grantFile: writeGrantFile(), aimUrl: aim.origin }));

    const res = await brokerRequest(
      path.join(dir, 'broker.sock'), 'POST', '/grant', brokerToken(),
      grantRequest(signedAtx(issuerKey)),
    );

    expect(res.status).toBe(403);
    expect(aimLookups).toEqual([`/api/v1/agents/${AGENT_ID}`]);
    expect(tokenRequests).toHaveLength(0);
    const denied = readAudit(path.join(dir, 'audit.log')).filter((e) => e.eventType === 'grant');
    expect(denied.map((e) => e.reason)).toEqual(['AIM reports agent not verified']);
  });

  it('startDaemon prints nothing on a grant start', async () => {
    const grantFile = writeGrantFile();
    const out: string[] = [];
    const collect = (...a: unknown[]) => { out.push(a.join(' ')); };
    const spies = [
      vi.spyOn(console, 'log').mockImplementation(collect),
      vi.spyOn(console, 'info').mockImplementation(collect),
      vi.spyOn(console, 'warn').mockImplementation(collect),
      vi.spyOn(console, 'error').mockImplementation(collect),
      vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
        out.push(String(chunk));
        return true;
      }),
    ];
    try {
      server = await startDaemon(daemonOptions({ grantFile }));
    } finally {
      for (const spy of spies) spy.mockRestore();
    }

    expect(out).toEqual([]);
    // What the lines used to say is on the server the caller holds.
    expect(server.getStatus().routes.grant).toMatchObject({ served: true, source: { file: grantFile } });
  });

  it('reports on /status what the grant route was loaded from, and never the private key path', async () => {
    const grantFile = writeGrantFile();
    server = await startDaemon(daemonOptions({ grantFile }));

    const res = await brokerRequest(path.join(dir, 'broker.sock'), 'GET', '/status', brokerToken());

    expect(res.status).toBe(200);
    expect(res.json.routes).toEqual({
      grant: {
        served: true,
        source: {
          file: grantFile,
          bindingCount: 1,
          providerCount: 1,
          assertionPublicKeyFile: `${path.join(dir, 'assertion.key')}.pub.json`,
          assertionKeyCreated: true,
        },
      },
      resolve: { served: false, reason: 'disabled' },
    });
    expect(res.json).toMatchObject({ grantServed: true, resolveServed: false, policyCount: 0 });
    expect(res.text).not.toContain(`${JSON.stringify(path.join(dir, 'assertion.key'))}`);
    expect(res.text).not.toContain('assertionKeyFile');
  });

  it('refuses to start when the named grant file does not exist, and leaves nothing running', async () => {
    const missing = path.join(dir, 'no-such-grants.json');

    await expect(startDaemon(daemonOptions({ grantFile: missing }))).rejects.toThrow(
      `Grant file ${missing} does not exist`,
    );

    expect(fs.existsSync(path.join(dir, 'broker.pid'))).toBe(false);
    expect(fs.existsSync(path.join(dir, 'broker.sock'))).toBe(false);
    expect(fs.existsSync(path.join(dir, 'broker.token'))).toBe(false);
  });

  it('refuses to start on a grant file it cannot apply as written', async () => {
    // A misspelled section: read as written, the operator's bindings would never load.
    const { bindings, ...rest } = grantFileContent();
    const grantFile = writeGrantFile({ ...rest, binding: bindings });

    await expect(startDaemon(daemonOptions({ grantFile }))).rejects.toThrow(
      /unknown top-level key "binding" \(did you mean "bindings"\?\)/,
    );

    expect(fs.existsSync(path.join(dir, 'broker.pid'))).toBe(false);
    expect(fs.existsSync(path.join(dir, 'broker.sock'))).toBe(false);
    expect(fs.existsSync(path.join(dir, 'broker.token'))).toBe(false);
  });
});

/**
 * The default grant file is `~/.secretless-ai/broker-grants.json`, resolved from the home
 * directory when `daemon.ts` loads. Each test points HOME at its own directory and loads a
 * fresh copy of the module, so the default is exercised without reading or writing the home
 * directory the suite was started from.
 */
describe('the default grant file', () => {
  let home: string;
  let savedHome: string | undefined;
  let server: BrokerServer | undefined;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'grant-home-'));
    savedHome = process.env.HOME;
    process.env.HOME = home;
    vi.resetModules();
    server = undefined;
  });

  afterEach(async () => {
    if (server) await server.stop();
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    vi.resetModules();
    fs.rmSync(home, { recursive: true, force: true });
  });

  /** The policy file is left to its default too, which is absent under this HOME. */
  function options(): DaemonOptions {
    return {
      httpPort: 0,
      socketPath: path.join(home, 'broker.sock'),
      auditLog: path.join(home, 'audit.log'),
      pidFile: path.join(home, 'broker.pid'),
      tokenFile: path.join(home, 'broker.token'),
    };
  }

  async function postGrant(): Promise<{ status: number; json: any }> {
    return brokerRequest(
      path.join(home, 'broker.sock'), 'POST', '/grant',
      fs.readFileSync(path.join(home, 'broker.token'), 'utf-8'),
      {
        agentId: AGENT_ID,
        atx: signedAtx(makeIssuerKey()),
        grant: 'grant://orders-db',
        operation: { method: 'GET', path: '/orders' },
      },
    );
  }

  it('leaves /grant not found when no grant file exists', async () => {
    const daemon = await import('./daemon.js');
    server = await daemon.startDaemon(options());

    const res = await postGrant();

    expect(res.status).toBe(404);
    expect(fs.existsSync(path.join(home, '.secretless-ai', 'broker-assertion.key'))).toBe(false);
  });

  it('is loaded when it exists, with the assertion key created beside it', async () => {
    const configDir = path.join(home, '.secretless-ai');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, 'broker-grants.json'),
      JSON.stringify({
        trust: {
          trustedIssuers: [ISSUER],
          publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: makeIssuerKey().pubHex }],
        },
        assertion: { issuer: BROKER_ISSUER, keyId: BROKER_KEY_ID },
        providers: {},
        bindings: [],
      }),
    );
    const daemon = await import('./daemon.js');
    server = await daemon.startDaemon(options());

    const res = await postGrant();

    // Configured, so the endpoint decides; the credential is from an issuer the file does not
    // trust, so the decision is the uniform denial.
    expect(res.status).toBe(403);
    expect(res.json).toEqual({ error: 'denied' });
    const keyFile = path.join(configDir, 'broker-assertion.key');
    expect(fs.statSync(keyFile).mode & 0o777).toBe(0o600);
    expect(fs.existsSync(`${keyFile}.pub.json`)).toBe(true);
  });
});
