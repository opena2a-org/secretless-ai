import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import {
  ExchangeProvider,
  TOKEN_EXCHANGE_GRANT_TYPE,
  SUBJECT_TOKEN_TYPE_JWT,
  type TokenExchangeRequest,
  type TokenExchangeResponse,
  type TokenExchangeTransport,
} from './exchange';
import { createOktaExchangeProvider } from './okta-adapter';
import { generateBrokerSigningKey, mintBrokerAssertion, brokerPublicJwk } from './assertion';
import type { ResolutionContext } from '@opena2a/atx-verify';
import type { ResourceBinding } from './types';

const CTX: ResolutionContext = {
  agentId: 'aim_orders_reader',
  agentDid: 'did:opena2a:agent:acme/orders-reader',
  issuerDid: 'did:opena2a:authority:opena2a.org',
  issuerChain: ['did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
  trustScore: 0.95,
  capabilities: ['orders:read'],
  oasbLevel: 'L2',
};

const BINDING: ResourceBinding = {
  mode: 'exchange',
  providerId: 'orders-idp',
  scope: 'orders.read',
  audience: 'https://api.orders.internal',
  ttlSeconds: 300,
  trustClass: 'orders:read',
};

/** Records the request and returns a canned scoped token. */
class FakeTransport implements TokenExchangeTransport {
  last?: TokenExchangeRequest;
  constructor(private readonly token = 'scoped-downstream-token-xyz') {}
  async exchange(req: TokenExchangeRequest): Promise<TokenExchangeResponse> {
    this.last = req;
    return { access_token: this.token, token_type: 'Bearer', expires_in: 300 };
  }
}

describe('broker assertion (AAP §11)', () => {
  it('mints an EdDSA JWT whose claims derive from the verified ATX context', () => {
    const key = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    const jwt = mintBrokerAssertion(CTX, BINDING, key, 1_000_000);
    const [h, p, s] = jwt.split('.');
    expect(h && p && s).toBeTruthy();

    const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf-8'));
    expect(claims).toMatchObject({
      iss: 'https://broker.acme.example',
      sub: CTX.agentDid,
      aud: BINDING.audience,
      scope: BINDING.scope,
      // trust_class is the abstract ATX capability, NOT the downstream scope
      // (AAP-SPEC §4.2; regression for the scope/trust-class conflation).
      trust_class: 'orders:read',
      trust_level: 4,
      issuer_chain: CTX.issuerChain,
      iat: 1_000_000,
      exp: 1_000_300,
    });

    // Signature verifies against the broker's published public key.
    const pub = crypto.createPublicKey(key.privateKey);
    const ok = crypto.verify(null, Buffer.from(`${h}.${p}`), pub, Buffer.from(s, 'base64url'));
    expect(ok).toBe(true);
  });

  it('refuses to mint without a trustClass (never a scope-shaped trust_class claim)', () => {
    const key = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    const { trustClass: _omitted, ...legacyBinding } = BINDING;
    expect(() => mintBrokerAssertion(CTX, legacyBinding, key, 1_000_000)).toThrow(/trustClass/);
  });

  it('accepts an injected jti for deterministic fixtures and defaults to 16 random bytes hex', () => {
    const key = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    const fixed = '9f8e7d6c5b4a39281706f5e4d3c2b1a0';
    const pinned = mintBrokerAssertion(CTX, BINDING, key, 1_000_000, fixed);
    expect(JSON.parse(Buffer.from(pinned.split('.')[1], 'base64url').toString('utf-8')).jti).toBe(fixed);

    const defaulted = mintBrokerAssertion(CTX, BINDING, key, 1_000_000);
    const jti = JSON.parse(Buffer.from(defaulted.split('.')[1], 'base64url').toString('utf-8')).jti;
    expect(jti).toMatch(/^[0-9a-f]{32}$/);
  });

  it('publishes a JWK with kid for the discovery document', () => {
    const key = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    const jwk = brokerPublicJwk(key);
    expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', kid: 'broker-key-1', alg: 'EdDSA' });
  });
});

describe('ExchangeProvider (RFC 8693)', () => {
  it('performs a token exchange and returns a scoped credential', async () => {
    const key = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    const transport = new FakeTransport();
    const provider = new ExchangeProvider({ tokenEndpoint: 'https://idp.example/token' }, key, transport);

    const cred = await provider.resolve(CTX, BINDING);

    expect(cred.token).toBe('scoped-downstream-token-xyz');
    expect(cred.tokenType).toBe('Bearer');
    expect(cred.expiresInSeconds).toBe(300);

    // The exchange used the correct RFC 8693 parameters and a JWT subject token.
    expect(transport.last?.params.grant_type).toBe(TOKEN_EXCHANGE_GRANT_TYPE);
    expect(transport.last?.params.subject_token_type).toBe(SUBJECT_TOKEN_TYPE_JWT);
    expect(transport.last?.params.scope).toBe('orders.read');
    expect(transport.last?.params.audience).toBe('https://api.orders.internal');
    expect(transport.last?.params.subject_token.split('.')).toHaveLength(3);
  });

  it('throws when the authorization server returns no access_token', async () => {
    const key = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    const transport: TokenExchangeTransport = {
      async exchange() {
        return { access_token: '' };
      },
    };
    const provider = new ExchangeProvider({ tokenEndpoint: 'https://idp.example/token' }, key, transport);
    await expect(provider.resolve(CTX, BINDING)).rejects.toThrow(/access_token/);
  });
});

describe('Okta adapter (vendor isolation, AAP Principle 4)', () => {
  it('builds an Exchange provider that resolves a scoped credential', async () => {
    const key = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    const transport = new FakeTransport('issued-scoped-token-abc');
    const provider = createOktaExchangeProvider({
      orgUrl: 'https://acme.okta.com',
      signingKey: key,
      transport,
    });
    const cred = await provider.resolve(CTX, BINDING);

    expect(cred.token).toBe('issued-scoped-token-abc');
    // The Okta token endpoint convention was used...
    expect(transport.last?.tokenEndpoint).toBe('https://acme.okta.com/oauth2/v1/token');
    // ...but the adapter injects no vendor name into the scoped credential the broker holds.
    expect(JSON.stringify(cred).toLowerCase()).not.toContain('okta');
  });

  it('supports a custom authorization server id', async () => {
    const key = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
    const transport = new FakeTransport();
    const provider = createOktaExchangeProvider({
      orgUrl: 'https://acme.okta.com',
      authorizationServerId: 'aus123',
      signingKey: key,
      transport,
    });
    await provider.resolve(CTX, BINDING);
    expect(transport.last?.tokenEndpoint).toBe('https://acme.okta.com/oauth2/aus123/v1/token');
  });
});
