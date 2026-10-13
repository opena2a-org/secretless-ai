/**
 * The life a scoped credential reports, at the grant resolver.
 *
 * A binding's TTL is the operator's ceiling on the credential's life. ExchangeProvider holds the
 * life it reports to that ceiling, but the provider registry takes any CredentialProvider, and
 * the resolver handed the worker whatever a provider reported: `1e21`, NaN and the string "300"
 * all reached the downstream caller under a 300 second binding.
 *
 * The STATED table is asserted against the resolver AND the exchange site, so the two sites that
 * report a life keep one rule: a row added to the table has to hold at both.
 */

import { describe, expect, it } from 'vitest';
import type {
  Atx,
  AtxVerifier,
  ResolutionContext,
} from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import type { AuditLogger } from './audit';
import { generateBrokerSigningKey } from './cpi/assertion';
import { ExchangeProvider, type TokenExchangeResponse } from './cpi/exchange';
import { MapProviderRegistry } from './cpi/registry';
import type { CpiMode, CredentialProvider, ScopedCredential } from './cpi/types';
import { GrantPolicy, MAX_GRANT_TTL_SECONDS } from './grant-policy';
import { GrantResolver, type GrantResolveOutcome } from './grant-resolver';
import { EphemeralWorker } from './worker';

const CTX: ResolutionContext = {
  agentId: 'aim_orders_reader',
  agentDid: 'did:opena2a:agent:acme/orders-reader',
  issuerDid: 'did:opena2a:authority:opena2a.org',
  issuerChain: ['did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
  trustScore: 0.95,
  capabilities: ['orders:read'],
  oasbLevel: 'L2',
  signedCapabilities: true,
};

/** The credential is verified elsewhere; these tests start from a verified context. */
const VERIFIER: AtxVerifier = { verify: () => ({ valid: true, context: CTX }) };

const ED_KEY = generateBrokerSigningKey('https://broker.acme.example', 'broker-key-1');
const TOKEN = 'not-a-real-token';
const YEAR = 86400 * 365;

/** [the life a provider states, the life handed on] under a 300 second binding. */
const STATED: Array<[unknown, number]> = [
  // A life inside the ceiling is handed on as stated.
  [120, 120],
  [300, 300],
  [0.5, 0.5],
  [0, 0],
  // A longer one does not raise the ceiling.
  [301, 300],
  [MAX_GRANT_TTL_SECONDS, 300],
  [YEAR, 300],
  [Number.MAX_SAFE_INTEGER, 300],
  [1e21, 300],
  [Infinity, 300],
  // A value that is not a number states no life, so the binding's TTL stands.
  [NaN, 300],
  [undefined, 300],
  [null, 300],
  ['300', 300],
  ['3600', 300],
  [true, 300],
  [{}, 300],
  // A negative one reads as already expired.
  [-5, 0],
  [-Infinity, 0],
];

function label(v: unknown): string {
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'object' && v !== null) return 'an object';
  return String(v);
}

/** A grant binding as policy carries it, resolved by the provider registered as "orders-idp". */
function bindingDoc(ttlSeconds: number, mode: CpiMode): Record<string, unknown> {
  return {
    grant: 'grant://orders-read',
    match: { trustClass: 'orders:read' },
    resolve: {
      mode,
      providerId: 'orders-idp',
      scope: 'orders.read',
      audience: 'https://api.orders.internal',
      ttlSeconds,
    },
  };
}

/** A provider that is not ExchangeProvider: it returns `cred` as its scoped credential. */
function providerReturning(cred: unknown): CredentialProvider {
  return {
    modes: ['assume'],
    resolve: async () => cred as ScopedCredential,
  };
}

/** An ExchangeProvider whose authorization server states `expiresIn`. */
function exchangeStating(expiresIn: unknown): ExchangeProvider {
  return new ExchangeProvider({ tokenEndpoint: 'https://idp.example/token' }, ED_KEY, {
    exchange: async () => ({ access_token: TOKEN, expires_in: expiresIn }) as TokenExchangeResponse,
  });
}

/**
 * Resolves grant://orders-read through a resolver whose one provider is `provider`. Returns the
 * outcome, every credential the downstream caller was handed, and every audit reason.
 */
async function resolveThrough(
  provider: CredentialProvider,
  ttlSeconds = 300,
): Promise<{ outcome: GrantResolveOutcome; handed: ScopedCredential[]; reasons: string[] }> {
  const handed: ScopedCredential[] = [];
  const reasons: string[] = [];
  const audit = {
    logEvent: (...event: unknown[]) => void reasons.push(String(event[5])),
  } as unknown as AuditLogger;
  const resolver = new GrantResolver({
    verifier: VERIFIER,
    policy: new GrantPolicy([bindingDoc(ttlSeconds, provider.modes[0])]),
    providers: new MapProviderRegistry().register('orders-idp', provider),
    worker: new EphemeralWorker({
      async call(_audience, _op, cred) {
        handed.push(cred);
        return { status: 200, body: { rows: [] } };
      },
    }),
    audit,
  });
  const outcome = await resolver.resolve({
    agentId: 'aim_orders_reader',
    atx: {} as Atx,
    grant: 'grant://orders-read',
    operation: { method: 'GET', path: '/orders' },
  });
  return { outcome, handed, reasons };
}

describe('GrantResolver: the life handed to the worker is held to the binding TTL', () => {
  for (const [stated, expected] of STATED) {
    it(`hands on ${expected}s when a provider under a 300s binding reports ${label(stated)}`, async () => {
      const { outcome, handed } = await resolveThrough(
        providerReturning({ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: stated }),
      );
      expect(outcome.ok).toBe(true);
      expect(handed).toEqual([{ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: expected }]);
    });
  }

  // The ceiling is the binding's own TTL, not a flat number.
  const ceilings: Array<[number, unknown, number]> = [
    [MAX_GRANT_TTL_SECONDS, 1e21, MAX_GRANT_TTL_SECONDS],
    [MAX_GRANT_TTL_SECONDS, 3600, 3600],
    [3600, MAX_GRANT_TTL_SECONDS, 3600],
    [1, 300, 1],
    [1, NaN, 1],
  ];
  for (const [ttlSeconds, stated, expected] of ceilings) {
    it(`hands on ${expected}s when a provider under a ${ttlSeconds}s binding reports ${label(stated)}`, async () => {
      const { handed } = await resolveThrough(
        providerReturning({ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: stated }),
        ttlSeconds,
      );
      expect(handed.map((c) => c.expiresInSeconds)).toEqual([expected]);
    });
  }

  it('reads the reported life once, and hands on what that read stated', async () => {
    let reads = 0;
    const cred = {
      token: TOKEN,
      tokenType: 'Bearer',
      get expiresInSeconds() {
        reads += 1;
        return reads === 1 ? 120 : 1e21;
      },
    };
    const { handed } = await resolveThrough(providerReturning(cred));
    // Read twice here: the caller holds a plain member, not the provider's accessor.
    expect([handed[0].expiresInSeconds, handed[0].expiresInSeconds]).toEqual([120, 120]);
    expect(reads).toBe(1);
  });

  it('leaves the object a provider returned as the provider returned it', async () => {
    const cred = Object.freeze({ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: 1e21 });
    const { outcome, handed } = await resolveThrough(providerReturning(cred));
    expect(outcome.ok).toBe(true);
    expect(handed[0].expiresInSeconds).toBe(300);
    expect(cred.expiresInSeconds).toBe(1e21);
  });

  // A provider and the caller it is paired with may agree on members ScopedCredential does not
  // name. Capping the life does not drop them.
  it('keeps the members a provider adds for its own caller', async () => {
    const { handed } = await resolveThrough(
      providerReturning({ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: YEAR, region: 'eu-west-1' }),
    );
    expect(handed).toEqual([
      { token: TOKEN, tokenType: 'Bearer', expiresInSeconds: 300, region: 'eu-west-1' },
    ]);
  });

  it('hands on the token of a credential whose members live on its prototype', async () => {
    const cred = Object.create({ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: YEAR });
    const { handed } = await resolveThrough(providerReturning(cred));
    expect(handed).toEqual([{ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: 300 }]);
  });

  for (const nothing of [undefined, null, TOKEN, 300]) {
    it(`denies, before the caller runs, when a provider returns ${label(nothing)} for a credential`, async () => {
      const { outcome, handed, reasons } = await resolveThrough(providerReturning(nothing));
      expect(outcome).toEqual({ ok: false, denial: { code: 'denied' } });
      expect(handed).toEqual([]);
      expect(reasons).toEqual(['provider "orders-idp" returned no credential']);
    });
  }
});

describe('The exchange site and the grant resolver report a life by one rule', () => {
  for (const [stated, expected] of STATED) {
    it(`ExchangeProvider reports ${expected}s under a 300s binding for expires_in ${label(stated)}`, async () => {
      const cred = await exchangeStating(stated).resolve(CTX, {
        mode: 'exchange',
        providerId: 'orders-idp',
        scope: 'orders.read',
        audience: 'https://api.orders.internal',
        ttlSeconds: 300,
        trustClass: 'orders:read',
      });
      expect(cred).toEqual({ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: expected });
    });

    it(`the resolver hands on ${expected}s from ExchangeProvider for expires_in ${label(stated)}`, async () => {
      const { outcome, handed } = await resolveThrough(exchangeStating(stated));
      expect(outcome.ok).toBe(true);
      expect(handed).toEqual([{ token: TOKEN, tokenType: 'Bearer', expiresInSeconds: expected }]);
    });
  }
});
