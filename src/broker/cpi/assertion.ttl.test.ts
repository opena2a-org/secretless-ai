/**
 * The binding's TTL at the mint site.
 *
 * GrantPolicy refuses an out-of-range `resolve.ttlSeconds` when it loads, but the three mint
 * functions and ExchangeProvider are exported and take a ResourceBinding directly. A binding
 * built in code never passes the loader, and the assertion builder adds its TTL to the issue
 * time to form `exp`: an absent TTL or NaN serialises to `"exp": null`, a string concatenates
 * into a thirteen-digit `exp`, zero or a negative mints an assertion already expired at issue,
 * and a whole number above the ceiling reads downstream as no expiry at all.
 *
 * Each table below is asserted against the loader AND every mint path, so the two sites keep
 * one accept-set: a value added to one table has to hold at both.
 */

import { describe, expect, it } from 'vitest';
import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import {
  generateBrokerPqcSigningKey,
  generateBrokerSigningKey,
  mintBrokerAssertion,
  mintBrokerAssertionMlDsa65,
  mintHybridBrokerAssertion,
} from './assertion';
import { ExchangeProvider, type TokenExchangeTransport } from './exchange';
import { GrantPolicy, MAX_GRANT_TTL_SECONDS } from '../grant-policy';
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
  signedCapabilities: true,
};

const IAT = 1_000_000;
const ISSUER = 'https://broker.acme.example';
const ED_KEY = generateBrokerSigningKey(ISSUER, 'broker-key-1');
const PQC_KEY = generateBrokerPqcSigningKey(ISSUER, 'broker-pqc-1', new Uint8Array(32).fill(7));

const REFUSED: unknown[] = [
  undefined,
  null,
  NaN,
  '300',
  0,
  -60,
  1.5,
  Infinity,
  MAX_GRANT_TTL_SECONDS + 1,
  Number.MAX_SAFE_INTEGER,
  1e21,
];
const ACCEPTED: number[] = [1, 300, MAX_GRANT_TTL_SECONDS];

const label = (v: unknown): string => (typeof v === 'string' ? JSON.stringify(v) : String(v));

/** A resource binding as a library caller builds one in code, with the given TTL. */
function bindingWith(ttlSeconds: unknown): ResourceBinding {
  return {
    mode: 'exchange',
    providerId: 'orders-idp',
    scope: 'orders.read',
    audience: 'https://api.orders.internal',
    ttlSeconds,
    trustClass: 'orders:read',
  } as ResourceBinding;
}

/** The same resolve half, as the grant binding a policy file would carry. */
function policyBindingWith(ttlSeconds: unknown): Record<string, unknown> {
  const { trustClass, ...resolve } = bindingWith(ttlSeconds);
  return { grant: 'grant://orders-db', match: { trustClass, minTrustLevel: 3 }, resolve };
}

const claimsOf = (segment: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(segment, 'base64url').toString('utf-8'));

/** Each mint path, reduced to the `exp` claim it signs. */
const MINT_PATHS: Array<[string, (b: ResourceBinding) => unknown]> = [
  ['mintBrokerAssertion', (b) => claimsOf(mintBrokerAssertion(CTX, b, ED_KEY, IAT).split('.')[1]).exp],
  [
    'mintBrokerAssertionMlDsa65',
    (b) => claimsOf(mintBrokerAssertionMlDsa65(CTX, b, PQC_KEY, IAT).split('.')[1]).exp,
  ],
  [
    'mintHybridBrokerAssertion',
    (b) => claimsOf(mintHybridBrokerAssertion(CTX, b, ED_KEY, PQC_KEY, IAT).payload).exp,
  ],
];

describe('broker assertion: the binding TTL is bounded where exp is formed', () => {
  for (const bad of REFUSED) {
    it(`refuses ttlSeconds ${label(bad)} at policy load and on every mint path`, () => {
      expect(() => new GrantPolicy([policyBindingWith(bad)])).toThrow(/ttlSeconds/);
      for (const [name, exp] of MINT_PATHS) {
        expect(() => exp(bindingWith(bad)), name).toThrow(
          /binding\.ttlSeconds must be a whole number of seconds from 1 to 43200 \(12 hours\)/,
        );
      }
    });
  }

  for (const ttl of ACCEPTED) {
    it(`loads and mints ttlSeconds ${label(ttl)}, with exp exactly that far past iat`, () => {
      expect(new GrantPolicy([policyBindingWith(ttl)]).size).toBe(1);
      for (const [name, exp] of MINT_PATHS) {
        expect(exp(bindingWith(ttl)), name).toBe(IAT + ttl);
      }
    });
  }

  it('names the refused value in the error', () => {
    const mint = (ttl: unknown) => () => mintBrokerAssertion(CTX, bindingWith(ttl), ED_KEY, IAT);
    expect(mint(1e21)).toThrow(/not 1e\+21/);
    expect(mint(NaN)).toThrow(/not NaN/);
    expect(mint(undefined)).toThrow(/not undefined/);
    expect(mint('300')).toThrow(/not a string/);
  });

  // The value checked is the value used: one read, so a binding whose TTL reads differently the
  // second time cannot pass the check with one number and mint with another.
  it('reads ttlSeconds once, and mints what that read returned', () => {
    for (const [name, exp] of MINT_PATHS) {
      let reads = 0;
      const b = {
        ...bindingWith(300),
        get ttlSeconds() {
          reads += 1;
          return reads === 1 ? 300 : 1e21;
        },
      };
      expect(exp(b), name).toBe(IAT + 300);
      expect(reads, name).toBe(1);
    }
  });
});

describe('ExchangeProvider: a binding the mint refuses never reaches the authorization server', () => {
  for (const bad of REFUSED) {
    it(`sends no token-exchange request for ttlSeconds ${label(bad)}`, async () => {
      let requests = 0;
      const transport: TokenExchangeTransport = {
        async exchange() {
          requests += 1;
          return { access_token: 'not-a-real-token' };
        },
      };
      const provider = new ExchangeProvider({ tokenEndpoint: 'https://idp.example/token' }, ED_KEY, transport);
      await expect(provider.resolve(CTX, bindingWith(bad))).rejects.toThrow(/binding\.ttlSeconds/);
      expect(requests).toBe(0);
    });
  }
});

/**
 * The mint checks the TTL before the request goes out, and the reported life is formed after
 * the response comes back. The caller's binding object can change in between, so the TTL that
 * caps the reported life has to be the one the mint checked, not a second read of the object.
 */
describe('ExchangeProvider: the reported life is capped by the TTL the assertion was minted with', () => {
  const YEAR = 86400 * 365;

  /**
   * Resolves `b` while `during` runs inside the token exchange. Returns the life of the assertion
   * that was sent (`exp - iat`) and the life reported for the scoped credential.
   */
  async function resolveWith(
    b: ResourceBinding,
    expiresIn: number | undefined,
    during: () => void = () => {},
  ): Promise<{ minted: number; reported: unknown }> {
    let minted = NaN;
    const transport: TokenExchangeTransport = {
      async exchange(req) {
        const claims = claimsOf(req.params.subject_token.split('.')[1]);
        minted = (claims.exp as number) - (claims.iat as number);
        during();
        return { access_token: 'not-a-real-token', expires_in: expiresIn };
      },
    };
    const provider = new ExchangeProvider({ tokenEndpoint: 'https://idp.example/token' }, ED_KEY, transport);
    const cred = await provider.resolve(CTX, b);
    return { minted, reported: cred.expiresInSeconds };
  }

  for (const later of [...REFUSED, MAX_GRANT_TTL_SECONDS]) {
    it(`a 300s binding that becomes ${label(later)} during the exchange still reports at most 300s`, async () => {
      for (const [expiresIn, reported] of [[undefined, 300], [YEAR, 300], [120, 120]] as const) {
        const b = bindingWith(300);
        const change = () => {
          (b as unknown as Record<string, unknown>).ttlSeconds = later;
        };
        expect(await resolveWith(b, expiresIn, change), `expires_in ${expiresIn}`).toEqual({
          minted: 300,
          reported,
        });
      }
    });
  }

  it('reads ttlSeconds once, and reports the life that read minted', async () => {
    let reads = 0;
    const b = {
      ...bindingWith(300),
      get ttlSeconds() {
        reads += 1;
        return reads === 1 ? 300 : 1e21;
      },
    };
    expect(await resolveWith(b, undefined)).toEqual({ minted: 300, reported: 300 });
    expect(reads).toBe(1);
  });

  // The provider's copy reads members by name, not by spreading own properties, so a binding
  // that keeps them on its prototype resolves as it did before the copy existed.
  it('resolves a binding whose members live on its prototype', async () => {
    const b = Object.create(bindingWith(300)) as ResourceBinding;
    expect(await resolveWith(b, YEAR)).toEqual({ minted: 300, reported: 300 });
  });

  it('requests the scope and audience the assertion carries', async () => {
    const reads = { scope: 0, audience: 0 };
    const b = {
      ...bindingWith(300),
      get scope() {
        reads.scope += 1;
        return reads.scope === 1 ? 'orders.read' : 'orders.write';
      },
      get audience() {
        reads.audience += 1;
        return reads.audience === 1 ? 'https://api.orders.internal' : 'https://api.other.internal';
      },
    };
    let sent: Record<string, string> = {};
    const transport: TokenExchangeTransport = {
      async exchange(req) {
        sent = req.params;
        return { access_token: 'not-a-real-token' };
      },
    };
    const provider = new ExchangeProvider({ tokenEndpoint: 'https://idp.example/token' }, ED_KEY, transport);
    await provider.resolve(CTX, b);
    const claims = claimsOf(sent.subject_token.split('.')[1]);
    expect({ scope: sent.scope, audience: sent.audience }).toEqual({
      scope: claims.scope,
      audience: claims.aud,
    });
    expect(reads).toEqual({ scope: 1, audience: 1 });
  });
});
