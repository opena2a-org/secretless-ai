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
