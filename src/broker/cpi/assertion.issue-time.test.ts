/**
 * The issue time at the mint site.
 *
 * `exp` is the issue time plus the binding's TTL. The TTL is bounded where it is added
 * (./assertion.ttl.test.ts); this file holds the other operand to an accept-set. Each mint
 * function takes the issue time as an argument, `nowSeconds`, so tests and fixture generation can
 * fix the clock. Unchecked, NaN or Infinity serialises to `"iat": null, "exp": null`, a string
 * concatenates with the TTL into a thirteen-digit `exp`, and a clock reading in milliseconds
 * (`Date.now()`) mints an `exp` more than fifty thousand years out.
 *
 * Every case is asserted on all three mint paths, which share one claim builder.
 */

import { describe, expect, it } from 'vitest';
import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import {
  MAX_ISSUE_TIME_SECONDS,
  generateBrokerPqcSigningKey,
  generateBrokerSigningKey,
  mintBrokerAssertion,
  mintBrokerAssertionMlDsa65,
  mintHybridBrokerAssertion,
} from './assertion';
import { ExchangeProvider, type TokenExchangeTransport } from './exchange';
import { MAX_GRANT_TTL_SECONDS, type ResourceBinding } from './types';

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

const TTL = 300;
const BINDING: ResourceBinding = {
  mode: 'exchange',
  providerId: 'orders-idp',
  scope: 'orders.read',
  audience: 'https://api.orders.internal',
  ttlSeconds: TTL,
  trustClass: 'orders:read',
};

const ISSUER = 'https://broker.acme.example';
const ED_KEY = generateBrokerSigningKey(ISSUER, 'broker-key-1');
const PQC_KEY = generateBrokerPqcSigningKey(ISSUER, 'broker-pqc-1', new Uint8Array(32).fill(7));

// 2026-06-01T12:00:00Z as a clock reads it in seconds, and as `Date.now()` reads it.
const SECONDS_CLOCK = 1_780_315_200;
const MILLISECONDS_CLOCK = 1_780_315_200_123;

const REFUSED: Array<[string, unknown]> = [
  ['NaN', NaN],
  ['null', null],
  ['Infinity', Infinity],
  ['-Infinity', -Infinity],
  ['the string "1780315200"', String(SECONDS_CLOCK)],
  ['a Date', new Date(SECONDS_CLOCK * 1000)],
  ['a bigint', BigInt(SECONDS_CLOCK)],
  ['a Date.now() reading in milliseconds', MILLISECONDS_CLOCK],
  ['one second past the ceiling', MAX_ISSUE_TIME_SECONDS + 1],
  ['Number.MAX_SAFE_INTEGER', Number.MAX_SAFE_INTEGER],
  ['1e21', 1e21],
  ['-1', -1],
  ['-60', -60],
];

const ACCEPTED: Array<[string, number]> = [
  ['0', 0],
  ['1000000', 1_000_000],
  ['a clock reading in seconds', SECONDS_CLOCK],
  ['a reading with a fraction of a second', SECONDS_CLOCK + 0.75],
  ['the ceiling', MAX_ISSUE_TIME_SECONDS],
];

const claimsOf = (segment: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(segment, 'base64url').toString('utf-8'));

/**
 * Each mint path, reduced to the claims it signs. `now` is passed through as given, so a path
 * called with no issue time runs on its default clock.
 */
const MINT_PATHS: Array<[string, (...now: unknown[]) => Record<string, unknown>]> = [
  [
    'mintBrokerAssertion',
    (...now) => claimsOf(mintBrokerAssertion(CTX, BINDING, ED_KEY, ...(now as [number])).split('.')[1]),
  ],
  [
    'mintBrokerAssertionMlDsa65',
    (...now) =>
      claimsOf(mintBrokerAssertionMlDsa65(CTX, BINDING, PQC_KEY, ...(now as [number])).split('.')[1]),
  ],
  [
    'mintHybridBrokerAssertion',
    (...now) =>
      claimsOf(mintHybridBrokerAssertion(CTX, BINDING, ED_KEY, PQC_KEY, ...(now as [number])).payload),
  ],
];

/** The message `fn` throws, or the empty string when it returns. */
function refusal(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    return (err as Error).message;
  }
  return '';
}

describe('broker assertion: the issue time is bounded where exp is formed', () => {
  it('sets the ceiling at the last second of year 9999', () => {
    expect(MAX_ISSUE_TIME_SECONDS).toBe(253_402_300_799);
    expect(new Date(MAX_ISSUE_TIME_SECONDS * 1000).toISOString()).toBe('9999-12-31T23:59:59.000Z');
  });

  for (const [what, bad] of REFUSED) {
    it(`refuses nowSeconds ${what} on every mint path`, () => {
      for (const [name, claims] of MINT_PATHS) {
        expect(() => claims(bad), name).toThrow(
          /nowSeconds must be a number of seconds since the epoch from 0 to 253402300799 \(9999-12-31T23:59:59Z\)/,
        );
      }
    });
  }

  for (const [what, now] of ACCEPTED) {
    it(`mints nowSeconds ${what} as iat, with exp the TTL past it`, () => {
      for (const [name, claims] of MINT_PATHS) {
        const { iat, exp } = claims(now);
        expect(iat, name).toBe(now);
        expect(exp, name).toBe(now + TTL);
      }
    });
  }

  // The property the two tables add up to: whatever the issue time, a mint path either refuses
  // or signs a numeric `exp` that lies after a numeric `iat` by no more than the TTL ceiling.
  it('signs no claim set whose exp is not a number within the TTL ceiling of a numeric iat', () => {
    for (const [what, now] of [...REFUSED, ...ACCEPTED]) {
      for (const [name, claims] of MINT_PATHS) {
        let signed: Record<string, unknown>;
        try {
          signed = claims(now);
        } catch {
          continue;
        }
        const { iat, exp } = signed;
        expect(typeof iat, `${name}, ${what}: iat`).toBe('number');
        expect(typeof exp, `${name}, ${what}: exp`).toBe('number');
        expect((exp as number) - (iat as number), `${name}, ${what}`).toBeGreaterThan(0);
        expect((exp as number) - (iat as number), `${name}, ${what}`).toBeLessThanOrEqual(
          MAX_GRANT_TTL_SECONDS,
        );
        expect(iat as number, `${name}, ${what}`).toBeLessThanOrEqual(MAX_ISSUE_TIME_SECONDS);
      }
    }
  });

  it('names the refused value in the error', () => {
    const mint = (now: unknown) => () => mintBrokerAssertion(CTX, BINDING, ED_KEY, now as number);
    expect(mint(NaN)).toThrow(/not NaN/);
    expect(mint(null)).toThrow(/not null/);
    expect(mint(-60)).toThrow(/not -60/);
    expect(mint(String(SECONDS_CLOCK))).toThrow(/not a string/);
    expect(mint(new Date(SECONDS_CLOCK * 1000))).toThrow(/not an object/);
    expect(mint(MILLISECONDS_CLOCK)).toThrow(/not 1780315200123/);
  });

  // A reading past the ceiling is most often a clock in the wrong unit, so the error says how to
  // pass seconds. A value that is not a clock reading at all gets no such advice.
  it('says how to pass seconds when the reading is past the ceiling, and only then', () => {
    const mint = (now: unknown) => () => mintBrokerAssertion(CTX, BINDING, ED_KEY, now as number);
    expect(refusal(mint(MILLISECONDS_CLOCK))).toMatch(/Math\.floor\(Date\.now\(\) \/ 1000\)/);
    expect(refusal(mint(Date.now()))).toMatch(/Math\.floor\(Date\.now\(\) \/ 1000\)/);
    for (const now of [NaN, null, -60, String(SECONDS_CLOCK)]) {
      const message = refusal(mint(now));
      expect(message).toMatch(/nowSeconds must be/);
      expect(message).not.toMatch(/Date\.now/);
    }
  });

  // A binding refused for its TTL is refused for its TTL, whatever the issue time holds: the new
  // check does not change which error a caller with two bad arguments reads first.
  it('still names the TTL first when both the TTL and the issue time are out of range', () => {
    const b = { ...BINDING, ttlSeconds: 1e21 };
    expect(() => mintBrokerAssertion(CTX, b, ED_KEY, NaN)).toThrow(/binding\.ttlSeconds/);
  });
});

describe('broker assertion: the default clock is a reading in whole seconds', () => {
  const inSeconds = (iat: unknown, before: number): void => {
    expect(Number.isInteger(iat)).toBe(true);
    expect(iat as number).toBeGreaterThanOrEqual(before);
    expect(iat as number).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
  };

  it('mints on every path when no issue time is passed, and when it is passed as undefined', () => {
    for (const [name, claims] of MINT_PATHS) {
      for (const args of [[], [undefined]]) {
        const before = Math.floor(Date.now() / 1000);
        const { iat, exp } = claims(...args);
        inSeconds(iat, before);
        expect(exp, name).toBe((iat as number) + TTL);
      }
    }
  });

  it('is the clock ExchangeProvider mints with', async () => {
    let sent: Record<string, unknown> = {};
    const transport: TokenExchangeTransport = {
      async exchange(req) {
        sent = claimsOf(req.params.subject_token.split('.')[1]);
        return { access_token: 'not-a-real-token' };
      },
    };
    const provider = new ExchangeProvider({ tokenEndpoint: 'https://idp.example/token' }, ED_KEY, transport);
    const before = Math.floor(Date.now() / 1000);
    await provider.resolve(CTX, BINDING);
    inSeconds(sent.iat, before);
    expect(sent.exp).toBe((sent.iat as number) + TTL);
  });
});
