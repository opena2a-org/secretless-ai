import { describe, it, expect } from 'vitest';
import { GrantPolicy, type GrantBinding } from './grant-policy';
import type { ResolutionContext } from '@opena2a/atx-verify';

const CTX: ResolutionContext = {
  agentId: 'aim_orders_reader',
  agentDid: 'did:opena2a:agent:acme/orders-reader',
  issuerDid: 'did:opena2a:authority:opena2a.org',
  issuerChain: ['did:opena2a:authority:partner.example', 'did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
  trustScore: 0.95,
  capabilities: ['orders:read'],
  oasbLevel: 'L2',
  // v1.1: `capabilities` and `scanSummary` are inside the signature. Every test below that
  // expects a grant needs this, because a credential that does not carry these fields under
  // its signature is denied before any predicate is compared.
  signedCapabilities: true,
};

const BINDING: GrantBinding = {
  grant: 'grant://orders-db',
  match: {
    trustClass: 'orders:read',
    minTrustLevel: 3,
    oasbLevel: '>=L2',
    issuerChainIncludes: { partnersSet: 'trusted-partners' },
    jurisdiction: { in: ['us', 'eu'] },
  },
  resolve: {
    mode: 'exchange',
    providerId: 'orders-idp',
    scope: 'orders.read',
    audience: 'https://api.orders.internal',
    ttlSeconds: 300,
  },
};

/** A fresh, deeply independent copy, so a test that mutates one cannot leak into another. */
function binding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return JSON.parse(JSON.stringify({ ...BINDING, ...overrides }));
}

/** A binding whose `match` is BINDING's with the given patch applied. */
function withMatch(patch: Record<string, unknown>): Record<string, unknown> {
  const b = binding();
  b.match = { ...(b.match as object), ...patch };
  return b;
}

/** A binding whose `resolve` is BINDING's with the given patch applied. */
function withResolve(patch: Record<string, unknown>): Record<string, unknown> {
  const b = binding();
  b.resolve = { ...(b.resolve as object), ...patch };
  return b;
}

/** An agent presenting NO OASB level — the party an unenforced floor lets through. */
const NO_OASB = { ...CTX, oasbLevel: undefined } as ResolutionContext;

describe('GrantPolicy (decision/enforcement split, AAP §3/§7)', () => {
  it('grants when the ATX satisfies the enforced predicates', () => {
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', CTX);
    expect(r.allowed).toBe(true);
    expect(r.binding?.resolve.mode).toBe('exchange');
  });

  it('default-denies an unknown grant', () => {
    const r = new GrantPolicy([BINDING]).evaluate('payroll-db', CTX);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/default deny/);
  });

  it('denies when the ATX lacks the required trust class', () => {
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', { ...CTX, capabilities: ['weather:read'] });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/trust class/);
  });

  it('denies when below the minimum trust level', () => {
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', { ...CTX, trustLevel: 1 });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/trust level/);
  });

  it('denies when below the required OASB level', () => {
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', { ...CTX, oasbLevel: 'L1' });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/OASB/);
  });

  it('parses but does not enforce federation/jurisdiction predicates in v1', () => {
    // An out-of-jurisdiction agent (v3 concern) and a non-partner-only chain still pass v1,
    // because only trustClass/minTrustLevel/oasbLevel are enforced (AAP §7.1).
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', {
      ...CTX,
      jurisdiction: ['cn'],
      issuerChain: ['did:opena2a:authority:opena2a.org'],
    });
    expect(r.allowed).toBe(true);
  });

  it('is an empty default-deny policy when constructed with no bindings', () => {
    const p = new GrantPolicy();
    expect(p.size).toBe(0);
    expect(p.evaluate('orders-db', CTX).allowed).toBe(false);
  });
});

/**
 * The floor an operator writes.
 *
 * `parseOasbFloor` used to return rank 0 for a level this build cannot order, and nothing is
 * below 0 — so the STRICTEST floor an operator could write was the one that enforced nothing.
 * Each spelling below is asserted separately because they fail for different reasons: a level
 * outside the vocabulary, a case difference, a word from another vocabulary, an operator
 * comparison syntax we do not parse, and a template that produced an empty string.
 */
describe('GrantPolicy: a floor this build cannot rank is refused at load', () => {
  for (const spec of ['L4', 'L0', 'L9', 'none', 'high', 'hardened', 'l3', 'L2+', '> L2', '>=L4', '>= high']) {
    it(`refuses oasbLevel ${JSON.stringify(spec)}, naming it and the levels this build ranks`, () => {
      expect(() => new GrantPolicy([withMatch({ oasbLevel: spec })])).toThrow(/cannot rank/);
      expect(() => new GrantPolicy([withMatch({ oasbLevel: spec })])).toThrow(
        new RegExp(spec.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      );
      expect(() => new GrantPolicy([withMatch({ oasbLevel: spec })])).toThrow(/L1, L2, L3/);
    });
  }

  it('refuses an empty floor with the message written for it, not the unrankable one', () => {
    // A bare `.toThrow()` here cannot tell which guard fired. Weakening `isNonEmptyString` to a
    // plain `typeof === 'string'` still throws — from the unrankable branch — so the empty-floor
    // message that explains the actual mistake would never be seen and no test would notice.
    expect(() => new GrantPolicy([withMatch({ oasbLevel: '' })])).toThrow(/removes the check/);
  });

  for (const empty of ['   ', '>=', '>= ']) {
    it(`refuses the whitespace-only floor ${JSON.stringify(empty)} rather than dropping the check`, () => {
      // These are non-empty strings, so they reach the rankable check and fail there.
      expect(() => new GrantPolicy([withMatch({ oasbLevel: empty })])).toThrow(/cannot rank/);
    });
  }

  for (const bad of [null, 0, false, 2, [], {}]) {
    it(`refuses a non-string oasbLevel ${JSON.stringify(bad)}`, () => {
      expect(() => new GrantPolicy([withMatch({ oasbLevel: bad })])).toThrow(/oasbLevel/);
    });
  }

  it('suggests the correct casing for a case-only near miss', () => {
    expect(() => new GrantPolicy([withMatch({ oasbLevel: 'l3' })])).toThrow(/did you mean "L3"/);
  });

  it('does NOT suggest a WEAKER level for an out-of-vocabulary one', () => {
    // nearestMatch('L4', ['L1','L2','L3']) returns 'L1' on a Levenshtein tie broken by array
    // order. Suggesting it would talk an operator into the weakest floor in the vocabulary
    // while they believe they are fixing a typo.
    for (const spec of ['L4', 'L0', 'L9']) {
      let message = '';
      try {
        new GrantPolicy([withMatch({ oasbLevel: spec })]);
      } catch (e) {
        message = e instanceof Error ? e.message : String(e);
      }
      // Both halves matter. Without the first, this passes vacuously on a build that does not
      // refuse the level at all — there is no message, so there is no suggestion in it either.
      expect(message).toMatch(/cannot rank/);
      expect(message).not.toMatch(/did you mean/);
    }
  });

  // The absence direction: every level this build DOES rank still loads, and ranks in order.
  for (const spec of ['L1', 'L2', 'L3', '>=L1', '>=L2', '>=L3', '>= L2']) {
    it(`accepts the rankable floor ${JSON.stringify(spec)}`, () => {
      expect(() => new GrantPolicy([withMatch({ oasbLevel: spec })])).not.toThrow();
    });
  }

  it('orders the levels it ranks, so a higher floor denies what a lower one grants', () => {
    const l1 = new GrantPolicy([withMatch({ oasbLevel: '>=L1' })]);
    const l3 = new GrantPolicy([withMatch({ oasbLevel: '>=L3' })]);
    expect(l1.evaluate('orders-db', { ...CTX, oasbLevel: 'L2' }).allowed).toBe(true);
    expect(l3.evaluate('orders-db', { ...CTX, oasbLevel: 'L2' }).allowed).toBe(false);
  });
});

/**
 * The level an agent presents.
 *
 * This side cannot be refused at load — it arrives at request time inside the credential — so it
 * denies instead. It was NOT fail-closed before: `OASB_RANK` was an object literal, so a lookup
 * of a prototype key returned a function rather than undefined, `?? 0` never fired, and
 * `function < 3` is false, so the deny branch never ran.
 */
describe('GrantPolicy: a presented level this build cannot rank satisfies no floor', () => {
  const l3 = () => new GrantPolicy([withMatch({ oasbLevel: '>=L3' })]);

  for (const key of ['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf']) {
    it(`denies an agent presenting the prototype key ${JSON.stringify(key)}`, () => {
      const r = l3().evaluate('orders-db', { ...CTX, oasbLevel: key });
      expect(r.allowed).toBe(false);
    });
  }

  for (const level of ['L4', 'L9', 'l3', 'L3 ', ' L3', 'none', 'HARDENED']) {
    it(`denies an agent presenting the unrankable level ${JSON.stringify(level)}`, () => {
      expect(l3().evaluate('orders-db', { ...CTX, oasbLevel: level }).allowed).toBe(false);
    });
  }

  it('classifies an empty presented level as absent, not as unrankable', () => {
    // An empty string is what an unset template variable produces, so "you sent nothing" is the
    // more accurate record. Asserted because the two branches must not disagree about it, and a
    // verdict-only assertion cannot see which one ran.
    const r = l3().evaluate('orders-db', { ...CTX, oasbLevel: '' });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/absent/);
  });

  for (const weird of [{ toString: 1 }, { valueOf: 1, toString: 1 }, Object.create(null)]) {
    it('denies rather than throwing on a presented level that cannot be stringified', () => {
      // Reachable on a v1.1 credential whose signature still verifies: the TBS projects this
      // field through the verifier's asString, which maps every non-string to '', so a holder
      // substitutes an object post-signing without changing the signed bytes. `String()` on it
      // throws from inside the decision function, which empties the audit record's policyId and
      // lets an agent make its own denial unattributable to the binding it violated.
      const r = l3().evaluate('orders-db', { ...CTX, oasbLevel: weird } as unknown as ResolutionContext);
      expect(r.allowed).toBe(false);
      expect(r.reason).toMatch(/satisfies no floor/);
    });
  }

  // Controls, both directions, so the block above cannot pass by denying everything.
  it('grants an agent presenting exactly the required level', () => {
    expect(l3().evaluate('orders-db', { ...CTX, oasbLevel: 'L3' }).allowed).toBe(true);
  });

  it('denies an agent presenting a lower ranked level', () => {
    expect(l3().evaluate('orders-db', { ...CTX, oasbLevel: 'L1' }).allowed).toBe(false);
  });

  it('denies an agent presenting no level at all', () => {
    expect(l3().evaluate('orders-db', NO_OASB).allowed).toBe(false);
  });
});

/**
 * The audit record must not assert a comparison that did not run. The single reason string this
 * replaced reported an unrankable or absent level as "below required", which is a false
 * statement written into the record an incident would be reconstructed from.
 */
describe('GrantPolicy: the denial reason states what actually happened', () => {
  const l2 = () => new GrantPolicy([withMatch({ oasbLevel: '>=L2' })]);

  it('says the level is absent, not that it is below the floor', () => {
    const r = l2().evaluate('orders-db', NO_OASB);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/absent/);
    expect(r.reason).not.toMatch(/below/);
  });

  it('says an unrankable level satisfies no floor, not that it is below the floor', () => {
    const r = l2().evaluate('orders-db', { ...CTX, oasbLevel: 'L9' });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/not one of L1, L2, L3/);
    expect(r.reason).not.toMatch(/below/);
  });

  it('says below only when a comparison of two ranked levels actually ran', () => {
    const r = l2().evaluate('orders-db', { ...CTX, oasbLevel: 'L1' });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/L1 below required >=L2/);
  });
});

/**
 * `minTrustLevel` on the value axis. `4 < null`, `4 < NaN` and `4 < "high"` are all `false`, so a
 * floor written with any of them passes `!== undefined`, loads, and then denies nothing. JSON can
 * express `null` and `"high"`.
 */
describe('GrantPolicy: a minimum trust level the comparison cannot order is refused at load', () => {
  for (const bad of [null, 'high', '3', -1, Infinity, -Infinity, [], {}, true]) {
    it(`refuses minTrustLevel ${JSON.stringify(bad)}`, () => {
      expect(() => new GrantPolicy([withMatch({ minTrustLevel: bad })])).toThrow(/minTrustLevel/);
    });
  }

  it('refuses NaN, which JSON cannot carry but a programmatic caller can', () => {
    expect(() => new GrantPolicy([withMatch({ minTrustLevel: NaN })])).toThrow(/minTrustLevel/);
  });

  // Absence direction: a real floor still loads and still discriminates.
  it('accepts an integer floor and denies below it', () => {
    const p = new GrantPolicy([withMatch({ minTrustLevel: 3 })]);
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 3 }).allowed).toBe(true);
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 2 }).allowed).toBe(false);
  });

  it('accepts a fractional floor, which orders perfectly well', () => {
    // Deliberately NOT refused. The reason this check exists is that the comparison cannot
    // ORDER the value; 2.5 orders fine and worked as a floor before this change. Refusing it
    // would be a break with no security argument, justified by an error message that is untrue
    // of the value it rejects. `trustLevel` is declared `number`, not an integer.
    const p = new GrantPolicy([withMatch({ minTrustLevel: 2.5 })]);
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 3 }).allowed).toBe(true);
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 2 }).allowed).toBe(false);
  });

  it('accepts a floor of 0 and omitting the predicate entirely', () => {
    expect(() => new GrantPolicy([withMatch({ minTrustLevel: 0 })])).not.toThrow();
    const b = binding();
    delete (b.match as Record<string, unknown>).minTrustLevel;
    expect(() => new GrantPolicy([b])).not.toThrow();
  });

  for (const bad of ['high', NaN, Infinity, -Infinity, null, undefined, '4', [4]]) {
    it(`denies rather than throwing when the ATX trust level is ${String(bad)}`, () => {
      // NaN and Infinity are the sharp cases and `typeof` alone does not catch them: `4 < NaN`
      // is false, so a NaN trust level satisfies every floor. A string is caught by `typeof`,
      // so testing only that would leave `Number.isFinite` unpinned.
      const p = new GrantPolicy([withMatch({ minTrustLevel: 3 })]);
      const r = p.evaluate('orders-db', { ...CTX, trustLevel: bad } as unknown as ResolutionContext);
      expect(r.allowed).toBe(false);
      expect(r.reason).toMatch(/not a number/);
    });
  }

  it('grants on a fractional trust level, which is a number and does order', () => {
    const p = new GrantPolicy([withMatch({ minTrustLevel: 3 })]);
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 3.5 }).allowed).toBe(true);
  });

  for (const bad of [undefined, null, 'orders:read', { includes: () => true }, 42]) {
    it(`denies rather than throwing when capabilities is ${JSON.stringify(bad) ?? String(bad)}`, () => {
      // The string and the duck-typed object are why this is `Array.isArray` and not a
      // truthiness check: `'orders:read'.includes('orders:read')` is true, and an object with an
      // `includes` method answers whatever it likes. Testing only `undefined` would pass on any
      // weaker guard, which is the axis the guard exists for.
      const p = new GrantPolicy([BINDING]);
      const r = p.evaluate('orders-db', { ...CTX, capabilities: bad } as unknown as ResolutionContext);
      expect(r.allowed).toBe(false);
      expect(r.reason).toMatch(/no capability list/);
    });
  }
});

/**
 * The key axis. A misspelled predicate leaves the field undefined, so the branch that reads it
 * never runs and the binding loads as the WIDER rule the operator did not write — while `size`
 * still reports it loaded. `policy.ts` refuses this at four nesting levels for `PolicyRule`.
 */
describe('GrantPolicy: a field this build does not read is refused at load', () => {
  it('refuses an unknown key on the binding', () => {
    expect(() => new GrantPolicy([binding({ effect: 'deny' })])).toThrow(/unknown field "effect"/);
  });

  it('refuses a misspelled match container rather than loading an unconstrained binding', () => {
    const b = binding();
    (b as Record<string, unknown>).matches = b.match;
    delete (b as Record<string, unknown>).match;
    expect(() => new GrantPolicy([b])).toThrow(/unknown field "matches"/);
  });

  for (const typo of ['oasbLevl', 'minTrustLvl', 'trustclass', 'scopeCheck', 'jurisdictions']) {
    it(`refuses the match predicate ${JSON.stringify(typo)}`, () => {
      expect(() => new GrantPolicy([withMatch({ [typo]: 'anything' })])).toThrow(
        new RegExp(`unknown field "${typo}"`),
      );
    });
  }

  it('names the likely intended field without binding it', () => {
    let message = '';
    try {
      new GrantPolicy([withMatch({ oasbLevl: '>=L3' })]);
    } catch (e) {
      message = e instanceof Error ? e.message : String(e);
    }
    expect(message).toMatch(/did you mean "oasbLevel"/);
    // The suggestion is advice, not a rewrite: the binding did not load.
    expect(() => new GrantPolicy([withMatch({ oasbLevl: '>=L3' })])).toThrow();
  });

  it('refuses an unknown sub-key of a federation predicate', () => {
    expect(() =>
      new GrantPolicy([withMatch({ issuerChainIncludes: { partnersSet: 'p', partnerSet: 'q' } })]),
    ).toThrow(/unknown field "partnerSet"/);
  });

  it('refuses an unknown sub-key of the jurisdiction predicate', () => {
    // The sibling of the case above. Without this, `jurisdiction: { in: ['us'], residency: ['cn'] }`
    // loaded silently — asymmetric coverage of the exact guard class this change is about.
    expect(() =>
      new GrantPolicy([withMatch({ jurisdiction: { in: ['us'], residency: ['cn'] } })]),
    ).toThrow(/unknown field "residency"/);
  });

  for (const bad of [null, 'orders:read', 42, []]) {
    it(`refuses a match container that is ${JSON.stringify(bad)}, naming the binding`, () => {
      // Without the container type check these produce a raw TypeError with no binding label,
      // or the misleading `unknown field "0"` from iterating a string's indices. The constructor
      // is written for a config loader, so a JSON-expressible shape gets a real message.
      const b = binding();
      b.match = bad;
      expect(() => new GrantPolicy([b])).toThrow(/match must be an object/);
    });

    it(`refuses a resolve container that is ${JSON.stringify(bad)}, naming the binding`, () => {
      const b = binding();
      b.resolve = bad;
      expect(() => new GrantPolicy([b])).toThrow(/resolve must be an object/);
    });
  }

  it('shape-validates the federation predicates it parses but does not enforce', () => {
    expect(() => new GrantPolicy([withMatch({ issuerChainIncludes: { partnersSet: '' } })])).toThrow();
    expect(() => new GrantPolicy([withMatch({ issuerChainIncludes: 'trusted' })])).toThrow();
    expect(() => new GrantPolicy([withMatch({ jurisdiction: { in: [] } })])).toThrow();
    expect(() => new GrantPolicy([withMatch({ jurisdiction: { in: ['us', ''] } })])).toThrow();
    expect(() => new GrantPolicy([withMatch({ jurisdiction: ['us'] })])).toThrow();
    // Absence direction: the well-formed clauses in BINDING still load.
    expect(() => new GrantPolicy([BINDING])).not.toThrow();
  });

  it('requires a trust class, the one predicate with no default', () => {
    for (const bad of [undefined, '', null, 3]) {
      expect(() => new GrantPolicy([withMatch({ trustClass: bad })])).toThrow(/trustClass/);
    }
  });
});

/**
 * The resource half. A binding is one authorization unit: validating the predicate and not the
 * TTL moves the fail-open rather than closing it. An absent `ttlSeconds` reaches the assertion
 * builder as `nowSeconds + undefined` = NaN, which `JSON.stringify` emits as `"exp": null`.
 */
describe('GrantPolicy: the resource half is validated too', () => {
  for (const bad of [undefined, null, '300', 0, -1, 1.5, NaN, Infinity]) {
    it(`refuses ttlSeconds ${String(bad)}`, () => {
      const b = withResolve({ ttlSeconds: bad });
      if (bad === undefined) delete (b.resolve as Record<string, unknown>).ttlSeconds;
      expect(() => new GrantPolicy([b])).toThrow(/ttlSeconds/);
    });
  }

  it('refuses a CPI mode this build has no provider interface for', () => {
    expect(() => new GrantPolicy([withResolve({ mode: 'impersonate' })])).toThrow(/resolve.mode/);
    expect(() => new GrantPolicy([withResolve({ mode: 'exchang' })])).toThrow(/did you mean "exchange"/);
  });

  for (const key of ['providerId', 'scope', 'audience']) {
    it(`refuses an empty ${key}`, () => {
      expect(() => new GrantPolicy([withResolve({ [key]: '' })])).toThrow(new RegExp(key));
    });
  }

  it('refuses an authored resolve.trustClass, which the resolver overwrites', () => {
    expect(() => new GrantPolicy([withResolve({ trustClass: 'orders:write' })])).toThrow(/discarded/);
  });

  it('refuses an unknown resolve key', () => {
    expect(() => new GrantPolicy([withResolve({ region: 'eu' })])).toThrow(/unknown field "region"/);
  });
});

/** The binding key itself. A binding a request can never match is a policy that never applies. */
describe('GrantPolicy: the grant reference is validated at load', () => {
  for (const bad of ['orders-db', 'grant://', 'grant://orders/db', 'grant://host:8080', 'secret://a/b', '']) {
    it(`refuses the binding key ${JSON.stringify(bad)}`, () => {
      expect(() => new GrantPolicy([binding({ grant: bad })])).toThrow();
    });
  }

  it('refuses a second binding for a grant the first already names', () => {
    // `evaluate` resolves by `find`, so the first wins and a stricter replacement is dead policy.
    const loose = withMatch({ oasbLevel: '>=L1' });
    const strict = withMatch({ oasbLevel: '>=L3' });
    expect(() => new GrantPolicy([loose, strict])).toThrow(/duplicate binding/);
  });

  it('accepts distinct grants in one policy', () => {
    const other = binding({ grant: 'grant://payroll-db' });
    const p = new GrantPolicy([BINDING, other]);
    expect(p.size).toBe(2);
  });

  it('refuses a binding that is not an object', () => {
    for (const bad of [null, undefined, 'grant://orders-db', 42, []]) {
      expect(() => new GrantPolicy([bad])).toThrow();
    }
  });
});

/**
 * A loaded policy is the class's own object. The engine previously stored the caller's array
 * elements by reference, so an operator-side object mutated after load changed a live decision
 * with no call into this class.
 */
describe('GrantPolicy: a loaded binding cannot be altered from outside', () => {
  it('keeps denying after the caller deletes the floor from its own object', () => {
    const b = binding() as { match: Record<string, unknown> };
    const p = new GrantPolicy([b]);
    expect(p.evaluate('orders-db', NO_OASB).allowed).toBe(false);

    delete b.match.oasbLevel;
    delete b.match.minTrustLevel;

    expect(p.evaluate('orders-db', NO_OASB).allowed).toBe(false);
  });

  it('keeps denying after the caller lowers the trust floor on its own object', () => {
    const b = binding() as { match: Record<string, unknown> };
    const p = new GrantPolicy([b]);
    b.match.minTrustLevel = 0;
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 1 }).allowed).toBe(false);
  });

  // NOT asserted: that `evaluate()`'s returned `binding` is a copy. `private` is a compile-time
  // marker only, so an in-process caller already reaches `bindings` directly and a copy on the
  // way out buys no adversarial protection — the same measurement that put `PolicyEngine`'s
  // `getRules()` at P3 rather than in a fix. The IN direction above is the one that matters,
  // because before this change the caller kept the only reference and the class had none.
});

/**
 * The credential version gate.
 *
 * `trustClass` and `oasbLevel` read `capabilities` and `scanSummary.oasbLevel`. The ATX v1.0
 * signature covers neither, so a holder rewrites them after signing and the credential still
 * verifies — measured with a real Ed25519 key: `scanSummary.oasbLevel` L2 -> L3 admitted the
 * holder to a `>=L3` binding, and injecting a capability that was never issued admitted them
 * too, while the control of rewriting the signature-covered `trustLevel` correctly failed
 * verification. Comparing those predicates reports a decision the agent made as one the
 * operator made.
 */
describe('GrantPolicy: a credential that does not sign what we match on is denied', () => {
  const p = () => new GrantPolicy([BINDING]);

  it('denies a v1.0 credential that satisfies every predicate honestly', () => {
    // Not an unqualified agent: identical to CTX in every field the binding matches on.
    const r = p().evaluate('orders-db', { ...CTX, signedCapabilities: false });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/signature/);
  });

  it('denies the holder who raised their own OASB level', () => {
    // What the forgery buys on v1.0: the agent writes L3 into its own scan summary.
    const r = p().evaluate('orders-db', { ...CTX, oasbLevel: 'L3', signedCapabilities: false });
    expect(r.allowed).toBe(false);
  });

  it('denies the holder who granted themselves the trust class', () => {
    const r = p().evaluate('orders-db', {
      ...CTX,
      capabilities: ['orders:read', 'orders:write'],
      signedCapabilities: false,
    });
    expect(r.allowed).toBe(false);
  });

  it('treats an absent signedCapabilities as unsigned, not as signed', () => {
    // `AtxVerifier` is a published interface. A third-party implementation that predates the
    // field, or omits it, must not read as "these fields are covered".
    const { signedCapabilities: _drop, ...noFlag } = CTX as Record<string, unknown> & {
      signedCapabilities: boolean;
    };
    const r = p().evaluate('orders-db', noFlag as unknown as ResolutionContext);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/signature/);
  });

  for (const truthy of [1, 'true', {}, [] as unknown]) {
    it(`treats a non-boolean signedCapabilities ${JSON.stringify(truthy)} as unsigned`, () => {
      const r = p().evaluate('orders-db', {
        ...CTX,
        signedCapabilities: truthy,
      } as unknown as ResolutionContext);
      expect(r.allowed).toBe(false);
    });
  }

  it('reports the credential version, not a predicate read from a field it does not sign', () => {
    // Pins the ORDER, not just the outcome. With the gate after the trustClass comparison the
    // verdict is still deny, so an outcome-only assertion cannot see the difference — but the
    // audit record then says "ATX lacks trust class", a conclusion drawn from the very field
    // we have just established the holder controls. We do not know what capabilities this agent
    // has; we know we cannot tell.
    const r = p().evaluate('orders-db', {
      ...CTX,
      capabilities: ['weather:read'],
      signedCapabilities: false,
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/signature/);
    expect(r.reason).not.toMatch(/trust class/);
  });

  // Controls. Without these the block above passes on a build that denies everything.
  it('grants the same agent on a credential that does sign those fields', () => {
    expect(p().evaluate('orders-db', CTX).allowed).toBe(true);
  });

  it('still denies an unqualified agent on a signed credential, for the RIGHT reason', () => {
    const r = p().evaluate('orders-db', { ...CTX, capabilities: ['weather:read'] });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/trust class/);
    expect(r.reason).not.toMatch(/signature/);
  });
});

/**
 * Inputs that are not what they appear to be at the moment they are read.
 *
 * Each of these validated clean and then behaved differently, so `size` and the constructor's
 * own promise ("every binding is validated here") were false for them.
 */
describe('GrantPolicy: a binding is what it was when it was validated', () => {
  it('refuses a hole in a sparse array rather than skipping it', () => {
    // `Array.prototype.map` skips holes; `find` does not. So `new Array(3)` with one real
    // binding reported size 3, validated one, and threw on `undefined.grant` at the first
    // evaluation.
    const sparse = new Array(3);
    sparse[1] = BINDING;
    expect(() => new GrantPolicy(sparse)).toThrow(/must be an object/);
    expect(() => new GrantPolicy([, ] as unknown[])).toThrow(/must be an object/);
  });

  // Each of the three below asserts the field is read EXACTLY ONCE, and that the value loaded is
  // the one the first read returned. Counting the reads is the point: a threshold picked to be
  // "somewhere after validation" is a guess about the implementation's internals, and a guess
  // that lands too high makes the test pass against the very re-read it exists to catch. Three
  // such tests survived exactly that way before this was tightened.

  it('reads minTrustLevel once, and loads what that read returned', () => {
    // `4 < NaN` is false, so loading NaN on a later read would grant every trust level under a
    // floor the operator wrote as 9.
    let reads = 0;
    const match = {
      trustClass: 'orders:read',
      get minTrustLevel() {
        reads += 1;
        return reads > 1 ? NaN : 9;
      },
    };
    const p = new GrantPolicy([{ ...binding(), match }]);
    expect(reads).toBe(1);
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 0 }).allowed).toBe(false);
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 9 }).allowed).toBe(true);
  });

  it('reads oasbLevel once, and loads what that read returned', () => {
    let reads = 0;
    const match = {
      trustClass: 'orders:read',
      get oasbLevel() {
        reads += 1;
        return reads > 1 ? '>=L1' : '>=L3';
      },
    };
    const p = new GrantPolicy([{ ...binding(), match }]);
    expect(reads).toBe(1);
    expect(p.evaluate('orders-db', { ...CTX, oasbLevel: 'L1' }).allowed).toBe(false);
    expect(p.evaluate('orders-db', { ...CTX, oasbLevel: 'L3' }).allowed).toBe(true);
  });

  it('reads ttlSeconds once, and loads what that read returned', () => {
    let reads = 0;
    const resolve = {
      mode: 'exchange',
      providerId: 'orders-idp',
      scope: 'orders.read',
      audience: 'https://api.orders.internal',
      get ttlSeconds() {
        reads += 1;
        return reads > 1 ? 315360000 : 60; // ten years, vs one minute
      },
    };
    const p = new GrantPolicy([{ ...binding(), resolve }]);
    expect(reads).toBe(1);
    expect(p.evaluate('orders-db', CTX).binding?.resolve.ttlSeconds).toBe(60);
  });

  it('does not hand the caller a live handle through the evaluation result', () => {
    // The return path, which the in-direction reconstruction does not close. Measured before
    // freezing: take the binding off a DENIED evaluation, delete its floors, and the next
    // evaluation of the same low-trust agent was allowed.
    const p = new GrantPolicy([BINDING]);
    const denied = p.evaluate('orders-db', { ...CTX, trustLevel: 1 });
    expect(denied.allowed).toBe(false);

    const handle = denied.binding as GrantBinding;
    expect(() => {
      delete (handle.match as Record<string, unknown>).minTrustLevel;
    }).toThrow(TypeError); // frozen: strict mode, and test files are modules
    expect(p.evaluate('orders-db', { ...CTX, trustLevel: 1 }).allowed).toBe(false);
  });
});
