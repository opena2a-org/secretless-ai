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

  for (const empty of ['', '   ', '>=', '>= ']) {
    it(`refuses the empty-ish floor ${JSON.stringify(empty)} rather than dropping the check`, () => {
      expect(() => new GrantPolicy([withMatch({ oasbLevel: empty })])).toThrow();
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

  for (const level of ['L4', 'L9', 'l3', 'L3 ', ' L3', 'none', 'HARDENED', '']) {
    it(`denies an agent presenting the unrankable level ${JSON.stringify(level)}`, () => {
      expect(l3().evaluate('orders-db', { ...CTX, oasbLevel: level }).allowed).toBe(false);
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
  for (const bad of [null, 'high', '3', -1, 1.5, [], {}, true]) {
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

  it('accepts a floor of 0 and omitting the predicate entirely', () => {
    expect(() => new GrantPolicy([withMatch({ minTrustLevel: 0 })])).not.toThrow();
    const b = binding();
    delete (b.match as Record<string, unknown>).minTrustLevel;
    expect(() => new GrantPolicy([b])).not.toThrow();
  });

  it('denies rather than throwing when the ATX trust level is not a number', () => {
    const p = new GrantPolicy([withMatch({ minTrustLevel: 3 })]);
    const r = p.evaluate('orders-db', { ...CTX, trustLevel: 'high' } as unknown as ResolutionContext);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/not a number/);
  });

  it('denies rather than throwing when the ATX carries no capability list', () => {
    const p = new GrantPolicy([BINDING]);
    const r = p.evaluate('orders-db', { ...CTX, capabilities: undefined } as unknown as ResolutionContext);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/no capability list/);
  });
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
