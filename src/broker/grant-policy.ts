/**
 * Grant policy — the *resource grant* half of the decision/enforcement split (AAP §3, §7).
 *
 * Maps a grant name to a concrete resource binding (CPI mode, provider, scope, audience,
 * TTL) and the match predicates an agent's verified ATX must satisfy. This is local,
 * operator-owned configuration; it never travels with the agent.
 *
 * The grammar is federation-aware from v1 so federation lights up later with no grammar
 * change (AAP §7.1). A v1 broker MUST parse the full clause — including the federation-only
 * predicates `issuerChainIncludes` and `jurisdiction` — and MAY treat those as satisfied
 * within its own org, while still enforcing `trustClass`, `oasbLevel`, mode, scope, and ttl
 * (AAP-BROKER-PROFILE §7.1). `minTrustLevel` is enforced here as well; it is this build's
 * addition, not a line of that list. Default-deny: no matching binding ⇒ denied (AAP §3.4).
 *
 * WHAT THE PREDICATES BIND, AND AGAINST WHOM. Two of the three — `trustClass` (read from
 * `ctx.capabilities`) and `oasbLevel` (read from `ctx.scanSummary.oasbLevel`) — sit outside
 * the ATX signature on credential version 1.0. Measured with a real key: a holder rewrites
 * `scanSummary.oasbLevel` from L2 to L3 after signing, the credential still verifies, and a
 * `>=L3` binding admitted it; injecting a capability that was never issued admitted it too;
 * the control, rewriting the signature-covered `trustLevel`, correctly failed verification.
 * So on v1.0 the agent, not the operator, decides two of the three predicates.
 *
 * `@opena2a/atx-verify` publishes `ResolutionContext.signedCapabilities` for exactly this
 * decision, and `evaluate()` requires it. A credential that does not carry these fields under
 * its signature is denied rather than compared against predicates its holder chose.
 */

import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import type { CpiMode, ResourceBinding } from './cpi/types';
import { isGrantRef } from '../grant';
import { nearestMatch } from '../near-miss';

export interface GrantMatch {
  /**
   * Trust class (capability) the ATX must carry, e.g. "orders:read".
   *
   * Read from `capabilities`, which the ATX v1.0 signature does not cover, so a credential
   * whose `signedCapabilities` is not true is denied before this predicate is compared. See
   * the file header.
   */
  trustClass: string;
  /**
   * Minimum ATX trust level, as a whole number.
   *
   * `trustLevel` is inside the signature on both credential versions, but only its INTEGER part
   * is: both canonical payloads project it through `Math.trunc` while the resolution context
   * carries the raw value, so a holder can edit a signed `3` to `3.999999` and it still verifies.
   * A whole-number floor is immune — truncation preserves the integer part, so the most a holder
   * can add is just under 1.0, which cannot cross it. A fractional floor is NOT immune, and that
   * is the second reason one is refused at load.
   */
  minTrustLevel?: number;
  /**
   * Minimum OASB level from the ATX scan summary, e.g. ">=L2".
   *
   * Read from `scanSummary.oasbLevel`, which the ATX v1.0 signature does not cover, so a
   * credential whose `signedCapabilities` is not true is denied before this predicate is
   * compared. A floor this build cannot rank is refused at load rather than loading as none.
   */
  oasbLevel?: string;
  /** Federation: issuer chain must include a node in this partner set. v1: parsed, in-org satisfied. */
  issuerChainIncludes?: { partnersSet: string };
  /** Jurisdiction constraint. v1: parsed, NOT enforced (AAP §9 — v3 concern). */
  jurisdiction?: { in: string[] };
}

export interface GrantBinding {
  /** The grant reference this clause governs, e.g. "grant://orders-db". */
  grant: string;
  match: GrantMatch;
  resolve: ResourceBinding;
}

export interface GrantEvaluation {
  allowed: boolean;
  binding?: GrantBinding;
  /** Reason for the decision. Logged to audit; NEVER returned to the agent (AAP §6.6). */
  reason: string;
}

/**
 * The OASB levels this build can ORDER, and therefore the only ones it can treat as a floor.
 *
 * A `Map`, not an object literal, and the difference is not stylistic. `OASB_RANK` is indexed
 * by a string that arrives on the wire inside the agent's own credential. As an object literal,
 * `OASB_RANK["constructor"]` resolved up the prototype chain to `Object.prototype.constructor`
 * — a function, so neither `null` nor `undefined`, so the `?? 0` that was meant to catch an
 * unknown level never fired, and `function < 3` is `false`, so the deny branch never ran.
 * Measured against a `>=L3` floor: `constructor`, `__proto__`, `toString` and `valueOf` were all
 * ALLOWED while `L1` and an absent level were correctly denied. A `Map` has no prototype keys,
 * so `.get()` returns `undefined` for every string that is not a level.
 *
 * The vocabulary is L1-L3, matching AAP-BROKER-PROFILE.md's own glossary ("OASB, Open Agent
 * Security Benchmark (levels L1-L3)"). That reference is informative, not normative, and it is
 * the only OASB definition anywhere in the AAP tree. The ATX WIRE schema is wider
 * (`^L[0-9]$`) and deliberately does not govern here: what an operator may write as a floor and
 * what an agent may present are different populations, and binding the policy vocabulary to
 * what can arrive is the category error. A level outside this set is unrankable, and unrankable
 * is refused on the policy side and denied on the wire side — never silently treated as zero.
 */
const OASB_RANK: ReadonlyMap<string, number> = new Map([
  ['L1', 1],
  ['L2', 2],
  ['L3', 3],
]);

/** The three keys a grant binding may carry, mirroring `GrantBinding`. */
const KNOWN_BINDING_KEYS = new Set(['grant', 'match', 'resolve']);

/**
 * The five predicates a `match` clause may carry, mirroring `GrantMatch`.
 *
 * A clause carrying anything else is REFUSED, not ignored. This is the same decision
 * `policy.ts` makes for `PolicyRule` at four nesting levels, and it is here for the same
 * measured reason: a misspelled predicate (`oasbLevl`, `minTrustLvl`) leaves the field
 * `undefined`, so the enforcement branch that reads it never runs, and the binding loads as
 * the WIDER rule the operator did not write — while `size` still counts it loaded.
 */
const KNOWN_MATCH_KEYS = new Set([
  'trustClass',
  'minTrustLevel',
  'oasbLevel',
  'issuerChainIncludes',
  'jurisdiction',
]);

/** The five keys an operator may author on a `resolve` clause. See `OVERWRITTEN_RESOLVE_KEYS`. */
const KNOWN_RESOLVE_KEYS = new Set(['mode', 'providerId', 'scope', 'audience', 'ttlSeconds']);

/**
 * Keys `ResourceBinding` declares but an operator must not author, with the reason.
 *
 * `resolve.trustClass` is injected by the resolver from the matched clause
 * (`grant-resolver.ts` spreads `{ ...binding.resolve, trustClass: binding.match.trustClass }`),
 * so a value written here is silently discarded — the `scopeCheck` shape, where a field the
 * operator wrote had no effect while every surface reported the binding loaded.
 */
const OVERWRITTEN_RESOLVE_KEYS = new Map<string, string>([
  [
    'trustClass',
    'resolve.trustClass is set by the broker from the matched clause\'s match.trustClass, so a ' +
    'value written here is discarded. Remove it; the trust class the assertion carries is the ' +
    'one in match.trustClass.',
  ],
]);

/** The three CPI modes, mirroring `CpiMode` in ./cpi/types. */
const CPI_MODES = new Set<string>(['retrieve', 'assume', 'exchange']);

export class GrantPolicy {
  private readonly bindings: readonly GrantBinding[];

  /**
   * Load grant bindings. Every binding is validated here and REFUSED if this build cannot
   * apply it exactly as written.
   *
   * The constructor is the only write path to `this.bindings` and must stay the only one.
   * When a grant-binding file loader lands, it parses the file and calls this constructor; it
   * does not get its own accept-set. Two load paths that decide the same requests with two
   * accept-sets is not a defect to fix once, it is a defect generator — every constraint added
   * to one of them later applies to one caller and not the other.
   *
   * Each binding is RECONSTRUCTED rather than stored by reference, so a caller that mutates its
   * own object after this returns cannot alter a loaded policy from outside the class.
   */
  constructor(bindings: readonly unknown[] = []) {
    const seen = new Set<string>();
    // Spread first. `Array.prototype.map` SKIPS holes in a sparse array while `find` does not,
    // so `new Array(3)` — or a trailing elision — produced a policy whose `size` counted three
    // bindings that were never validated, and whose first evaluation threw on `undefined.grant`.
    // Spreading materialises each hole as `undefined`, which the check below already refuses.
    // The ARRAY is frozen, not just its elements. Freezing only the elements left `push` open,
    // and an appended binding never passes `validateGrantBinding` — so an unrankable floor could
    // reach `evaluate()`, where `parseOasbFloor` returns undefined and `1 < undefined` is false:
    // the exact fail-open this class exists to close, re-entered through the back of the array.
    this.bindings = Object.freeze([...bindings].map((b) => validateGrantBinding(b, seen)));
  }

  get size(): number {
    return this.bindings.length;
  }

  /**
   * Evaluate a grant name against the policy and a verified-ATX context. Default-deny.
   * `grantName` is the logical name (without the `grant://` scheme).
   */
  evaluate(grantName: string, ctx: ResolutionContext): GrantEvaluation {
    // Interpolating a non-string calls its `toString`, which a hostile object can make throw —
    // from inside the decision function, so a caller's catch decides the outcome. The in-tree
    // caller always passes a parsed string; a library consumer need not.
    if (typeof grantName !== 'string') {
      return { allowed: false, reason: 'grant name is not a string (default deny)' };
    }
    const target = `grant://${grantName}`;
    const binding = this.bindings.find((b) => b.grant === target);
    if (!binding) {
      return { allowed: false, reason: `No binding for ${target} (default deny)` };
    }
    const m = binding.match;

    // The credential's own version decides whether the predicates below mean anything.
    //
    // `trustClass` and `oasbLevel` read `capabilities` and `scanSummary.oasbLevel`, and the
    // v1.0 signature covers neither, so on a v1.0 credential the holder supplies the answers
    // to the questions this policy asks. Comparing them would report a decision the agent made
    // as one the operator made. `!== true` rather than `=== false`: a custom `AtxVerifier` — a
    // published interface anyone may implement — that omits the field must not read as signed.
    if (ctx.signedCapabilities !== true) {
      return {
        allowed: false,
        binding,
        reason:
          'ATX does not cover capabilities or scan summary under its signature (credential ' +
          'version 1.0), so the predicates this binding matches on are set by the holder',
      };
    }

    // Enforced predicates (v1).
    //
    // The context is derived from the agent's credential, so each field is checked for the
    // SHAPE the comparison needs before the comparison runs. A context that cannot be compared
    // denies: the alternative is a raw TypeError thrown from inside the decision function, or a
    // comparison against a non-number that is silently `false` and therefore never denies.
    if (!Array.isArray(ctx.capabilities)) {
      return { allowed: false, binding, reason: 'ATX carries no capability list' };
    }
    // Read by INDEX. `Array.isArray` is true for an Array subclass and for a Proxy over an array,
    // and both can override `includes` — but a `for…of` is no better, because it consults
    // `Symbol.iterator`, which is just as overridable. Measured: a subclass whose iterator yields
    // a class it does not contain is granted by a `for…of` and denied by `includes`, and a Proxy
    // trapping `includes` is the mirror image. Swapping one for the other moves the hole; an
    // index read is redirected by neither.
    //
    // It is NOT a defence against a Proxy that traps every property read: such an object can lie
    // about `length` and about each element, and nothing this function does while reading it in
    // place can prevent that. A caller who supplies a hostile `AtxVerifier` already decides the
    // verdict, so that is the boundary, not a gap. What this closes is the ordinary object that
    // merely overrides a method.
    let hasTrustClass = false;
    const capCount = ctx.capabilities.length;
    for (let i = 0; i < capCount; i += 1) {
      // No `typeof` guard: `m.trustClass` is a validated non-empty string and `===` is strict,
      // so a non-string member can never match it. A guard whose removal no test can detect is
      // not a defence — it is dead code that reads as one.
      if (ctx.capabilities[i] === m.trustClass) { hasTrustClass = true; break; }
    }
    if (!hasTrustClass) {
      return { allowed: false, binding, reason: `ATX lacks trust class "${m.trustClass}"` };
    }
    if (m.minTrustLevel !== undefined) {
      if (typeof ctx.trustLevel !== 'number' || !Number.isFinite(ctx.trustLevel)) {
        return {
          allowed: false,
          binding,
          reason: `ATX trust level is not a number, so it satisfies no minimum (required ${m.minTrustLevel})`,
        };
      }
      if (ctx.trustLevel < m.minTrustLevel) {
        return {
          allowed: false,
          binding,
          reason: `trust level ${ctx.trustLevel} below minimum ${m.minTrustLevel}`,
        };
      }
    }
    if (m.oasbLevel !== undefined) {
      // Recomputed rather than cached so there is one definition of what a floor means.
      // Non-null asserted rather than branched: the constructor refuses an unrankable floor, and
      // it is the only writer to `this.bindings`, so there is no input that reaches this line
      // with an unrankable `m.oasbLevel`. A defensive branch here would be code no test can
      // reach, which reads as covered while proving nothing.
      const required = parseOasbFloor(m.oasbLevel) as number;
      const have = typeof ctx.oasbLevel === 'string' ? OASB_RANK.get(ctx.oasbLevel) : undefined;
      // Three distinct reasons, because the single reason this replaced asserted a comparison
      // that had not run: an unrankable level was reported as "below required", which is a
      // false statement written into an audit record.
      // An empty string is ABSENT, not unrankable: it is what an unset template variable
      // produces, and "you sent nothing" is the more accurate record than "you sent something I
      // cannot rank". Kept as one predicate so the two branches cannot disagree about it.
      if (ctx.oasbLevel === undefined || ctx.oasbLevel === null || ctx.oasbLevel === '') {
        return {
          allowed: false,
          binding,
          reason: `OASB level absent; binding requires ${m.oasbLevel}`,
        };
      }
      if (have === undefined) {
        return {
          allowed: false,
          binding,
          reason:
            // `describe`, never `String()`. This branch is reached precisely when the value is
            // NOT a string, and `String({ toString: 1 })` throws `TypeError: Cannot convert
            // object to primitive value` — from inside the decision function, which is what the
            // comment above says this code exists to avoid. It is reachable on a v1.1 credential
            // whose signature still verifies: the TBS projects `scanSummary.oasbLevel` through
            // the verifier's `asString`, which maps every non-string to the empty string, so a
            // holder can substitute an object post-signing without changing the signed bytes.
            // The throw cost us the audit record — `policyId` emptied and the reason became
            // "resolution error", so an agent could make its own denial unattributable to the
            // binding it violated.
            `OASB level ${describe(ctx.oasbLevel)} is not one of ${rankableLevels()}, so it ` +
            `satisfies no floor; binding requires ${m.oasbLevel}`,
        };
      }
      if (have < required) {
        return {
          allowed: false,
          binding,
          reason: `OASB level ${ctx.oasbLevel} below required ${m.oasbLevel}`,
        };
      }
    }

    // Parsed-but-not-enforced-in-v1 predicates. The SHAPE of each is validated at load, so a
    // malformed clause is refused there rather than discovered at request time; evaluation is
    // deferred to v2 (federation) / v3 (jurisdiction).
    // m.issuerChainIncludes — federation (AAP §7): treated as satisfied within a single org.
    // m.jurisdiction        — residency  (AAP §9): parsed, not enforced.

    return { allowed: true, binding, reason: `Granted by binding for ${target}` };
  }
}

/** The levels this build can order, for an error or audit string. */
function rankableLevels(): string {
  return [...OASB_RANK.keys()].join(', ');
}

/**
 * Parse an OASB floor like ">=L2" or "L2" to a numeric rank.
 *
 * Returns `undefined` for a level this build cannot order. It previously returned 0 for that
 * case, which made the STRICTEST floor an operator could write the one that enforced nothing:
 * nothing is below 0, so `oasbLevel: "L4"` — or `"l3"`, or `"high"` — granted an agent
 * presenting no OASB level at all.
 */
function parseOasbFloor(spec: string): number | undefined {
  const level = spec.replace(/^>=\s*/, '').trim();
  return OASB_RANK.get(level);
}

/** A non-empty string, the shape almost every field here needs. */
function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v !== '';
}

/**
 * Suggest a correction for an unrankable OASB level, and ONLY when it is a pure case difference.
 *
 * Deliberately NOT `nearestMatch`. Measured against the rankable set, `nearestMatch` returns
 * "L1" for "L4", "L0" and "L9" — a Levenshtein tie broken by array order. Telling an operator
 * who wrote "L4" that they may have meant "L1" talks them into the WEAKEST floor in the
 * vocabulary while they believe they are fixing a typo. A case difference is the only near miss
 * where the intended level is unambiguous.
 */
function caseOnlyMatch(level: string): string | undefined {
  for (const known of OASB_RANK.keys()) {
    if (known.toLowerCase() === level.toLowerCase()) return known;
  }
  return undefined;
}

/** Refuse an object carrying a key this build does not read. */
function checkKeys(
  what: string,
  value: Record<string, unknown>,
  known: Set<string>,
  overwritten?: Map<string, string>,
): void {
  for (const key of Object.keys(value)) {
    const reason = overwritten?.get(key);
    if (reason) {
      throw new Error(`${what}: ${reason}`);
    }
    if (known.has(key)) continue;
    const near = nearestMatch(key, [...known]);
    throw new Error(
      `${what}: unknown field "${key}"${near ? ` (did you mean "${near}"?)` : ''}. ` +
      `It may carry: ${[...known].join(', ')}. ` +
      `A field this build does not read is refused rather than ignored, because ignoring ` +
      `"${key}" would drop whatever it was meant to restrict and load the binding as written ` +
      `without it.`,
    );
  }
}

/**
 * Validate one grant binding, or throw naming what is wrong and why refusing beats ignoring.
 *
 * Module-private on purpose. Exporting it — or the `KNOWN_*` sets — would create a second
 * accept-set reachable from outside the module, which is the shape that has already re-opened
 * closed defects in this package.
 *
 * `seen` carries the grant references already loaded in this call, so a duplicate is refused.
 * `evaluate()` resolves a grant by `find`, so the FIRST binding for a name wins and every later
 * one is silently dead — including a stricter one written to replace it.
 */
function validateGrantBinding(raw: unknown, seen: Set<string>): GrantBinding {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Grant binding must be an object');
  }
  const b = raw as Record<string, unknown>;

  // Read once. Six reads of `b.grant` meant the reference `isGrantRef` approved, the key `seen`
  // recorded, and the key finally stored could all be different values when the source defines an
  // accessor — defeating BOTH the grant-reference check and the duplicate check.
  const grant = b.grant;
  if (!isNonEmptyString(grant)) {
    throw new Error('Grant binding must have a non-empty "grant" string, e.g. "grant://orders-db"');
  }
  const label = `Grant binding "${grant}"`;

  if (!isGrantRef(grant)) {
    throw new Error(
      `${label}: not a grant reference. A binding is keyed by "grant://name", where name uses ` +
      `RFC 3986 unreserved characters only and never carries a backend, host, path, or port. ` +
      `A binding whose key is not a grant reference can never be matched by a request.`,
    );
  }
  if (seen.has(grant)) {
    throw new Error(
      `${label}: duplicate binding. A grant resolves to the FIRST binding that names it, so a ` +
      `second one never applies — including a stricter one written to replace it. Keep one ` +
      `binding per grant.`,
    );
  }
  seen.add(grant);

  checkKeys(label, b, KNOWN_BINDING_KEYS);

  if (!b.match || typeof b.match !== 'object' || Array.isArray(b.match)) {
    throw new Error(`${label}: match must be an object naming the predicates the ATX must satisfy`);
  }
  if (!b.resolve || typeof b.resolve !== 'object' || Array.isArray(b.resolve)) {
    throw new Error(`${label}: resolve must be an object naming the resource this grant maps to`);
  }

  const match = validateGrantMatch(label, b.match as Record<string, unknown>);
  const resolve = validateResourceBinding(label, b.resolve as Record<string, unknown>);

  // Reconstructed, not spread: a shallow copy would leave `match` and `resolve` as the caller's
  // own objects, so deleting a predicate from one after loading would widen a live policy with
  // no call into this class.
  //
  // Frozen because `evaluate()` returns the matched binding, and that is the same object the
  // class decides on. Measured before freezing: a caller took the `binding` off a DENIED
  // evaluation, deleted `match.oasbLevel` and `match.minTrustLevel` from it, and the next
  // evaluation of the same low-trust agent returned allowed. `private` is a compile-time marker
  // and buys nothing against a determined in-process caller, so this is a footgun guard rather
  // than a security boundary — but the footgun is on the return value of a published method,
  // costs one call to remove, and `GrantEvaluation.binding` gives a consumer no hint it is live.
  return Object.freeze({ grant, match: Object.freeze(match), resolve: Object.freeze(resolve) });
}

function validateGrantMatch(label: string, m: Record<string, unknown>): GrantMatch {
  checkKeys(`${label}: match`, m, KNOWN_MATCH_KEYS);

  // Read once, like every other field below. Validating `m.trustClass` and then reading it AGAIN
  // to store it let an accessor load a different class than the one that passed — and this one
  // also travels: `grant-resolver.ts` copies it into the broker assertion's `trust_class` claim,
  // so the minted credential would carry a class the operator never wrote.
  const trustClass = m.trustClass;
  if (!isNonEmptyString(trustClass)) {
    throw new Error(
      `${label}: match.trustClass must be a non-empty string, e.g. "orders:read". It is the ` +
      `capability the ATX must carry, and it is also the trust class the broker assertion claims.`,
    );
  }

  const out: GrantMatch = { trustClass };

  // Read ONCE into a local, then validate and store THAT. Reading `m.minTrustLevel` again to
  // store it would validate one value and load another whenever the source object defines an
  // accessor rather than a data property: measured, a getter returning 9 four times and then
  // `NaN` passed validation and loaded `NaN`, which orders below nothing and grants every trust
  // level. Not reachable from JSON, but the constructor is written for a config loader that does
  // not exist yet, and "the field is read twice" is not a property a future caller can see.
  const minTrustLevel = m.minTrustLevel;
  if (minTrustLevel !== undefined) {
    // Two distinct failures, refused together. `null`, `NaN` and any non-numeric string pass
    // `!== undefined` and then make the comparison in `evaluate()` unconditionally false —
    // `4 < null`, `4 < NaN` and `4 < "high"` are all `false` — so the floor loads and denies
    // nothing. JSON can express `null` and `"high"`. A negative floor orders correctly but sits
    // below every trust level a verifier emits, so it is a floor that admits everyone.
    if (typeof minTrustLevel !== 'number' || !Number.isInteger(minTrustLevel) || minTrustLevel < 0) {
      throw new Error(
        `${label}: match.minTrustLevel must be a whole number of zero or more, not ` +
        `${describe(minTrustLevel)}. A value the comparison cannot order is not a low minimum — ` +
        `it is no minimum, and the binding would grant every trust level. A FRACTIONAL floor is ` +
        `refused for a second reason: only the integer part of trustLevel is inside the ATX ` +
        `signature, so a holder can raise a signed 3 to 3.999999 and still verify.`,
      );
    }
    out.minTrustLevel = minTrustLevel;
  }

  const oasbLevel = m.oasbLevel; // Read once. See the note on minTrustLevel above.
  if (oasbLevel !== undefined) {
    if (!isNonEmptyString(oasbLevel)) {
      throw new Error(
        `${label}: match.oasbLevel must be a non-empty string like ">=L2", not ` +
        `${describe(oasbLevel)}. An empty floor is not a floor everything satisfies — it ` +
        `removes the check. Omit oasbLevel to require no OASB level.`,
      );
    }
    if (parseOasbFloor(oasbLevel) === undefined) {
      const bare = oasbLevel.replace(/^>=\s*/, '').trim();
      const cased = caseOnlyMatch(bare);
      throw new Error(
        `${label}: match.oasbLevel "${oasbLevel}" names a level this build cannot rank` +
        `${cased ? ` (did you mean "${cased}"? levels are case-sensitive)` : ''}. ` +
        `This build ranks: ${rankableLevels()}. ` +
        `A floor it cannot rank is refused rather than ignored, because ignoring it would ` +
        `leave the binding with no OASB floor at all while reporting it loaded.`,
      );
    }
    out.oasbLevel = oasbLevel;
  }

  // Federation predicates. AAP §7.1 requires a v1 broker to PARSE the full clause, so these are
  // accepted rather than refused — but their shape is validated here, so the docstring's claim
  // that a malformed clause is caught at load is true rather than aspirational.
  if (m.issuerChainIncludes !== undefined) {
    const ici = m.issuerChainIncludes;
    if (!ici || typeof ici !== 'object' || Array.isArray(ici)) {
      throw new Error(`${label}: match.issuerChainIncludes must be an object with "partnersSet"`);
    }
    const rec = ici as Record<string, unknown>;
    checkKeys(`${label}: match.issuerChainIncludes`, rec, new Set(['partnersSet']));
    if (!isNonEmptyString(rec.partnersSet)) {
      throw new Error(
        `${label}: match.issuerChainIncludes.partnersSet must be a non-empty string naming the ` +
        `partner set.`,
      );
    }
    out.issuerChainIncludes = Object.freeze({ partnersSet: rec.partnersSet });
  }

  if (m.jurisdiction !== undefined) {
    const j = m.jurisdiction;
    if (!j || typeof j !== 'object' || Array.isArray(j)) {
      throw new Error(`${label}: match.jurisdiction must be an object with an "in" array`);
    }
    const rec = j as Record<string, unknown>;
    checkKeys(`${label}: match.jurisdiction`, rec, new Set(['in']));
    if (!Array.isArray(rec.in) || rec.in.length === 0 || !rec.in.every(isNonEmptyString)) {
      throw new Error(
        `${label}: match.jurisdiction.in must be a non-empty array of non-empty strings. An ` +
        `empty list names no jurisdiction, which is not the same as naming every one.`,
      );
    }
    out.jurisdiction = Object.freeze({ in: Object.freeze([...rec.in]) as string[] });
  }

  return out;
}

function validateResourceBinding(label: string, r: Record<string, unknown>): ResourceBinding {
  checkKeys(`${label}: resolve`, r, KNOWN_RESOLVE_KEYS, OVERWRITTEN_RESOLVE_KEYS);

  const mode = r.mode;
  if (!isNonEmptyString(mode) || !CPI_MODES.has(mode)) {
    const near = typeof mode === 'string' ? nearestMatch(mode, [...CPI_MODES]) : undefined;
    throw new Error(
      `${label}: resolve.mode must be one of ${[...CPI_MODES].join(', ')}, not ` +
      `${describe(mode)}${near ? ` (did you mean "${near}"?)` : ''}.`,
    );
  }
  const [providerId, scope, audience] = (['providerId', 'scope', 'audience'] as const).map((key) => {
    const value = r[key];
    if (!isNonEmptyString(value)) {
      throw new Error(`${label}: resolve.${key} must be a non-empty string, not ${describe(value)}`);
    }
    return value;
  });
  // Read once. See the note on minTrustLevel in validateGrantMatch.
  //
  // An absent or non-numeric TTL reaches the assertion builder as `nowSeconds + undefined`, which
  // is NaN, which `JSON.stringify` emits as `"exp": null` — a broker assertion a downstream
  // verifier may read as carrying no expiry at all. An integer is required separately from that:
  // `exp` is a NumericDate (RFC 7519 §2), so a fractional TTL mints a claim whose type the spec
  // does not admit, and a non-positive one mints a credential already expired at issue.
  const ttlSeconds = r.ttlSeconds;
  if (typeof ttlSeconds !== 'number' || !Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error(
      `${label}: resolve.ttlSeconds must be a whole number of seconds greater than zero, not ` +
      `${describe(ttlSeconds)}. A TTL this build cannot add to a timestamp mints a credential ` +
      `whose expiry serialises to null, and \`exp\` is a whole number of seconds (RFC 7519 §2).`,
    );
  }

  return {
    mode: mode as CpiMode,
    providerId: providerId as string,
    scope: scope as string,
    audience: audience as string,
    ttlSeconds,
  };
}

/** Describe a rejected value in an error without printing an object's contents. */
function describe(v: unknown): string {
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  if (typeof v === 'number' && Number.isNaN(v)) return 'NaN';
  if (typeof v === 'string') return `"${v}"`;
  if (Array.isArray(v)) return 'an array';
  return `a ${typeof v}`;
}
