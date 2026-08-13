/**
 * Policy engine — default-deny allowlist for credential access.
 *
 * Loads policy rules from ~/.secretless-ai/broker-policies.json and evaluates
 * each resolve request against them. Deny rules are evaluated first (short-circuit).
 * All constraints must pass for an allow rule to grant access.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { PolicyRule, PolicyConstraints, AgentIdentity } from './types';
import { RateLimiter } from './rate-limiter';
import { nearestMatch } from '../near-miss';

const DEFAULT_POLICY_FILE = path.join(os.homedir(), '.secretless-ai', 'broker-policies.json');

export interface PolicyEvaluation {
  /** Whether the request is allowed. */
  allowed: boolean;
  /** ID of the matching rule, or empty string if default-deny. */
  matchedRuleId: string;
  /** Human-readable reason for the decision. */
  reason: string;
}

export class PolicyEngine {
  private rules: PolicyRule[] = [];
  private readonly rateLimiter: RateLimiter;
  private readonly policyFile: string;

  constructor(options?: { policyFile?: string; rateLimiter?: RateLimiter }) {
    this.policyFile = options?.policyFile ?? DEFAULT_POLICY_FILE;
    this.rateLimiter = options?.rateLimiter ?? new RateLimiter();
  }

  /**
   * Load policies from the policy file. Safe to call multiple times (reloads).
   * Returns the number of rules loaded.
   *
   * ASYNC because the duplicate-member scan it depends on lives in
   * `@opena2a/atx-verify`, which is ESM-only while this package is CommonJS —
   * the same dynamic-import mechanism the `/grant` path already uses in
   * `server.ts`. The whole chain above this call is already async
   * (`commands/broker.ts` -> `daemon.ts` -> `server.start()`), so the await
   * costs one keyword at the single call site. The signature change IS
   * consumer-visible for anyone using `PolicyEngine` as a library; a call left
   * un-awaited leaves the engine at zero rules, which is default-deny.
   */
  async loadPolicies(): Promise<number> {
    if (!fs.existsSync(this.policyFile)) {
      this.rules = [];
      return 0;
    }

    // Resolved BEFORE the load block and with its OWN message, because a module
    // that will not load is an installation fault and not a fault in the
    // operator's file. Reporting it as "Failed to load policies from <their
    // file>" would send them to debug the wrong artifact.
    //
    // There is deliberately no catch that continues without the scan. Falling
    // back to a bare JSON.parse here is not a degraded mode — it is the
    // pre-0.23.0 code path verbatim, the one this check exists to close. A
    // security check that cannot run must withhold, not wave the input through.
    let firstDuplicateMember: (text: string) => string | null;
    try {
      ({ firstDuplicateMember } = await import('@opena2a/atx-verify'));
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Cannot load policies from ${this.policyFile}: the duplicate-member scanner ` +
        `(@opena2a/atx-verify) could not be loaded, so the policy file was NOT applied and no ` +
        `credential will be served. This is an installation fault, not a fault in your policy ` +
        `file — do not edit or delete the file to clear it.\n` +
        `  Verify: node -e "import('@opena2a/atx-verify').then(() => console.log('ok'))"\n` +
        `  Fix:    npm install   # and check node -v is >= 20.19.0\n` +
        `  Cause:  ${detail}`,
      );
    }

    try {
      const raw = fs.readFileSync(this.policyFile, 'utf-8');

      // Scanned on the RAW TEXT, and on the SAME binding `JSON.parse` consumes
      // below — never a re-read and never a normalised copy, or the two would
      // be judging different bytes.
      //
      // It has to happen out here because `JSON.parse` resolves a duplicated
      // key before any consumer of the parsed object can see it: a reviver is
      // handed each member exactly once, already collapsed. Issue #140's filed
      // direction proposed that reviver; it cannot work, and the control it
      // would produce never fires.
      let duplicate: string | null;
      try {
        duplicate = firstDuplicateMember(raw);
      } catch {
        // StrictParseError. The scanner is lax on scalar tokens but strict on
        // structure, so this is text it cannot vouch for as a single JSON
        // value. Refusing here rather than letting JSON.parse decide keeps the
        // accept-set of the file and the accept-set of the check identical.
        throw new Error(
          `Policy file is not a single well-formed JSON value that the duplicate-member ` +
          `scanner can vouch for, so it was not applied. Check the file for truncation, ` +
          `trailing content after the closing brace, or a malformed string escape.`,
        );
      }
      if (duplicate !== null) {
        throw new Error(
          `Policy file has a duplicate member "${duplicate}". A member name that collides with ` +
          `another member of the same object is refused rather than resolved: where the collision ` +
          `is exact, JSON.parse keeps the LAST occurrence, so the half of the rule that RESTRICTS ` +
          `is the half that disappears — while the rule count, getRules() and /health all report ` +
          `it loaded. ` +
          `The colliding member may be spelled differently in the file than it reads here: names ` +
          `are compared after JSON escape decoding and case folding, so a case variant or an ` +
          `escaped spelling collides too. Remove the duplicate and keep the one you meant.`,
        );
      }

      const parsed = JSON.parse(raw);

      // Accept both { rules: [...] } and bare array [...] formats
      const rules = Array.isArray(parsed) ? parsed : parsed.rules;
      if (!Array.isArray(rules)) {
        throw new Error('Policy file must contain a "rules" array or be a JSON array');
      }

      // The ENVELOPE gets the same treatment as a rule. Measured: a file with
      // `{"rules": [allow], "denyRules": [deny-all]}` loaded the allow set,
      // ignored the deny set, and served the credential — the operator's deny
      // rules were never in the engine and nothing said so. This defect has now
      // been found at four nesting levels, so the check goes at every level
      // rather than at the one where the last instance turned up.
      if (!Array.isArray(parsed)) {
        for (const key of Object.keys(parsed)) {
          if (KNOWN_ENVELOPE_KEYS.has(key)) continue;
          const near = nearestMatch(key, [...KNOWN_ENVELOPE_KEYS]);
          throw new Error(
            `Policy file has an unknown top-level key "${key}"${near ? ` (did you mean "${near}"?)` : ''}. ` +
            `A policy file may carry: ${[...KNOWN_ENVELOPE_KEYS].join(', ')}. ` +
            `Rules under a key this build does not read would never be loaded, and nothing ` +
            `downstream could tell that from a file that declared no such rules.`,
          );
        }
      }

      this.rules = rules.map((r: unknown) => validateRule(r));
      return this.rules.length;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to load policies from ${this.policyFile}: ${message}`);
    }
  }

  /**
   * Load policies from an in-memory array (for testing).
   */
  loadRules(rules: PolicyRule[]): void {
    this.rules = rules.map(r => ({ ...r }));
  }

  /**
   * Evaluate whether an agent may access a credential.
   *
   * Evaluation order:
   * 1. Deny rules checked first (any match = denied)
   * 2. Allow rules checked next (first match with passing constraints = allowed)
   * 3. Default deny if no allow rule matches
   */
  evaluate(
    agentId: string,
    credentialName: string,
    agentIdentity?: AgentIdentity,
  ): PolicyEvaluation {
    // Phase 1: Check deny rules first
    for (const rule of this.rules) {
      if (rule.effect !== 'deny') continue;
      if (!matchGlob(rule.agentSelector, agentId)) continue;
      if (!matchGlob(rule.credentialSelector, credentialName)) continue;

      return {
        allowed: false,
        matchedRuleId: rule.id,
        reason: `Denied by rule "${rule.id}"`,
      };
    }

    // Phase 2: Check allow rules
    for (const rule of this.rules) {
      if (rule.effect !== 'allow') continue;
      if (!matchGlob(rule.agentSelector, agentId)) continue;
      if (!matchGlob(rule.credentialSelector, credentialName)) continue;

      // Check constraints
      const constraintResult = this.checkConstraints(
        rule.constraints,
        agentId,
        credentialName,
        agentIdentity,
      );

      if (!constraintResult.passed) {
        return {
          allowed: false,
          matchedRuleId: rule.id,
          reason: constraintResult.reason,
        };
      }

      return {
        allowed: true,
        matchedRuleId: rule.id,
        reason: `Allowed by rule "${rule.id}"`,
      };
    }

    // Phase 3: Default deny
    return {
      allowed: false,
      matchedRuleId: '',
      reason: 'No matching allow rule (default deny)',
    };
  }

  /** Get the current policy rule count. */
  get ruleCount(): number {
    return this.rules.length;
  }

  /** Get a copy of the loaded rules. */
  getRules(): PolicyRule[] {
    return this.rules.map(r => ({ ...r }));
  }

  private checkConstraints(
    constraints: PolicyConstraints,
    agentId: string,
    credentialName: string,
    agentIdentity?: AgentIdentity,
  ): { passed: boolean; reason: string } {
    // Time window check
    if (constraints.timeWindow) {
      if (!isWithinTimeWindow(constraints.timeWindow.start, constraints.timeWindow.end)) {
        return {
          passed: false,
          reason: `Outside allowed time window (${constraints.timeWindow.start}-${constraints.timeWindow.end})`,
        };
      }
    }

    // Trust score check
    if (constraints.minTrustScore !== undefined) {
      if (!agentIdentity) {
        return {
          passed: false,
          reason: `Trust score required (min ${constraints.minTrustScore}) but no agent identity available`,
        };
      }
      if (agentIdentity.trustScore < constraints.minTrustScore) {
        return {
          passed: false,
          reason: `Trust score ${agentIdentity.trustScore} below minimum ${constraints.minTrustScore}`,
        };
      }
    }

    // No scope check. It lived here, and it could not deny: it called
    // compareToBaseline with an empty current-permission list, and expansion is
    // computed from that list, so the deny branch was unreachable for every
    // baseline. The key is now refused at load (UNENFORCED_CONSTRAINT_KEYS)
    // rather than accepted and not applied, so there is nothing to enforce
    // here. Real enforcement needs live permission discovery in the resolve
    // path — latency, egress and error semantics — and is its own unit.

    // Capability check. `!== undefined`, not truthiness — see the load-time
    // check: an empty string is falsy and used to skip this whole block.
    if (constraints.requireCapability !== undefined) {
      if (!agentIdentity) {
        return {
          passed: false,
          reason: `Capability "${constraints.requireCapability}" required but no agent identity available`,
        };
      }
      if (!agentIdentity.capabilities.includes(constraints.requireCapability)) {
        return {
          passed: false,
          reason: `Agent lacks required capability "${constraints.requireCapability}"`,
        };
      }
    }

    // Rate limit check — evaluated LAST so that denied requests from other
    // constraints do not consume rate limit slots
    if (constraints.rateLimit) {
      const key = `${agentId}:${credentialName}`;
      if (!this.rateLimiter.check(key, constraints.rateLimit.maxPerMinute)) {
        return {
          passed: false,
          reason: `Rate limit exceeded (${constraints.rateLimit.maxPerMinute}/min)`,
        };
      }
    }

    return { passed: true, reason: '' };
  }
}

/**
 * Simple glob matching supporting * (any chars) and ? (single char).
 * Not a full glob implementation — covers the common policy selector patterns.
 */
export function matchGlob(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (pattern === value) return true;

  // Convert glob to regex: escape special chars, then convert * and ?
  //
  // `[\s\S]` and `[^]`-style classes rather than `.`, because `.` does not match
  // a line terminator: `matchGlob('AWS_*', 'AWS_KEY\n')` was FALSE while
  // `matchGlob('*', 'AWS_KEY\n')` was true (the `*` fast path above skips the
  // regex entirely). A glob DENY rule therefore missed any value carrying \n,
  // \r, U+2028 or U+2029 while a wildcard ALLOW matched it — the deny rule the
  // operator wrote silently did not fire. Measured; also measured that such a
  // name does not currently resolve to a credential, because `getSecret`
  // rejects it at `SAFE_NAME` before any lookup. So this is the policy decision
  // being wrong rather than a credential being served, and it is fixed here so
  // that it stays that way if name validation ever moves.
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '[\\s\\S]*')
    .replace(/\?/g, '[\\s\\S]');

  const regex = new RegExp(`^${escaped}$`);
  return regex.test(value);
}

/**
 * Check if the current time is within a time window (24h format).
 * Handles windows that cross midnight (e.g., "22:00"-"06:00").
 */
export function isWithinTimeWindow(start: string, end: string): boolean {
  const now = new Date();
  const currentMinutes = now.getHours() * 60 + now.getMinutes();

  const startMinutes = parseTimeToMinutes(start);
  const endMinutes = parseTimeToMinutes(end);

  if (startMinutes <= endMinutes) {
    // Normal window (e.g., 09:00-17:00)
    return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
  } else {
    // Overnight window (e.g., 22:00-06:00)
    return currentMinutes >= startMinutes || currentMinutes <= endMinutes;
  }
}

function parseTimeToMinutes(time: string): number {
  const parts = time.split(':');
  if (parts.length !== 2) {
    throw new Error(`Invalid time format: "${time}". Expected HH:MM`);
  }
  const hours = parseInt(parts[0], 10);
  const minutes = parseInt(parts[1], 10);
  if (isNaN(hours) || isNaN(minutes) || hours < 0 || hours > 23 || minutes < 0 || minutes > 59) {
    throw new Error(`Invalid time value: "${time}"`);
  }
  return hours * 60 + minutes;
}

/**
 * Every constraint this build knows how to ENFORCE.
 *
 * Derived by hand and pinned by a test against `PolicyConstraints`, so a new
 * constraint added to the type without being added here fails the suite rather
 * than being silently refused at runtime — and one added here without an
 * enforcement branch in `checkConstraints` fails too. The set is a promise
 * about what is applied, not a list of what parses.
 */
export const KNOWN_CONSTRAINT_KEYS = new Set([
  'timeWindow',
  'rateLimit',
  'minTrustScore',
  'requireCapability',
]);

/**
 * The five keys a policy rule may carry, mirroring `PolicyRule` in ./types.
 *
 * A rule is refused if it carries anything else. Misspelling the CONTAINER
 * reaches the same place misspelling a constraint did: `contraints: {...}` left
 * `r.constraints` undefined, so the block below never ran, and the rule loaded
 * as an unconstrained ALLOW while `loadPolicies()`, `getRules()` and `/health`
 * all reported it loaded. That is the same fail-open the constraint-key check
 * closes, one level up, and it was reachable in the build that fixed the inner
 * one.
 *
 * Deliberately NOT tolerating annotation keys (`description`, `comment`): the
 * shipped example in docs/use-cases/run-broker.md and every fixture use exactly
 * these five, so tolerance buys no compatibility, and each tolerated key is one
 * more near-miss neighbour for the typo this exists to catch.
 *
 * Deliberately NOT auto-correcting a near miss to the key it resembles. Binding
 * a key the operator did not write is a guess about intent inside the
 * authorization path; the error names the likely intent instead.
 */
export const KNOWN_RULE_KEYS = new Set([
  'id',
  'agentSelector',
  'credentialSelector',
  'constraints',
  'effect',
]);

/** Top-level keys of the policy FILE. `version` is in the documented example. */
export const KNOWN_ENVELOPE_KEYS = new Set(['version', 'rules']);

/**
 * Sub-keys of each structured constraint.
 *
 * The destructuring below reads `{start, end}` and `{maxPerMinute}` and drops
 * everything else, so `rateLimit: {maxPerMinute: 60, maxPerHour: 1}` silently
 * discarded the hourly cap and permitted 3600/hour, and `timeWindow` with a
 * mistyped `End` kept the open window the operator meant to close. Same defect
 * as the container, one level further in.
 */
const KNOWN_CONSTRAINT_SUBKEYS = new Map<string, Set<string>>([
  ['timeWindow', new Set(['start', 'end'])],
  ['rateLimit', new Set(['maxPerMinute'])],
]);

/** Refuse a structured constraint carrying a sub-key we would silently drop. */
function checkSubKeys(ruleId: string, constraint: string, value: object): void {
  const known = KNOWN_CONSTRAINT_SUBKEYS.get(constraint);
  if (!known) return;
  for (const key of Object.keys(value)) {
    if (known.has(key)) continue;
    const near = nearestMatch(key, [...known]);
    throw new Error(
      `Rule "${ruleId}": ${constraint} has an unknown field "${key}"` +
      `${near ? ` (did you mean "${near}"?)` : ''}. ` +
      `${constraint} takes: ${[...known].join(', ')}. ` +
      `A field this build does not read is refused rather than dropped, because dropping ` +
      `it would loosen the limit the operator wrote.`,
    );
  }
}

/**
 * Constraints this build parses but does not enforce, with the reason.
 *
 * A rule naming one is REFUSED, not ignored. `scopeCheck` sat in the known set
 * and was documented as "deny if credential permissions expanded since last
 * baseline", while `checkConstraints` called
 * `compareToBaseline(credentialName, '', [])` — an empty current-permission
 * list, from which `hasExpanded` is computed, so it was false for every
 * baseline and the deny branch was unreachable. Measured: the same function
 * returns `hasExpanded: true` when given real permissions, so the call site was
 * what disabled it, not the comparison. An operator's scope-drift gate was
 * inert while every surface reported it enforced.
 *
 * Accepting the key with no enforcement is the failure mode this file is about,
 * so it is refused until the enforcement exists.
 */
const UNENFORCED_CONSTRAINT_KEYS = new Map<string, string>([
  [
    'scopeCheck',
    'this build does not enforce scopeCheck — it never denied a request, so accepting it ' +
    'would report a scope-drift gate that is not there. Remove it from the rule; a rule ' +
    'without it is enforced exactly as written.',
  ],
]);

/** "HH:MM", 00:00-23:59. */
const TIME_OF_DAY = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

function validateRule(raw: unknown): PolicyRule {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Policy rule must be an object');
  }

  const r = raw as Record<string, unknown>;

  if (typeof r.id !== 'string' || !r.id) {
    throw new Error('Policy rule must have a non-empty "id" string');
  }

  // Top-level keys are checked BEFORE the constraint block, because the defect
  // this closes is that a misspelled container never reaches that block at all.
  for (const key of Object.keys(r)) {
    if (KNOWN_RULE_KEYS.has(key)) continue;
    const near = nearestMatch(key, [...KNOWN_RULE_KEYS]);
    throw new Error(
      `Rule "${r.id}": unknown field "${key}"${near ? ` (did you mean "${near}"?)` : ''}. ` +
      `A rule may carry: ${[...KNOWN_RULE_KEYS].join(', ')}. ` +
      `A field this build does not read is refused rather than ignored, because ignoring ` +
      `"${key}" would drop whatever it was meant to restrict and load the rule as written ` +
      `without it.`,
    );
  }
  // Non-empty, and the DENY direction is why: an empty selector matches nothing,
  // so a deny rule written with one never fires while a sibling `allow: *`
  // does — the restriction disappears and the permission survives. Measured.
  if (typeof r.agentSelector !== 'string' || r.agentSelector === '') {
    throw new Error(
      `Rule "${r.id}": agentSelector must be a non-empty string. An empty selector matches ` +
      `no agent, so a deny rule carrying one silently never fires. Use "*" to match every agent.`,
    );
  }
  if (typeof r.credentialSelector !== 'string' || r.credentialSelector === '') {
    throw new Error(
      `Rule "${r.id}": credentialSelector must be a non-empty string. An empty selector matches ` +
      `no credential, so a deny rule carrying one silently never fires. Use "*" to match every one.`,
    );
  }
  if (r.effect !== 'allow' && r.effect !== 'deny') {
    throw new Error(`Rule "${r.id}": effect must be "allow" or "deny"`);
  }

  /**
   * Constraint parsing REFUSES what it cannot apply.
   *
   * This block used to accept a rule and silently drop any constraint it could
   * not type-match, which is the worst possible reading of an unrecognised
   * policy: the RESTRICTIVE half of the operator's rule evaporated and the
   * PERMISSIVE half survived. Measured on 0.22.0 — a `timeWindow` written with
   * numeric hours instead of "HH:MM" strings, or `rateLimit.maxPerMinute` as
   * the string "1", produced `constraints: {}` and `evaluate()` returned
   * `allowed: true, reason: 'Allowed by rule "r1"'`, while `loadPolicies()`
   * returned 1 and `getRules()` showed the rule present. Every surface the
   * operator could check reported the policy as loaded.
   *
   * A numeric string is not a hypothetical: it is what a YAML-to-JSON
   * conversion, a templating layer or an env-var substitution produces. The
   * sharpest case is `minTrustScore: "80"` — the trust floor vanishes and any
   * agent matching the selector is served.
   *
   * The surrounding function already throws on a malformed `id`,
   * `agentSelector`, `credentialSelector` or `effect`. This block is now
   * consistent with the rest of its own function rather than the exception
   * inside it, and `checkConstraints` — which is correctly fail-closed — is no
   * longer defeated by its own input layer.
   */
  const constraints: PolicyConstraints = {};
  if (r.constraints !== undefined && r.constraints !== null) {
    if (typeof r.constraints !== 'object' || Array.isArray(r.constraints)) {
      throw new Error(`Rule "${r.id}": constraints must be an object`);
    }
    const c = r.constraints as Record<string, unknown>;

    for (const key of Object.keys(c)) {
      const unenforced = UNENFORCED_CONSTRAINT_KEYS.get(key);
      if (unenforced) {
        throw new Error(`Rule "${r.id}": ${unenforced}`);
      }
      if (!KNOWN_CONSTRAINT_KEYS.has(key)) {
        throw new Error(
          `Rule "${r.id}": unknown constraint "${key}". ` +
          `Known constraints: ${[...KNOWN_CONSTRAINT_KEYS].join(', ')}. ` +
          `A constraint this build cannot apply is refused rather than ignored, ` +
          `because ignoring it would widen the rule.`,
        );
      }
    }

    if (c.timeWindow !== undefined) {
      const tw = c.timeWindow;
      if (typeof tw !== 'object' || tw === null || Array.isArray(tw)) {
        throw new Error(`Rule "${r.id}": timeWindow must be an object with "start" and "end"`);
      }
      const { start, end } = tw as Record<string, unknown>;
      if (typeof start !== 'string' || typeof end !== 'string') {
        throw new Error(
          `Rule "${r.id}": timeWindow.start and timeWindow.end must be "HH:MM" strings ` +
          `(got ${typeof start} and ${typeof end})`,
        );
      }
      if (!TIME_OF_DAY.test(start) || !TIME_OF_DAY.test(end)) {
        throw new Error(`Rule "${r.id}": timeWindow.start and timeWindow.end must be "HH:MM", 00:00-23:59`);
      }
      checkSubKeys(r.id, 'timeWindow', tw);
      constraints.timeWindow = { start, end };
    }

    if (c.rateLimit !== undefined) {
      const rl = c.rateLimit;
      if (typeof rl !== 'object' || rl === null || Array.isArray(rl)) {
        throw new Error(`Rule "${r.id}": rateLimit must be an object with "maxPerMinute"`);
      }
      const { maxPerMinute } = rl as Record<string, unknown>;
      if (typeof maxPerMinute !== 'number' || !Number.isFinite(maxPerMinute) || maxPerMinute <= 0) {
        throw new Error(
          `Rule "${r.id}": rateLimit.maxPerMinute must be a positive number (got ${JSON.stringify(maxPerMinute)})`,
        );
      }
      checkSubKeys(r.id, 'rateLimit', rl);
      constraints.rateLimit = { maxPerMinute };
    }

    if (c.minTrustScore !== undefined) {
      if (typeof c.minTrustScore !== 'number' || !Number.isFinite(c.minTrustScore)) {
        throw new Error(
          `Rule "${r.id}": minTrustScore must be a number (got ${JSON.stringify(c.minTrustScore)})`,
        );
      }
      constraints.minTrustScore = c.minTrustScore;
    }

    if (c.requireCapability !== undefined) {
      if (typeof c.requireCapability !== 'string') {
        throw new Error(`Rule "${r.id}": requireCapability must be a string`);
      }
      // Non-empty, because the enforcement branch guards on TRUTHINESS: an
      // empty string skipped the whole capability check, including its
      // fail-closed "no agent identity" arm, so the gate vanished while
      // getRules() still showed `requireCapability: ""`. Measured: "deploy"
      // with no identity denies, "" with no identity allows. `${VAR}` with the
      // variable unset is exactly how a templating layer produces it — the same
      // substitution story as the numeric strings this function already refuses.
      if (c.requireCapability === '') {
        throw new Error(
          `Rule "${r.id}": requireCapability must not be empty. An empty capability is not ` +
          `a capability that everything satisfies — it removes the check. Name the capability, ` +
          `or omit requireCapability entirely.`,
        );
      }
      constraints.requireCapability = c.requireCapability;
    }

  }

  return {
    id: r.id,
    agentSelector: r.agentSelector,
    credentialSelector: r.credentialSelector,
    constraints,
    effect: r.effect,
  };
}
