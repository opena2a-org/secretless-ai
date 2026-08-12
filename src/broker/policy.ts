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
import { compareToBaseline } from '../scope/baselines';

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
   */
  loadPolicies(): number {
    if (!fs.existsSync(this.policyFile)) {
      this.rules = [];
      return 0;
    }

    try {
      const raw = fs.readFileSync(this.policyFile, 'utf-8');
      const parsed = JSON.parse(raw);

      // Accept both { rules: [...] } and bare array [...] formats
      const rules = Array.isArray(parsed) ? parsed : parsed.rules;
      if (!Array.isArray(rules)) {
        throw new Error('Policy file must contain a "rules" array or be a JSON array');
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

    // Scope check
    if (constraints.scopeCheck) {
      const scopeResult = compareToBaseline(credentialName, '', []);
      // Only enforce if a baseline exists (baselinePermissions > 0 means we have a baseline)
      if (scopeResult.baselinePermissions.length > 0 && scopeResult.hasExpanded) {
        return {
          passed: false,
          reason: `Credential scope has expanded since baseline (+${scopeResult.added.length} permissions)`,
        };
      }
    }

    // Capability check
    if (constraints.requireCapability) {
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
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');

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
const KNOWN_CONSTRAINT_KEYS = new Set([
  'timeWindow',
  'rateLimit',
  'minTrustScore',
  'requireCapability',
  'scopeCheck',
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
  if (typeof r.agentSelector !== 'string') {
    throw new Error(`Rule "${r.id}": agentSelector must be a string`);
  }
  if (typeof r.credentialSelector !== 'string') {
    throw new Error(`Rule "${r.id}": credentialSelector must be a string`);
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
      constraints.requireCapability = c.requireCapability;
    }

    if (c.scopeCheck !== undefined) {
      if (typeof c.scopeCheck !== 'boolean') {
        throw new Error(`Rule "${r.id}": scopeCheck must be a boolean`);
      }
      constraints.scopeCheck = c.scopeCheck;
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
