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

      if (!Array.isArray(parsed.rules)) {
        throw new Error('Policy file must contain a "rules" array');
      }

      this.rules = parsed.rules.map((r: unknown) => validateRule(r));
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

    // Rate limit check
    if (constraints.rateLimit) {
      const key = `${agentId}:${credentialName}`;
      if (!this.rateLimiter.check(key, constraints.rateLimit.maxPerMinute)) {
        return {
          passed: false,
          reason: `Rate limit exceeded (${constraints.rateLimit.maxPerMinute}/min)`,
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

  const constraints: PolicyConstraints = {};
  if (r.constraints && typeof r.constraints === 'object') {
    const c = r.constraints as Record<string, unknown>;

    if (c.timeWindow && typeof c.timeWindow === 'object') {
      const tw = c.timeWindow as Record<string, unknown>;
      if (typeof tw.start === 'string' && typeof tw.end === 'string') {
        constraints.timeWindow = { start: tw.start, end: tw.end };
      }
    }

    if (c.rateLimit && typeof c.rateLimit === 'object') {
      const rl = c.rateLimit as Record<string, unknown>;
      if (typeof rl.maxPerMinute === 'number' && rl.maxPerMinute > 0) {
        constraints.rateLimit = { maxPerMinute: rl.maxPerMinute };
      }
    }

    if (typeof c.minTrustScore === 'number') {
      constraints.minTrustScore = c.minTrustScore;
    }

    if (typeof c.requireCapability === 'string') {
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
