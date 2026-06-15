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
 * within its own org, while still enforcing `trustClass`, `minTrustLevel`, `oasbLevel`,
 * mode, scope, and ttl. Default-deny: no matching binding ⇒ denied (AAP §3.4).
 */

import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import type { ResourceBinding } from './cpi/types';

export interface GrantMatch {
  /** Trust class (capability) the ATX must carry, e.g. "orders:read". Enforced in v1. */
  trustClass: string;
  /** Minimum ATX trust level. Enforced in v1. */
  minTrustLevel?: number;
  /** Minimum OASB level from the ATX scan summary, e.g. ">=L2". Enforced in v1. */
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

const OASB_RANK: Record<string, number> = { L1: 1, L2: 2, L3: 3 };

export class GrantPolicy {
  private readonly bindings: GrantBinding[];

  constructor(bindings: GrantBinding[] = []) {
    this.bindings = bindings;
  }

  get size(): number {
    return this.bindings.length;
  }

  /**
   * Evaluate a grant name against the policy and a verified-ATX context. Default-deny.
   * `grantName` is the logical name (without the `grant://` scheme).
   */
  evaluate(grantName: string, ctx: ResolutionContext): GrantEvaluation {
    const target = `grant://${grantName}`;
    const binding = this.bindings.find((b) => b.grant === target);
    if (!binding) {
      return { allowed: false, reason: `No binding for ${target} (default deny)` };
    }
    const m = binding.match;

    // Enforced predicates (v1).
    if (!ctx.capabilities.includes(m.trustClass)) {
      return { allowed: false, binding, reason: `ATX lacks trust class "${m.trustClass}"` };
    }
    if (m.minTrustLevel !== undefined && ctx.trustLevel < m.minTrustLevel) {
      return {
        allowed: false,
        binding,
        reason: `trust level ${ctx.trustLevel} below minimum ${m.minTrustLevel}`,
      };
    }
    if (m.oasbLevel) {
      const required = parseOasbFloor(m.oasbLevel);
      const have = ctx.oasbLevel ? OASB_RANK[ctx.oasbLevel] ?? 0 : 0;
      if (have < required) {
        return {
          allowed: false,
          binding,
          reason: `OASB level ${ctx.oasbLevel ?? 'none'} below required ${m.oasbLevel}`,
        };
      }
    }

    // Parsed-but-not-enforced-in-v1 predicates. Presence is validated so a malformed clause
    // is caught now; evaluation is deferred to v2 (federation) / v3 (jurisdiction).
    // m.issuerChainIncludes — federation (AAP §7): treated as satisfied within a single org.
    // m.jurisdiction        — residency  (AAP §9): parsed, not enforced.

    return { allowed: true, binding, reason: `Granted by binding for ${target}` };
  }
}

/** Parse an OASB floor like ">=L2" or "L2" to a numeric rank. */
function parseOasbFloor(spec: string): number {
  const level = spec.replace(/^>=\s*/, '').trim();
  return OASB_RANK[level] ?? 0;
}
