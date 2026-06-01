/**
 * Grant resolver — the AAP §6 resolution flow, the enforcement point of the
 * decision/enforcement split (§3). Given a presented ATX, a grant reference, and a
 * logical operation, it:
 *
 *   1. verifies the ATX locally (signature/suite/expiry/CRL — §6 step 2),
 *   2. (optionally) cross-checks AIM agent identity (reuse of the existing AIM path),
 *   3. evaluates local grant policy against the verified context (default-deny — §3.4),
 *   4. resolves a scoped credential via the selected CPI provider (§5),
 *   5. runs the operation in an ephemeral worker and returns ONLY the result (§6.5),
 *   6. audits every step through the existing signed audit path (§6.7).
 *
 * Every failure yields the SAME opaque typed denial (§6.6): the agent learns nothing
 * about policy internals or backend topology. Diagnostic detail goes to the audit log.
 */

import type { Atx, AtxVerifier } from './atx';
import type { GrantPolicy } from './grant-policy';
import type { ProviderRegistry } from './cpi/types';
import type { AgentOperation, EphemeralWorker, OperationResult } from './worker';
import type { AuditLogger } from './audit';
import type { AimClient } from './aim-client';
import { parseGrantRef } from '../grant';

export interface GrantResolverDeps {
  verifier: AtxVerifier;
  policy: GrantPolicy;
  providers: ProviderRegistry;
  worker: EphemeralWorker;
  audit?: AuditLogger;
  aimClient?: AimClient | null;
}

export interface GrantResolveInput {
  agentId: string;
  atx: Atx;
  /** grant://name */
  grant: string;
  operation: AgentOperation;
}

/** Opaque denial. One code for every failure mode (AAP §6.6). No detail crosses to the agent. */
export interface TypedDenial {
  code: 'denied';
}

export type GrantResolveOutcome =
  | { ok: true; result: OperationResult }
  | { ok: false; denial: TypedDenial };

const DENIED: GrantResolveOutcome = { ok: false, denial: { code: 'denied' } };

export class GrantResolver {
  constructor(private readonly deps: GrantResolverDeps) {}

  async resolve(input: GrantResolveInput): Promise<GrantResolveOutcome> {
    const start = Date.now();
    // Audit keys off the agent-supplied id ONLY until the ATX is verified; thereafter it
    // keys off the cryptographically-verified identity so a caller cannot attribute its
    // action to, or run the AIM cross-check against, a different principal (the verified
    // ATX is the source of truth, never the top-level `input.agentId`).
    let auditAgentId = input.agentId;
    const audit = (result: 'allowed' | 'denied', reason: string, policyId = '') => {
      this.deps.audit?.logEvent(
        'grant',
        auditAgentId,
        input.grant,
        policyId,
        result,
        reason,
        Date.now() - start,
      );
    };

    try {
      // 1. Verify the ATX locally.
      const verification = this.deps.verifier.verify(input.atx);
      if (!verification.valid || !verification.context) {
        audit('denied', `ATX verification failed: ${verification.rejectCategory ?? 'invalid'}`);
        return DENIED;
      }
      const ctx = verification.context;
      // The verified ATX identity supersedes the agent-supplied id for every downstream
      // decision and audit record.
      auditAgentId = ctx.agentId;

      // 2. Optional AIM identity cross-check, against the VERIFIED identity (defense in depth;
      // advisory — an agent AIM has never seen is not denied here, but a known-unverified one is).
      if (this.deps.aimClient) {
        const identity = await this.deps.aimClient.getAgentIdentity(ctx.agentId);
        if (identity && identity.verified === false) {
          audit('denied', 'AIM reports agent not verified');
          return DENIED;
        }
      }

      // 3. Parse the grant reference (rejects any backend-leaking shape) and evaluate policy.
      let grantName: string;
      try {
        grantName = parseGrantRef(input.grant).name;
      } catch (err) {
        audit('denied', `invalid grant reference: ${(err as Error).message}`);
        return DENIED;
      }
      const evaluation = this.deps.policy.evaluate(grantName, ctx);
      if (!evaluation.allowed || !evaluation.binding) {
        audit('denied', evaluation.reason, evaluation.binding?.grant ?? '');
        return DENIED;
      }
      const binding = evaluation.binding;

      // 4. Select the CPI provider and resolve a scoped credential (confined to the broker).
      const provider = this.deps.providers.get(binding.resolve.providerId);
      if (!provider) {
        audit('denied', `no provider "${binding.resolve.providerId}"`, binding.grant);
        return DENIED;
      }
      if (!provider.modes.includes(binding.resolve.mode)) {
        audit('denied', `provider does not support mode ${binding.resolve.mode}`, binding.grant);
        return DENIED;
      }
      const cred = await provider.resolve(ctx, binding.resolve);

      // 5. Run the operation in an ephemeral worker. Only the result crosses back.
      const result = await this.deps.worker.run(binding.resolve, cred, input.operation);

      // 6. Audit success. Note: no token, no credential, no backend secret is logged.
      audit('allowed', `resolved ${binding.grant} via ${binding.resolve.mode}`, binding.grant);
      return { ok: true, result };
    } catch (err) {
      // Any provider/worker/transport failure collapses to the same opaque denial.
      audit('denied', `resolution error: ${(err as Error).message}`);
      return DENIED;
    }
  }
}
