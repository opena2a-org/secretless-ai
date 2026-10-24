/**
 * Grant resolver — the AAP §6 resolution flow, the enforcement point of the
 * decision/enforcement split (§3). Given a presented ATX, a grant reference, and a
 * logical operation, it:
 *
 *   1. verifies the ATX locally (signature/suite/expiry/CRL — §6 step 2),
 *   2. (optionally) cross-checks AIM agent identity (reuse of the existing AIM path),
 *   3. evaluates local grant policy against the verified context (default-deny — §3.4),
 *   4. resolves a scoped credential via the selected CPI provider (§5), and holds the life it
 *      reports to the binding's TTL,
 *   5. runs the operation in an ephemeral worker and returns ONLY the result (§6.5),
 *   6. audits every step to the signed, hash-chained audit log (§6.7; see audit.ts).
 *
 * Every failure yields the SAME opaque typed denial (§6.6): the agent learns nothing
 * about policy internals or backend topology. The audit record names the check that
 * decided with a code from a closed set (GRANT_AUDIT_REASONS), never with text.
 *
 * When the worker's downstream caller delivers salts, the broker commits to the operation it
 * forwards: it draws a fresh 32-byte salt, hands it to the caller with the operation, and
 * writes only SHA-256(salt || JCS(operation)) to the record. The resource keeps the salt beside
 * the operation in its own record, so whoever holds both can open the commitment.
 */

import * as crypto from 'crypto';
import type {
  Atx,
  AtxVerifier,
  RejectCategory,
} from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import type { GrantPolicy } from './grant-policy';
import {
  capCredentialLife,
  type CpiMode,
  type ProviderRegistry,
  type ScopedCredential,
} from './cpi/types';
import {
  resolveDownstreamUrl,
  type AgentOperation,
  type EphemeralWorker,
  type OperationResult,
} from './worker';
import type { AuditLogger } from './audit';
import type { AimClient } from './aim-client';
import { canonicalizeJson } from './jcs';
import { GRANT_AUDIT_REASONS, type AuditEntry, type GrantAuditReason } from './types';
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

/** Bytes of salt drawn for each committed operation (256 bits). */
const SALT_BYTES = 32;

/** A DID Core idchar: ALPHA / DIGIT / "." / "-" / "_" / pct-encoded. */
const ID_CHAR = '(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})';

/** A DID, by the W3C DID Core syntax: `did:` method-name `:` method-specific-id. */
const DID = new RegExp(`^did:[a-z0-9]+:(?:${ID_CHAR}*:)*${ID_CHAR}+$`);

/** A CGT `jti`: 16 random bytes, lowercase hex (AAP §8.1). */
const JTI = /^[0-9a-f]{32}$/;

const KNOWN_REASONS: ReadonlySet<string> = new Set(GRANT_AUDIT_REASONS);

/** The code a rejected ATX is recorded under, by the verifier's reject category. */
const ATX_REJECTED: ReadonlyMap<string, GrantAuditReason> = new Map(
  Object.entries({
    UNSUPPORTED_VERSION: 'atx-unsupported-version',
    EXPIRED: 'atx-expired',
    REVOKED: 'atx-revoked',
    UNTRUSTED_ISSUER: 'atx-untrusted-issuer',
    SIGNATURE_INVALID: 'atx-signature-invalid',
    MALFORMED: 'atx-malformed',
  } satisfies Record<RejectCategory, GrantAuditReason>),
);

/** The code a completed resolution is recorded under, by the CPI mode that resolved it. */
const RESOLVED: Record<CpiMode, GrantAuditReason> = {
  retrieve: 'resolved-retrieve',
  assume: 'resolved-assume',
  exchange: 'resolved-exchange',
};

/**
 * What the record writes for an input it will not write as given: a fixed marker and the input's
 * length in UTF-8 bytes (0 for a value that is not a string).
 */
function unparsed(value: unknown): string {
  return `unparsed:${typeof value === 'string' ? Buffer.byteLength(value, 'utf-8') : 0}`;
}

/** The agent-supplied id when it parses as a DID; otherwise the marker. */
function parsedDid(value: unknown): string {
  return typeof value === 'string' && DID.test(value) ? value : unparsed(value);
}

/** The jti a provider reported, when it is in the form a CGT jti takes; otherwise the marker. */
function parsedJti(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  return typeof value === 'string' && JTI.test(value) ? value : unparsed(value);
}

/** The policy's denial code when it is one this build knows; otherwise the general one. */
function policyDenial(code: unknown): GrantAuditReason {
  return typeof code === 'string' && code.startsWith('policy-') && KNOWN_REASONS.has(code)
    ? (code as GrantAuditReason)
    : 'policy-denied';
}

/** The members of an operation the downstream caller acts on: method, path, query and body. */
function forwardedMembers(op: AgentOperation): AgentOperation {
  return {
    method: op.method,
    path: op.path,
    ...(op.query === undefined ? {} : { query: op.query }),
    ...(op.body === undefined ? {} : { body: op.body }),
  };
}

/**
 * The commitment a grant record carries for an operation: the lowercase hex SHA-256 of `salt`
 * followed by the operation's RFC 8785 (JCS) bytes. `canonical` is that JCS text.
 */
function operationCommitment(salt: Uint8Array, canonical: string): string {
  return crypto.createHash('sha256').update(salt).update(canonical, 'utf-8').digest('hex');
}

export class GrantResolver {
  constructor(private readonly deps: GrantResolverDeps) {}

  async resolve(input: GrantResolveInput): Promise<GrantResolveOutcome> {
    const start = Date.now();
    // Until the ATX is verified the record has only the agent-supplied id, and writes it only in
    // parsed form. Once verified, it names the agent by the verified ATX DID, so a caller cannot
    // attribute its action to, or run the AIM cross-check against, a different principal (the
    // verified ATX is the source of truth, never the top-level `input.agentId`).
    let recordedAgent = parsedDid(input.agentId);
    let recordedGrant = unparsed(input.grant);
    let cgtJti: string | undefined;
    let committed: string | undefined;
    const audit = (result: 'allowed' | 'denied', reason: GrantAuditReason, policyId = '') => {
      const entry: AuditEntry = {
        timestamp: new Date().toISOString(),
        eventType: 'grant',
        agentId: recordedAgent,
        credentialName: recordedGrant,
        policyId,
        result,
        reason,
        latencyMs: Date.now() - start,
      };
      if (cgtJti !== undefined) entry.cgtJti = cgtJti;
      if (committed !== undefined) entry.operationCommitment = committed;
      this.deps.audit?.log(entry);
    };

    // The step in progress, recorded if it throws. Exception text can come from a provider or the
    // downstream and carry what the operation named, so a failure is recorded as a code.
    let failure: GrantAuditReason = 'policy-error';
    try {
      // The grant reference is recorded only when it names a configured grant: there is no
      // grant-name grammar to parse it against, so the configured names are the parsed form.
      if (this.deps.policy.configures(input.grant)) recordedGrant = input.grant;

      // 1. Verify the ATX locally.
      failure = 'atx-verifier-error';
      const verification = this.deps.verifier.verify(input.atx);
      if (!verification.valid || !verification.context) {
        audit('denied', ATX_REJECTED.get(String(verification.rejectCategory)) ?? 'atx-rejected');
        return DENIED;
      }
      const ctx = verification.context;
      // The verified ATX identity supersedes the agent-supplied id for every downstream
      // decision and audit record.
      const did: unknown = ctx.agentDid;
      recordedAgent = typeof did === 'string' && did !== '' ? did : unparsed(did);

      // 2. Optional AIM identity cross-check, against the VERIFIED identity (defense in depth;
      // advisory — an agent AIM has never seen is not denied here, but a known-unverified one is).
      if (this.deps.aimClient) {
        failure = 'aim-lookup-error';
        const identity = await this.deps.aimClient.getAgentIdentity(ctx.agentId);
        if (identity && identity.verified === false) {
          audit('denied', 'aim-agent-unverified');
          return DENIED;
        }
      }

      // 3. Parse the grant reference (rejects any backend-leaking shape) and evaluate policy.
      let grantName: string;
      try {
        grantName = parseGrantRef(input.grant).name;
      } catch {
        audit('denied', 'grant-reference-invalid');
        return DENIED;
      }
      failure = 'policy-error';
      const evaluation = this.deps.policy.evaluate(grantName, ctx);
      if (!evaluation.allowed || !evaluation.binding) {
        audit('denied', policyDenial(evaluation.code), evaluation.binding?.grant ?? '');
        return DENIED;
      }
      const binding = evaluation.binding;

      // 4. Select the CPI provider and resolve a scoped credential (confined to the broker).
      failure = 'provider-error';
      const provider = this.deps.providers.get(binding.resolve.providerId);
      if (!provider) {
        audit('denied', 'provider-not-registered', binding.grant);
        return DENIED;
      }
      if (!provider.modes.includes(binding.resolve.mode)) {
        audit('denied', 'provider-mode-unsupported', binding.grant);
        return DENIED;
      }
      // The trust class comes from the MATCHED policy clause: the broker assertion's
      // trust_class claim carries the abstract ATX capability (AAP-SPEC §4.2), not the
      // downstream scope the binding resolves to.
      const cred = await provider.resolve(ctx, {
        ...binding.resolve,
        trustClass: binding.match.trustClass,
      });
      if (!cred || typeof cred !== 'object') {
        audit('denied', 'provider-returned-no-credential', binding.grant);
        return DENIED;
      }
      // The binding's TTL is the operator's ceiling on the credential's life, and it holds for
      // whichever provider the registry returned, not only for one that caps its own report. The
      // worker is handed a copy this call owns, with the life held to the TTL policy loaded, so a
      // provider that reports a longer life, NaN or a string cannot hand the downstream caller a
      // life the binding does not allow. Each named member is read from the provider's object
      // once, and by name, so a credential that keeps them on its prototype still carries them;
      // the rest keeps any member a provider adds for the caller it is paired with.
      const { token, tokenType, expiresInSeconds: stated, ...added } = cred;
      const confined: ScopedCredential = {
        ...added,
        token,
        tokenType,
        expiresInSeconds: capCredentialLife(stated, binding.resolve.ttlSeconds),
      };
      // The CGT jti, read from the copy above, so the record links to the token service's record.
      cgtJti = parsedJti(added.cgtJti);

      // 5. Run the operation in an ephemeral worker. Only the result crosses back.
      //
      // The worker pins the path to the binding's origin before any caller runs. The same check
      // runs here first, so a refused path is recorded as refused, with no commitment: nothing
      // was forwarded.
      failure = 'operation-path-refused';
      resolveDownstreamUrl(binding.resolve.audience, input.operation.path);

      // No commitment without a holder of its salt: a salt is drawn only for a caller that
      // delivers it to the resource. The commitment is over the operation's JCS bytes, and the
      // caller is handed the operation rebuilt from those bytes, so what it forwards is exactly
      // what the record commits to. The salt itself is never written, and is wiped once the
      // call returns.
      let operation = input.operation;
      let salt: Buffer | undefined;
      if (this.deps.worker.deliversSalt) {
        failure = 'operation-not-canonical';
        const canonical = canonicalizeJson(forwardedMembers(input.operation));
        salt = crypto.randomBytes(SALT_BYTES);
        committed = operationCommitment(salt, canonical);
        operation = JSON.parse(canonical) as AgentOperation;
      }

      failure = 'downstream-error';
      let result: OperationResult;
      try {
        result = await this.deps.worker.run(
          binding.resolve,
          confined,
          operation,
          salt === undefined ? undefined : Buffer.from(salt),
        );
      } finally {
        salt?.fill(0);
      }

      // 6. Audit success. Note: no token, no credential, no backend secret, no salt is logged.
      audit('allowed', RESOLVED[binding.resolve.mode], binding.grant);
      return { ok: true, result };
    } catch {
      // Any provider/worker/transport failure collapses to the same opaque denial, recorded as
      // the step that failed.
      audit('denied', failure);
      return DENIED;
    }
  }
}
