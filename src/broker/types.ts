/**
 * Broker service types — identity-aware credential mediation.
 *
 * Defines the core data structures for the broker daemon including
 * configuration, request/response shapes, policy rules, and audit entries.
 */

/** Broker daemon configuration. */
export interface BrokerConfig {
  /** Unix domain socket path. Default: ~/.secretless-ai/broker.sock */
  socketPath: string;
  /** HTTP fallback port (localhost only). Default: 19421 */
  httpPort: number;
  /** AIM server URL for agent identity verification. Optional. */
  aimUrl?: string;
  /** Bearer token for authenticating to AIM. Optional. */
  aimToken?: string;
  /** Path to policy file. Default: ~/.secretless-ai/broker-policies.json */
  policyFile?: string;
  /** Path to audit log. Default: ~/.secretless-ai/broker-audit.log */
  auditLog?: string;
  /**
   * Path to the broker authentication token file. Default: ~/.secretless-ai/broker.token.
   * Overridable so isolated broker instances (e.g. tests) do not write to — and on stop
   * delete — the shared machine-wide token of a real running broker.
   */
  tokenFile?: string;
}

/** Credential resolution request from an agent. */
export interface ResolveRequest {
  /** Agent identifier (verified against AIM if configured). */
  agentId: string;
  /** Name of the credential to resolve. */
  credentialName: string;
}

/** Credential resolution response. */
export interface ResolveResponse {
  /** Resolved credential value. */
  value: string;
  /** Seconds until this credential should be re-fetched. */
  expiresIn?: number;
}

/** Policy rule for credential access control. */
export interface PolicyRule {
  /** Unique rule identifier. */
  id: string;
  /** Glob pattern matching agent IDs (e.g., "scan-*", "deploy-agent"). */
  agentSelector: string;
  /** Glob pattern matching credential names (e.g., "GITHUB_*", "AWS_*"). */
  credentialSelector: string;
  /** Access constraints applied when the rule matches. */
  constraints: PolicyConstraints;
  /** Whether this rule allows or denies access. */
  effect: 'allow' | 'deny';
}

/** Constraints attached to a policy rule. */
export interface PolicyConstraints {
  /** Time window during which access is permitted (24h format, e.g., "09:00"-"17:00"). */
  timeWindow?: { start: string; end: string };
  /** Maximum credential resolutions per minute. */
  rateLimit?: { maxPerMinute: number };
  /** Minimum AIM trust score required for the agent. */
  minTrustScore?: number;
  /** AIM capability the agent must possess. */
  requireCapability?: string;
  // No `scopeCheck`. It was documented as "block if credential scope has
  // expanded beyond baseline" and could not block: the enforcement path
  // compared an empty current-permission list against the baseline, so
  // expansion was false for every baseline. The key is refused at policy load
  // rather than accepted and not applied — see UNENFORCED_CONSTRAINT_KEYS in
  // ./policy. Reinstating it means implementing live permission discovery
  // first, and the type should stay silent about it until then.
}

/**
 * The reason codes of a grant record (an {@link AuditEntry} with `eventType` "grant"), a closed
 * set. A code names the check that decided. No text from the agent, the operation, a provider or
 * the downstream reaches the signed record through `reason`, and no exception text does.
 */
export const GRANT_AUDIT_REASONS = [
  // The ATX did not verify, by the verifier's reject category.
  'atx-unsupported-version',
  'atx-expired',
  'atx-revoked',
  'atx-untrusted-issuer',
  'atx-signature-invalid',
  'atx-malformed',
  // The ATX did not verify, with no reject category or one this build does not know.
  'atx-rejected',
  // The verifier threw.
  'atx-verifier-error',
  'aim-agent-unverified',
  'aim-lookup-error',
  'grant-reference-invalid',
  // The grant policy denied, by the predicate that decided.
  'policy-no-binding',
  'policy-capabilities-unsigned',
  'policy-no-capability-list',
  'policy-trust-class-missing',
  'policy-trust-level-not-number',
  'policy-trust-level-below-minimum',
  'policy-oasb-level-absent',
  'policy-oasb-level-unrankable',
  'policy-oasb-level-below-floor',
  // The grant policy denied without naming a predicate this build knows.
  'policy-denied',
  'policy-error',
  'provider-not-registered',
  'provider-mode-unsupported',
  'provider-error',
  'provider-returned-no-credential',
  // The operation path would leave the binding's origin; nothing was forwarded.
  'operation-path-refused',
  // The operation is outside the JSON value space, so it cannot be committed to; nothing was forwarded.
  'operation-not-canonical',
  // The operation was handed to the downstream caller, and the call failed.
  'downstream-error',
  // The operation ran, by the CPI mode that resolved its credential.
  'resolved-retrieve',
  'resolved-assume',
  'resolved-exchange',
] as const;

/** A reason code of a grant record. */
export type GrantAuditReason = (typeof GRANT_AUDIT_REASONS)[number];

/** The reason codes a grant policy evaluation names for a denial. */
export type GrantPolicyDenial = Extract<GrantAuditReason, `policy-${string}`>;

/**
 * Every reason code a broker audit record carries, a closed set: the grant codes, unchanged and in
 * their order, then the codes of the broker's other writers. A code names the component and the
 * case. `AuditLogger` writes any other value as `unparsed:<length>`, so no text from an agent, a
 * caller, AIM, a module loader or a credential backend reaches the signed record through `reason`.
 */
export const AUDIT_REASONS = [
  ...GRANT_AUDIT_REASONS,
  // AIM answered a lookup with a 4xx, by status.
  'aim-unauthorized',
  'aim-forbidden',
  'aim-not-found',
  'aim-rate-limited',
  'aim-client-error',
  // AIM did not answer the reachability probe at start.
  'aim-unreachable',
  'broker-started',
  'broker-stopping',
  // A request without the broker's bearer token, by the transport it came in on.
  'auth-refused-socket',
  'auth-refused-http',
  // The duplicate-member scanner did not load, by endpoint; the request was refused.
  'scanner-unavailable-resolve',
  'scanner-unavailable-grant',
  // A /resolve policy evaluation, by the check that decided.
  'rule-allow',
  'rule-deny',
  'rule-default-deny',
  'rule-outside-time-window',
  'rule-trust-score-no-identity',
  'rule-trust-score-below-minimum',
  'rule-capability-no-identity',
  'rule-capability-missing',
  'rule-rate-limit-exceeded',
  // A /resolve request the policy allowed: the resolver held no value, or threw.
  'credential-not-found',
  'backend-error',
  // A credential event, by its type.
  'credential-requested',
  'credential-granted',
  'credential-denied',
  'credential-expired-after-use',
  'credential-expired-unused',
  'credential-revoked',
  'credential-rotated',
  'credential-leak-detected',
] as const;

/** A reason code of a broker audit record. */
export type AuditReason = (typeof AUDIT_REASONS)[number];

/** The reason codes a `/resolve` policy evaluation names, by the check that decided. */
export type PolicyEvaluationCode = Extract<AuditReason, `rule-${string}`>;

/** Audit log entry for credential access attempts. */
export interface AuditEntry {
  /** ISO 8601 timestamp. */
  timestamp: string;
  /** Event classification (e.g., "resolve", "health", "startup"). */
  eventType: string;
  /**
   * Agent that made the request. A grant record carries the verified ATX DID once the ATX
   * verifies. Before that it carries the agent-supplied id only when the id parses as a DID (W3C
   * DID Core syntax), and otherwise the marker `unparsed:<length>`, the length in UTF-8 bytes. A
   * `resolve` record and a credential event carry the id as sent only when it is at most 128 bytes
   * and parses as a DID or as an agent name, and otherwise the marker.
   */
  agentId: string;
  /**
   * Credential that was requested. A grant record carries the grant reference only when it names
   * a configured grant, and otherwise the marker `unparsed:<length>`. A `resolve` record carries
   * the name as sent only when the resolver returned a value for it or a policy rule's
   * `credentialSelector` equals it, and otherwise the marker.
   */
  credentialName: string;
  /** Policy rule that matched (empty if no match). */
  policyId: string;
  /** Whether the request was allowed or denied. */
  result: 'allowed' | 'denied';
  /**
   * Reason for the decision: an {@link AuditReason} code, or `unparsed:<length>` for a value
   * written as one that is not. Typed `string` because records written before the codes carry a
   * description.
   */
  reason: string;
  /** Request processing time in milliseconds. */
  latencyMs: number;
  /**
   * The `jti` of the CGT minted for this resolution: 32 lowercase hex characters, or
   * `unparsed:<length>` when a provider reported one in another form. Absent when no CGT was
   * minted: Retrieve mode, or a denial before minting.
   */
  cgtJti?: string;
  /**
   * Lowercase hex SHA-256 of a fresh 32-byte salt followed by the RFC 8785 (JCS) bytes of the
   * operation as handed to the downstream caller. The salt goes to the resource with the
   * operation, and the resource keeps it beside the operation in its own record; it is never
   * written here. Absent when the downstream caller does not deliver salts, and on any denial
   * before the operation is forwarded.
   */
  operationCommitment?: string;
}

/** An audit entry as a writer hands it to `AuditLogger.log`: its reason is a code. */
export type CodedAuditEntry = Omit<AuditEntry, 'reason'> & { reason: AuditReason };

/** AIM agent identity information (subset of AIM API response). */
export interface AgentIdentity {
  /** Agent identifier. */
  agentId: string;
  /** Trust score from AIM (0.0 to 1.0). */
  trustScore: number;
  /** Agent capabilities registered in AIM. */
  capabilities: string[];
  /** Whether the agent is active/verified. */
  verified: boolean;
}

/** Broker health status. */
export interface BrokerHealth {
  /** Whether the broker is operational. */
  healthy: boolean;
  /** Broker uptime in seconds. */
  uptimeSeconds: number;
  /** Number of requests handled since startup. */
  requestCount: number;
  /** Whether AIM integration is configured (i.e. --aim-url was passed). */
  aimConfigured: boolean;
  /** Whether AIM responded to a reachability probe at startup. */
  aimReachable: boolean;
  /** Loaded policy rule count. */
  policyCount: number;
  /** Whether `POST /grant` is served. False: no grant resolver is configured and the route answers 404. */
  grantServed: boolean;
  /** Whether `POST /resolve` is served. False: the broker was built with `resolver: null` and the route answers 404. */
  resolveServed: boolean;
}

/** Why a broker serves no `POST /resolve`. */
export type ResolveOffReason =
  /** The embedder found no policy file to load: none named, and the default is absent. */
  | 'noPolicyFile'
  /** The embedder turned the route off, whether or not a policy file exists (the daemon's `--no-resolve`). */
  | 'disabled';

/** What a served `POST /grant` was loaded from. */
export interface GrantRouteSource {
  /** Path of the grant file. */
  file: string;
  /** Number of bindings in the file. */
  bindingCount: number;
  /** Number of providers in the file. */
  providerCount: number;
  /** The public half of the broker's assertion key, for the operator to register with each identity provider. */
  assertionPublicKeyFile: string;
  /** True when the start that loaded the file created that key, so no identity provider can trust it yet. */
  assertionKeyCreated: boolean;
}

/** `POST /grant` on `/status`. */
export type GrantRouteStatus =
  | {
      served: true;
      /** Null when the embedder passed a grant resolver without a `grantSource`. */
      source: GrantRouteSource | null;
    }
  | { served: false };

/** `POST /resolve` on `/status`. Its rule count is `policyCount`. */
export type ResolveRouteStatus =
  | {
      served: true;
      /**
       * Path of the policy file the rules were loaded from; null when that file was absent at the
       * last load (0 rules, default deny) or the rules were set in memory.
       */
      policyFile: string | null;
    }
  | { served: false; reason: ResolveOffReason };

/** The broker's capability routes. `/health` and `/status` are always served and are not listed. */
export interface BrokerRoutes {
  grant: GrantRouteStatus;
  resolve: ResolveRouteStatus;
}

/** Broker status with extended details. */
export interface BrokerStatus extends BrokerHealth {
  /** PID of the broker process. */
  pid: number;
  /** ISO 8601 start time. */
  startedAt: string;
  /** Socket path the broker is listening on. */
  socketPath: string;
  /** HTTP port the broker is listening on. */
  httpPort: number;
  /** The capability routes. */
  routes: BrokerRoutes;
}

/**
 * The status `getDaemonStatus` assembles from the PID file alone. The three live-only members
 * are absent, never defaulted: a status that does not carry them was not read from the broker.
 */
export type PidFileBrokerStatus = Omit<BrokerStatus, 'grantServed' | 'resolveServed' | 'routes'>;
