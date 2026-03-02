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
  /** Path to policy file. Default: ~/.secretless-ai/broker-policies.json */
  policyFile?: string;
  /** Path to audit log. Default: ~/.secretless-ai/broker-audit.log */
  auditLog?: string;
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
  /** Block if credential scope has expanded beyond baseline. */
  scopeCheck?: boolean;
}

/** Audit log entry for credential access attempts. */
export interface AuditEntry {
  /** ISO 8601 timestamp. */
  timestamp: string;
  /** Event classification (e.g., "resolve", "health", "startup"). */
  eventType: string;
  /** Agent that made the request. */
  agentId: string;
  /** Credential that was requested. */
  credentialName: string;
  /** Policy rule that matched (empty if no match). */
  policyId: string;
  /** Whether the request was allowed or denied. */
  result: 'allowed' | 'denied';
  /** Human-readable reason for the decision. */
  reason: string;
  /** Request processing time in milliseconds. */
  latencyMs: number;
}

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
  /** Whether AIM integration is available. */
  aimConnected: boolean;
  /** Loaded policy rule count. */
  policyCount: number;
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
}
