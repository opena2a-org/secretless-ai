export type {
  BrokerConfig,
  ResolveRequest,
  ResolveResponse,
  PolicyRule,
  PolicyConstraints,
  AuditEntry,
  AgentIdentity,
  BrokerHealth,
  BrokerStatus,
} from './types';

export { PolicyEngine, matchGlob, isWithinTimeWindow, type PolicyEvaluation } from './policy';
export { RateLimiter } from './rate-limiter';
export { AuditLogger } from './audit';
export { AimClient } from './aim-client';
export { CredentialResolver, type ResolverOptions } from './resolver';
export { BrokerServer } from './server';
export {
  startDaemon,
  stopDaemon,
  getDaemonStatus,
  isDaemonRunning,
  type DaemonOptions,
} from './daemon';

export {
  CredentialEventEmitter,
  type CredentialEvent,
  type CredentialEventType,
  type AlertLevel,
} from './events';

// AAP (Agent Authorization Protocol) — grant-based authorization layer.
//
// The ATX verifier was extracted to @opena2a/atx-verify (the single
// spec-compliant implementation, shared with the AIM SDK). secretless
// re-exports its TYPES only: types are erased at compile, so they cross the
// CJS→ESM-only package boundary for free, and secretless's own public surface
// (GrantResolverDeps.verifier: AtxVerifier, GrantResolveInput.atx: Atx) needs
// them. Callers wanting the VALUES (LocalAtxVerifier, canonicalPayload,
// normalizeRfc3339, SUPPORTED_ATX_VERSION) import them from @opena2a/atx-verify
// directly — a CJS package cannot statically re-export ESM-only values.
export type {
  Atx,
  AtxSignature,
  AtxPublicKey,
  AtxTrustAnchors,
  AtxVerifier,
  AtxVerificationResult,
  ResolutionContext,
  RejectCategory,
} from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
export {
  GrantPolicy,
  type GrantBinding,
  type GrantMatch,
  type GrantEvaluation,
} from './grant-policy';
export {
  EphemeralWorker,
  HttpsDownstreamCaller,
  type AgentOperation,
  type OperationResult,
  type DownstreamCaller,
} from './worker';
export {
  GrantResolver,
  type GrantResolverDeps,
  type GrantResolveInput,
  type GrantResolveOutcome,
  type TypedDenial,
} from './grant-resolver';
export * from './cpi';
