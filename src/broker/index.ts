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
export {
  LocalAtxVerifier,
  canonicalPayload,
  normalizeRfc3339,
  SUPPORTED_ATX_VERSION,
  type Atx,
  type AtxSignature,
  type AtxPublicKey,
  type AtxTrustAnchors,
  type AtxVerifier,
  type AtxVerificationResult,
  type ResolutionContext,
  type RejectCategory,
} from './atx';
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
