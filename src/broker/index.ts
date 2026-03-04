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
