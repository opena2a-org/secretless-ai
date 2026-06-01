export { init } from './init';
export { scan, type ScanFinding, type ScanOptions } from './scan';
export {
  scoreFinding, formatConfidence,
  patternSpecificity, valueEntropy, lengthTier, pathTier,
  type ConfidenceTier, type ConfidenceBreakdown, type ScoreFindingInput,
} from './confidence';
export { status, type StatusResult } from './status';
export { verify, type VerifyResult } from './verify';
export { detectAITools, toolDisplayName, type AITool } from './detect';
export { CREDENTIAL_PATTERNS, SECRET_FILE_PATTERNS, CONFIG_FILES, CREDENTIAL_PREFIX_QUICK_CHECK, type CredentialPattern } from './patterns';
export { loadSecretlessIgnore, buildMatcher, DEFAULT_IGNORE_PATTERNS, type IgnoreMatcher, type LoadOptions as IgnoreLoadOptions } from './secretlessignore';
export { cleanTranscripts, discoverTranscripts, type CleanResult, type CleanOptions, type TranscriptFinding } from './transcript';
export { startWatch, stopWatch, isWatchRunning } from './watch';
export { doctor, quickDiagnosis, fixProfiles, type DoctorOptions, type DoctorResult, type DoctorFinding, type QuickDiagnosisResult, type ProfileInfo, type FixResult, type Severity, type HealthStatus } from './doctor';

// MCP protection
export {
  discoverMcpConfigs, classifyEnvVars, McpVault,
  protectMcp, rewriteConfig, restoreConfig,
  type McpClient, type McpConfigFile, type McpServerEntry,
  type ClassifiedEnv, type ProtectOptions, type ProtectResult,
  type RewriteResult,
} from './mcp';

// Backend management
export {
  createBackend, isKeychainAvailable, isKeychainLikely, isOnePasswordAvailable, isOnePasswordLikely,
  resolveBackendType, readBackendConfig, writeBackendConfig,
  migrateSecrets,
  LocalBackend, MacOSKeychainBackend, LinuxKeychainBackend, VaultBackend,
  type SecretBackend, type WritableSecretBackend, type BackendHealth,
  type BackendType, type SelectableBackendType, type VaultBackendConfig,
  type MigrateOptions, type MigrateResult,
} from './backends';

// Secret management
export { SecretStore, type SecretStoreOptions } from './secret-store';
export { runWithSecrets, type RunOptions } from './run';
export { parseEnvFile, importEnvFile, detectEnvFiles, type EnvEntry, type ImportResult } from './env-import';
export { parseManifest, readManifest, checkManifest, type ManifestEntry, type ManifestCheck } from './manifest';
export { runSetup, type SetupOptions, type SetupResult } from './setup';
export { installPreCommitHook, uninstallPreCommitHook, isHookInstalled } from './git-hook';
export { scanStagedFiles } from './scan-staged';

// Scope discovery
export {
  discoverScope, detectProvider, createScopeProvider,
  GCPScopeProvider, AWSScopeProvider, VaultScopeProvider,
  saveBaseline, loadBaseline, listBaselines, compareToBaseline, resetBaseline,
  type ScopeBaseline, type ScopeCheckResult, type ScopeProvider,
} from './scope';

// Shell history scanning
export {
  scanHistory, cleanHistory,
  type HistoryFinding, type HistoryScanResult, type HistoryCleanResult,
} from './history';

// Broker service
export {
  PolicyEngine, matchGlob, isWithinTimeWindow,
  RateLimiter, AuditLogger, AimClient,
  CredentialResolver, BrokerServer,
  startDaemon, stopDaemon, getDaemonStatus, isDaemonRunning,
  CredentialEventEmitter,
  type BrokerConfig, type ResolveRequest, type ResolveResponse,
  type PolicyRule, type PolicyConstraints, type PolicyEvaluation,
  type AuditEntry, type AgentIdentity,
  type BrokerHealth, type BrokerStatus,
  type ResolverOptions, type DaemonOptions,
  type CredentialEvent, type CredentialEventType, type AlertLevel,
} from './broker';

// Phantom references (secret:// URI scheme)
export {
  parseSecretRef, isSecretRef, findSecretRefs, buildSecretRef,
  resolveRef, resolveEnvRefs, RefResolutionError,
  type SecretRef, type SecretBackend as PhantomBackend,
  type ResolveResult, type ResolveError,
} from './phantom';

// AAP grant references (grant:// scheme — abstract, no backend topology)
export {
  isGrantRef, parseGrantRef, buildGrantRef, GRANT_SCHEME, type GrantRef,
} from './grant';

// AAP (Agent Authorization Protocol) — verifier, grant policy, CPI providers, resolver
export {
  LocalAtxVerifier, canonicalPayload, normalizeRfc3339, SUPPORTED_ATX_VERSION,
  GrantPolicy, EphemeralWorker, HttpsDownstreamCaller, GrantResolver,
  ExchangeProvider, HttpsTokenExchangeTransport, createOktaExchangeProvider,
  MapProviderRegistry, mintBrokerAssertion, generateBrokerSigningKey, brokerPublicJwk,
  RetrieveProvider, AssumeProvider,
  TOKEN_EXCHANGE_GRANT_TYPE, SUBJECT_TOKEN_TYPE_JWT, REQUESTED_TOKEN_TYPE_ACCESS,
  type Atx, type AtxSignature, type AtxPublicKey, type AtxTrustAnchors,
  type AtxVerifier, type AtxVerificationResult, type ResolutionContext, type RejectCategory,
  type GrantBinding, type GrantMatch, type GrantEvaluation,
  type AgentOperation, type OperationResult, type DownstreamCaller,
  type GrantResolverDeps, type GrantResolveInput, type GrantResolveOutcome, type TypedDenial,
  type CpiMode, type ResourceBinding, type ScopedCredential,
  type CredentialProvider, type ProviderRegistry,
  type ExchangeProviderConfig, type TokenExchangeRequest, type TokenExchangeResponse,
  type TokenExchangeTransport, type OktaAdapterOptions, type BrokerSigningKey,
} from './broker';

// Identity Vault (requires @opena2a/aim-core)
export {
  vaultInit, vaultRegister, vaultList, vaultRotate, vaultRevoke,
  vaultAudit, vaultScan, vaultExec, vaultTest, vaultMigrate,
  loadAimCoreVault, loadAimCoreIdentity, getOrCreateAgent, getVaultStore,
  PATHS as VAULT_PATHS,
} from './vault-core';

// Session management
export {
  readSessionState, writeSessionState, getSessionStatus,
  isSessionWarm, clearSessionState, getSessionFilePath,
  DEFAULT_SESSION_TTL_SECONDS, MAX_SESSION_TTL_SECONDS,
  warmSession, isMacOS, isTouchIDAvailable,
  warm, preloadCache,
  installDaemon, uninstallDaemon, isDaemonInstalled,
  hookCheck, runHookCheck,
  type SessionState, type SessionStatus,
  type WarmResult, type InstallResult, type UninstallResult,
  type HookCheckResult,
} from './session';
