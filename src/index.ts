export { init } from './init';
export { scan, type ScanFinding, type ScanOptions } from './scan';
export { status, type StatusResult } from './status';
export { verify, type VerifyResult } from './verify';
export { detectAITools, toolDisplayName, type AITool } from './detect';
export { CREDENTIAL_PATTERNS, SECRET_FILE_PATTERNS, CONFIG_FILES, CREDENTIAL_PREFIX_QUICK_CHECK, type CredentialPattern } from './patterns';
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
  createBackend, isKeychainAvailable,
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
  type BrokerConfig, type ResolveRequest, type ResolveResponse,
  type PolicyRule, type PolicyConstraints, type PolicyEvaluation,
  type AuditEntry, type AgentIdentity,
  type BrokerHealth, type BrokerStatus,
  type ResolverOptions, type DaemonOptions,
} from './broker';
