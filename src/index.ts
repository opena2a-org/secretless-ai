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
  LocalBackend, MacOSKeychainBackend, LinuxKeychainBackend,
  type SecretBackend, type WritableSecretBackend, type BackendHealth,
  type BackendType, type SelectableBackendType,
  type MigrateOptions, type MigrateResult,
} from './backends';
