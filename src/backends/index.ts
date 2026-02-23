export type { SecretBackend, WritableSecretBackend, BackendHealth, BackendConfig, BackendType, AccessAuditEntry } from './types';
export { LocalBackend } from './local';
export { MacOSKeychainBackend } from './keychain-macos';
export { LinuxKeychainBackend } from './keychain-linux';
export { createBackend, isKeychainAvailable } from './factory';
export { readBackendConfig, writeBackendConfig, resolveBackendType, type SelectableBackendType } from './config';
export { migrateSecrets, type MigrateOptions, type MigrateResult } from './migrate';
