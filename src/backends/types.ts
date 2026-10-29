/**
 * Pluggable secret backend interface.
 * Each backend resolves secrets from a different source.
 * Zero mandatory deps — backend SDKs are optional peer dependencies.
 */
export interface SecretBackend {
  /** Backend name (e.g., "vault", "aws-sm", "env") */
  readonly name: string;

  /** Resolve one or more secrets by path/name. Returns key-value pairs. `options.exact` narrows the read to the one entry at `path` (ResolveOptions). */
  resolve(path: string, options?: ResolveOptions): Promise<Record<string, string>>;

  /** Check if the backend is available and authenticated */
  healthCheck(): Promise<BackendHealth>;
}

/** How `resolve` is to read its path. */
export interface ResolveOptions {
  /**
   * The path names one entry, not a prefix: the caller wants that entry or
   * nothing. Every backend honors it. `resolve(path, { exact: true })`
   * returns `{ [path]: value }` when an entry is stored under exactly
   * `path`, and `{}` otherwise; it reads the value of no other entry. A
   * backend that addresses an entry by its key sends no list request
   * (Vault answers a 404 with `{}` and no LIST, #375; gcp-sm reads the one
   * secret the key is stored under; local and the keychains filter their
   * index to the key). A backend that finds an entry only through a
   * listing of names (1Password) lists names and reads one value. The
   * cache layer serves an exact read only from the entry cached at `path`
   * and passes the option to the backend it wraps. Without the option the
   * path is a prefix: the entry at `path` and every entry under `path/`.
   */
  exact?: boolean;
}

/**
 * A secret backend that also supports writing and deleting secrets.
 * LocalBackend and keychain backends implement this interface.
 */
export interface WritableSecretBackend extends SecretBackend {
  /** Store a single secret by key. */
  store(key: string, value: string): Promise<void>;

  /** Delete a secret by key. Returns true if the key existed. */
  delete(key: string): Promise<boolean>;
}

export interface BackendHealth {
  healthy: boolean;
  latencyMs: number;
  message?: string;
}

/** Backend configuration from secretless config file */
export interface BackendConfig {
  /** Backend type */
  type: BackendType;
  /** Backend-specific config */
  config?: Record<string, unknown>;
  /** Priority (lower = preferred, default: 100) */
  priority?: number;
  /** Path prefix this backend handles (e.g., "vault/", "aws/") */
  prefix?: string;
}

export type BackendType = 'env' | 'local' | 'keychain' | 'vault' | 'aws-sm' | 'gcp-sm' | '1password';

/** Access audit entry */
export interface AccessAuditEntry {
  timestamp: string;
  backend: string;
  path: string;
  action: 'resolve' | 'healthCheck' | 'migrate' | 'store' | 'delete';
  success: boolean;
  latencyMs: number;
}
