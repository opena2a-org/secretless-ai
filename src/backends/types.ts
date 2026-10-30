/**
 * Pluggable secret backend interface.
 * Each backend resolves secrets from a different source.
 * Zero mandatory deps — backend SDKs are optional peer dependencies.
 */
export interface SecretBackend {
  /** Backend name (e.g., "vault", "aws-sm", "env") */
  readonly name: string;

  /** Resolve one or more secrets by path/name. Returns key-value pairs. `options.exact` narrows the result to the one entry at `path` (ResolveOptions). */
  resolve(path: string, options?: ResolveOptions): Promise<Record<string, string>>;

  /** Check if the backend is available and authenticated */
  healthCheck(): Promise<BackendHealth>;

  /**
   * The store this backend reads and the identity of the credential it reads
   * it with, as tagged lines, for the value cache's scope (`cacheScope` in
   * cache.ts). A credential is given as its SHA-256, never as itself. File
   * and environment reads only: no request, no prompt. Never logged or
   * printed. A backend without it is scoped by its kind alone.
   */
  describeStore?(): StoreScopeLine[];
}

/** One tagged line a backend names for the value cache's scope. */
export type StoreScopeLine = readonly [tag: string, value: string];

/** How `resolve` is to read its path. */
export interface ResolveOptions {
  /**
   * The path names one entry, not a prefix: the caller wants that entry or
   * nothing. Every backend honors it. `resolve(path, { exact: true })`
   * returns `{ [path]: value }` when an entry is stored under exactly
   * `path`, and `{}` otherwise. A backend that addresses an entry by its
   * key reads that entry alone and sends no list request (Vault answers a
   * 404 with `{}` and no LIST, #375; gcp-sm reads the one secret the key is
   * stored under; the keychains filter their index to the key and look up
   * that entry). A backend that finds an entry only through a listing of
   * names (1Password) lists names and reads the items carrying that title.
   * The local store is one encrypted file, decrypted whole for any read, so
   * there the option narrows the result, not the read. The cache layer
   * serves an exact read only from the entry cached at `path` and passes
   * the option to the backend it wraps. Without the option the path is a
   * prefix: the entry at `path` and every entry under `path/`, except that
   * Vault answers a path that holds an entry with that entry alone, and
   * gcp-sm reads a `secret/NAME` path as one entry.
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
