/**
 * Credential scope discovery types.
 *
 * Defines the data structures for tracking what permissions a credential has,
 * comparing against stored baselines, and detecting scope expansion (drift).
 */

/** Snapshot of a credential's effective permissions at a point in time. */
export interface ScopeBaseline {
  /** Name of the credential (e.g., "GOOGLE_SERVICE_ACCOUNT") */
  credentialName: string;
  /** Cloud/identity provider (e.g., "gcp", "vault", "aws") */
  provider: string;
  /** List of permissions the credential holds */
  permissions: string[];
  /** ISO 8601 timestamp of when this baseline was captured */
  checkedAt: string;
  /** Permissions from the previous baseline (for historical diff) */
  previousPermissions?: string[];
}

/** Result of comparing current permissions against a stored baseline. */
export interface ScopeCheckResult {
  /** Name of the credential */
  credentialName: string;
  /** Cloud/identity provider */
  provider: string;
  /** Permissions currently held by the credential */
  currentPermissions: string[];
  /** Permissions from the stored baseline */
  baselinePermissions: string[];
  /** Permissions added since baseline */
  added: string[];
  /** Permissions removed since baseline */
  removed: string[];
  /** True if any permissions were added since baseline */
  hasExpanded: boolean;
  /** ISO 8601 timestamp */
  checkedAt: string;
  /** Provider-specific metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Interface for cloud/identity providers that can discover credential scopes.
 * Each provider implements this to inspect what permissions a credential has.
 */
export interface ScopeProvider {
  /** Provider identifier (e.g., "gcp", "vault") */
  readonly name: string;
  /** Discover the effective permissions of a credential. */
  discover(credential: string): Promise<string[]>;
  /** Check if the provider is reachable and the credential is valid. */
  healthCheck(): Promise<boolean>;
}
