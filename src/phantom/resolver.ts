/**
 * Phantom reference resolver — resolves secret:// URIs to credential values.
 *
 * Routes resolution requests to the appropriate backend based on the URI scheme.
 * When the broker is running, resolution goes through the broker (policy-gated).
 * When the broker is not available, resolves directly (local-only fallback).
 *
 * IMPORTANT: Resolved values must NEVER be returned to LLM context.
 * This resolver is used by `secretless-ai run` to inject into subprocesses.
 */

import { parseSecretRef, isSecretRef, type SecretRef, type SecretBackend } from './ref';
import { SecretStore } from '../secret-store';
import { createBackend, hasKeychainImplementation, UnreachableBackendError } from '../backends/factory';
import type { WritableSecretBackend } from '../backends/types';

export interface ResolveResult {
  /** The resolved credential value (never empty on success). */
  value: string;
  /** Which backend was used to resolve. */
  backend: SecretBackend;
  /** Time to resolve in milliseconds. */
  resolveTimeMs: number;
}

export interface ResolveError {
  /** Error message. */
  message: string;
  /** The secret reference that failed. */
  ref: string;
  /** The backend that was attempted. */
  backend?: SecretBackend;
}

/**
 * Resolve a secret:// URI to a credential value.
 *
 * Resolution order per backend:
 * - env:       process.env[path]
 * - local:     SecretStore (AES-256-GCM encrypted local storage)
 * - keychain:  macOS Keychain / Linux Secret Service; refused on a platform
 *              with neither, where the local store is not read in its place
 * - vault:     HashiCorp Vault HTTP API
 * - 1password: 1Password CLI
 */
export async function resolveRef(uri: string): Promise<ResolveResult> {
  const startTime = Date.now();
  const ref = parseSecretRef(uri);

  let value: string | undefined;

  switch (ref.backend) {
    case 'env':
      value = resolveFromEnv(ref);
      break;
    case 'local':
      value = await resolveFromLocal(ref);
      break;
    case 'keychain':
    case 'vault':
    case '1password':
      value = await resolveFromBackend(ref, uri);
      break;
  }

  if (value === undefined) {
    throw new RefResolutionError(`Secret not found: ${uri}`, uri, ref.backend);
  }

  return {
    value,
    backend: ref.backend,
    resolveTimeMs: Date.now() - startTime,
  };
}

/**
 * Resolve all secret:// URIs in an environment variable map.
 * Non-secret values are passed through unchanged.
 *
 * @param env - Environment variables (name -> value, where value may be a secret:// URI)
 * @returns Resolved environment variables with secret values filled in
 */
export async function resolveEnvRefs(
  env: Record<string, string>,
): Promise<{ resolved: Record<string, string>; errors: ResolveError[] }> {
  const resolved: Record<string, string> = {};
  const errors: ResolveError[] = [];

  for (const [key, value] of Object.entries(env)) {
    if (isSecretRef(value)) {
      try {
        const result = await resolveRef(value);
        resolved[key] = result.value;
      } catch (err) {
        errors.push({
          message: err instanceof Error ? err.message : String(err),
          ref: value,
          backend: refBackend(value),
        });
        // Keep the reference as-is on failure (don't silently drop env vars)
        resolved[key] = value;
      }
    } else {
      resolved[key] = value;
    }
  }

  return { resolved, errors };
}

/**
 * The backend a reference names, or undefined when the reference does not
 * parse. The catch in resolveEnvRefs asked parseSecretRef for the backend a
 * second time, so a reference the parser refuses threw again from inside the
 * catch and rejected the whole call instead of being recorded in `errors`
 * (#387).
 */
function refBackend(uri: string): SecretBackend | undefined {
  try {
    return parseSecretRef(uri).backend;
  } catch {
    return undefined;
  }
}

/** Resolve from environment variables. */
function resolveFromEnv(ref: SecretRef): string | undefined {
  return process.env[ref.path];
}

/** Resolve from the local encrypted SecretStore. */
async function resolveFromLocal(ref: SecretRef): Promise<string | undefined> {
  const store = new SecretStore();
  return store.getSecret(ref.path);
}

/** Resolve from the backend the reference names (keychain, vault, 1password). */
async function resolveFromBackend(ref: SecretRef, uri: string): Promise<string | undefined> {
  let backend: WritableSecretBackend;
  const unreachable = (reason: string): RefResolutionError =>
    new RefResolutionError(
      `Backend "${ref.backend}" named by ${uri} is not reachable${reason}. No other store was read in its place.`,
      uri,
      ref.backend,
    );

  // On a platform with no OS keychain implementation the factory builds the
  // local encrypted file for `keychain`. The reference is refused before the
  // factory is asked: that file answered it with its own value for the same
  // name, reported as the keychain's (#376).
  if (ref.backend === 'keychain' && !hasKeychainImplementation()) {
    throw unreachable(`: OS keychain is not supported on ${process.platform}`);
  }

  try {
    // Use the ref's backend type, not the configured default. It is named for
    // this one read, so unless it is the store this machine uses anyway it is
    // built without the value cache. That file is shared and keyed by entry
    // name alone: behind it, a value read from a second store was served as
    // the configured backend's for the same name, and a value the configured
    // backend had cached answered the reference in the named backend's
    // place (#369).
    backend = createBackend(ref.backend as any, undefined, true, { role: 'named' });
  } catch (err) {
    // Backend not available (e.g., VAULT_ADDR unset, 1password CLI not
    // installed). The configured backend is not asked in its place: it
    // answered with its own value for the same name, reported as the named
    // backend's, which is the substitution `createBackend` refuses for a
    // configured backend (#372). The error names the URI, so a caller of
    // resolveEnvRefs can tell which reference failed, and the reason, without
    // the `--backend` wording of the factory's message.
    throw unreachable(err instanceof UnreachableBackendError ? `: ${err.reason}` : '');
  }

  const key = `secret/${ref.path}`;
  try {
    // The reference names one entry, so it is asked as an exact read and only
    // the value under its own key answers it. resolve() also returns entries
    // stored under `key/`: Vault lists the path as a prefix when it holds no
    // entry there, and the first entry of that listing answered the reference
    // with a different secret's value (#383).
    const result = await backend.resolve(key, { exact: true });
    return Object.prototype.hasOwnProperty.call(result, key) ? result[key] : undefined;
  } catch {
    return undefined;
  }
}

/** Custom error class for resolution failures. */
export class RefResolutionError extends Error {
  readonly ref: string;
  readonly backend?: SecretBackend;

  constructor(message: string, ref: string, backend?: SecretBackend) {
    super(message);
    this.name = 'RefResolutionError';
    this.ref = ref;
    this.backend = backend;
  }
}
