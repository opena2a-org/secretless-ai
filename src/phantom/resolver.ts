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
import { createBackend } from '../backends/factory';
import { readBackendConfig } from '../backends/config';
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
 * - keychain:  macOS Keychain / Linux Secret Service
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
      value = await resolveFromBackend(ref);
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
          backend: isSecretRef(value)
            ? parseSecretRef(value).backend
            : undefined,
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

/** Resolve from environment variables. */
function resolveFromEnv(ref: SecretRef): string | undefined {
  return process.env[ref.path];
}

/** Resolve from the local encrypted SecretStore. */
async function resolveFromLocal(ref: SecretRef): Promise<string | undefined> {
  const store = new SecretStore();
  return store.getSecret(ref.path);
}

/** Resolve from a configured backend (keychain, vault, 1password). */
async function resolveFromBackend(ref: SecretRef): Promise<string | undefined> {
  const configuredBackend = readBackendConfig();
  let backend: WritableSecretBackend;

  try {
    // Use the ref's backend type, not the configured default
    backend = createBackend(ref.backend as any);
  } catch {
    // Backend not available (e.g., 1password CLI not installed).
    // Try the configured backend as fallback — which can be unavailable too,
    // and now throws when it is. Both unreachable means this ref cannot be
    // resolved, which is `undefined`: resolveRef() turns that into a
    // RefResolutionError naming the URI. Letting the throw escape instead
    // would replace that message with a bare backend error carrying no ref.
    try {
      backend = createBackend(configuredBackend ?? 'local');
    } catch {
      return undefined;
    }
  }

  try {
    const result = await backend.resolve(`secret/${ref.path}`);
    // resolve() returns a Record<string, string> — extract the value
    const keys = Object.keys(result);
    if (keys.length > 0) {
      return result[keys[0]];
    }
    return undefined;
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
