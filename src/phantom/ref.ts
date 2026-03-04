/**
 * Phantom credential reference — the secret:// URI scheme.
 *
 * Phantom references are safe to include in LLM context windows because they
 * contain no credential values. The broker resolves them at execution time.
 *
 * Format: secret://backend/path?scope=read&ttl=300
 *
 * Examples:
 *   secret://keychain/prod-db-password
 *   secret://vault/secret/data/prod/api-key
 *   secret://1password/op://Personal/prod-server/password
 *   secret://env/ANTHROPIC_API_KEY
 *   secret://local/my-secret-name
 */

/** Supported secret backends for phantom references. */
export type SecretBackend = 'keychain' | 'vault' | '1password' | 'env' | 'local';

/** Parsed phantom credential reference. */
export interface SecretRef {
  /** The full URI string (e.g., "secret://keychain/prod-db"). */
  uri: string;
  /** Backend to resolve from (e.g., "keychain", "vault", "env"). */
  backend: SecretBackend;
  /** Path within the backend (e.g., "prod-db-password"). */
  path: string;
  /** Optional scope restriction (e.g., "read", "write"). */
  scope?: string;
  /** Optional TTL override in seconds. */
  ttlSeconds?: number;
  /** Optional capability requirement. */
  capability?: string;
}

/** Regex that matches a secret:// URI in text. */
const SECRET_REF_PATTERN = /secret:\/\/([a-z0-9]+)\/([^\s?#]+)(\?[^\s#]*)?/g;

/** Valid backend names. */
const VALID_BACKENDS = new Set<string>(['keychain', 'vault', '1password', 'env', 'local']);

/**
 * Parse a secret:// URI into a SecretRef.
 * Throws if the URI is malformed or uses an unknown backend.
 */
export function parseSecretRef(uri: string): SecretRef {
  if (!uri.startsWith('secret://')) {
    throw new Error(`Invalid secret reference: must start with "secret://". Got: "${uri}"`);
  }

  const withoutScheme = uri.slice('secret://'.length);
  const questionIndex = withoutScheme.indexOf('?');

  const pathPart = questionIndex >= 0
    ? withoutScheme.slice(0, questionIndex)
    : withoutScheme;

  const queryString = questionIndex >= 0
    ? withoutScheme.slice(questionIndex + 1)
    : '';

  const slashIndex = pathPart.indexOf('/');
  if (slashIndex < 0) {
    throw new Error(`Invalid secret reference: missing path after backend. Got: "${uri}"`);
  }

  const backend = pathPart.slice(0, slashIndex);
  const secretPath = pathPart.slice(slashIndex + 1);

  if (!VALID_BACKENDS.has(backend)) {
    throw new Error(
      `Unknown backend "${backend}". Valid backends: ${Array.from(VALID_BACKENDS).join(', ')}`,
    );
  }

  if (!secretPath) {
    throw new Error(`Invalid secret reference: empty path. Got: "${uri}"`);
  }

  // Parse query parameters
  const params = parseQueryString(queryString);

  const ref: SecretRef = {
    uri,
    backend: backend as SecretBackend,
    path: secretPath,
  };

  if (params.scope) ref.scope = params.scope;
  if (params.ttl) {
    const ttl = parseInt(params.ttl, 10);
    if (!isNaN(ttl) && ttl > 0) ref.ttlSeconds = ttl;
  }
  if (params.capability) ref.capability = params.capability;

  return ref;
}

/**
 * Check if a string looks like a phantom credential reference.
 * Fast check — does not validate the full URI.
 */
export function isSecretRef(value: string): boolean {
  return value.startsWith('secret://');
}

/**
 * Find all phantom references in a text string.
 * Returns the matched URIs (not parsed — use parseSecretRef for full parsing).
 */
export function findSecretRefs(text: string): string[] {
  const refs: string[] = [];
  const regex = new RegExp(SECRET_REF_PATTERN);
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    refs.push(match[0]);
  }

  return refs;
}

/**
 * Build a secret:// URI from components.
 */
export function buildSecretRef(
  backend: SecretBackend,
  secretPath: string,
  options?: { scope?: string; ttlSeconds?: number; capability?: string },
): string {
  let uri = `secret://${backend}/${secretPath}`;

  const params: string[] = [];
  if (options?.scope) params.push(`scope=${encodeURIComponent(options.scope)}`);
  if (options?.ttlSeconds) params.push(`ttl=${options.ttlSeconds}`);
  if (options?.capability) params.push(`capability=${encodeURIComponent(options.capability)}`);

  if (params.length > 0) {
    uri += '?' + params.join('&');
  }

  return uri;
}

/** Parse a query string into key-value pairs. */
function parseQueryString(qs: string): Record<string, string> {
  if (!qs) return {};

  const result: Record<string, string> = {};
  for (const pair of qs.split('&')) {
    const eqIndex = pair.indexOf('=');
    if (eqIndex >= 0) {
      const key = decodeURIComponent(pair.slice(0, eqIndex));
      const value = decodeURIComponent(pair.slice(eqIndex + 1));
      result[key] = value;
    }
  }
  return result;
}
