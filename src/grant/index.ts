/**
 * Grant references — the abstract identifier an agent emits instead of a secret.
 *
 * AAP (Agent Authorization Protocol) §4. A grant reference is `grant://name`, where
 * `name` is an opaque logical resource the agent was granted. It is DELIBERATELY less
 * expressive than `secret://backend/path` (see ../phantom): a grant reference MUST NOT
 * encode a backend, host, path, port, credential, or CPI mode. Embedding any of those
 * would leak resolution topology into the agent's reasoning context — a violation of
 * AAP Principle 4 (abstract identifiers).
 *
 * The agent emits `grant://name`; the broker maps it to a concrete resource via local
 * policy that never travels with the agent.
 */

export const GRANT_SCHEME = 'grant://';

/** A parsed grant reference. It carries a logical name and nothing else. */
export interface GrantRef {
  /** The full reference, e.g. "grant://orders-db". */
  uri: string;
  /** The logical grant name, e.g. "orders-db". */
  name: string;
}

/**
 * RFC 3986 "unreserved" characters: ALPHA / DIGIT / "-" / "." / "_" / "~".
 * A grant name is restricted to these so it cannot smuggle a path ("/"),
 * authority ("@", ":"), query ("?"), or fragment ("#") — i.e. no backend topology.
 */
const GRANT_NAME_RE = /^[A-Za-z0-9._~-]+$/;

/** True if the string is syntactically a grant reference. */
export function isGrantRef(value: string): boolean {
  if (!value.startsWith(GRANT_SCHEME)) return false;
  const name = value.slice(GRANT_SCHEME.length);
  return GRANT_NAME_RE.test(name);
}

/**
 * Parse a grant reference into its logical name.
 *
 * Throws if the reference encodes anything beyond an opaque name — a host, port,
 * path, userinfo, query, or fragment. This is the lock-in that keeps backend
 * topology out of the agent context.
 */
export function parseGrantRef(uri: string): GrantRef {
  if (typeof uri !== 'string' || !uri.startsWith(GRANT_SCHEME)) {
    throw new Error(`Not a grant reference: expected "${GRANT_SCHEME}name"`);
  }
  const name = uri.slice(GRANT_SCHEME.length);
  if (name.length === 0) {
    throw new Error('Grant reference has an empty name');
  }
  if (!GRANT_NAME_RE.test(name)) {
    // Any '/', ':', '@', '?', '#', etc. lands here — a grant must never carry a backend.
    throw new Error(
      `Invalid grant name "${name}": a grant reference names a logical resource only ` +
        `(RFC 3986 unreserved chars), never a backend, host, path, or port`,
    );
  }
  return { uri, name };
}

/**
 * Build a grant reference from a logical name. Refuses to build one that would
 * encode backend topology, so callers cannot accidentally construct a leaky ref.
 */
export function buildGrantRef(name: string): string {
  if (!GRANT_NAME_RE.test(name)) {
    throw new Error(
      `Cannot build grant reference: name "${name}" must be RFC 3986 unreserved chars only`,
    );
  }
  return `${GRANT_SCHEME}${name}`;
}
