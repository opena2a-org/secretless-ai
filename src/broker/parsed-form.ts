/**
 * The forms in which a broker audit record writes a value it did not choose.
 *
 * A record writes such a value as given only in a parsed form. Any other value is written as the
 * marker `unparsed:<length>`, its length in UTF-8 bytes, so no text an agent or a caller chose
 * reaches the signed record through that member.
 */

/** A DID Core idchar: ALPHA / DIGIT / "." / "-" / "_" / pct-encoded. */
const ID_CHAR = '(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})';

/** A DID, by the W3C DID Core syntax: `did:` method-name `:` method-specific-id. */
export const DID = new RegExp(`^did:[a-z0-9]+:(?:${ID_CHAR}*:)*${ID_CHAR}+$`);

/** An agent name, in the character set of a grant name. */
const AGENT_NAME = /^[A-Za-z0-9._~-]+$/;

/** The longest agent id, in UTF-8 bytes, a `/resolve` or credential event record writes as given. */
const MAX_AGENT_ID_BYTES = 128;

/**
 * What the record writes for an input it will not write as given: a fixed marker and the input's
 * length in UTF-8 bytes (0 for a value that is not a string).
 */
export function unparsed(value: unknown): string {
  return `unparsed:${typeof value === 'string' ? Buffer.byteLength(value, 'utf-8') : 0}`;
}

/**
 * An agent id as a `/resolve` or credential event record writes it: as given when it is at most
 * 128 bytes and parses as a DID or as an agent name (letters, digits, `.`, `_`, `~` and `-`);
 * otherwise the marker.
 */
export function parsedAgentId(value: unknown): string {
  return typeof value === 'string' &&
    Buffer.byteLength(value, 'utf-8') <= MAX_AGENT_ID_BYTES &&
    (DID.test(value) || AGENT_NAME.test(value))
    ? value
    : unparsed(value);
}
