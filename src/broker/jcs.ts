/**
 * JSON Canonicalization Scheme (JCS), RFC 8785, over the JSON value space: objects, arrays,
 * strings, finite numbers, booleans and null.
 *
 * Object members are sorted by the UTF-16 code units of their names (section 3.2.3), strings and
 * numbers are serialized as ECMAScript's JSON.stringify serializes them (sections 3.2.2.2 and
 * 3.2.2.3), and no whitespace is emitted (section 3.2.1). A value outside that space throws:
 * undefined, a function, a symbol, a bigint, NaN or an infinity, a lone surrogate, an object that
 * is not a plain object or array, an array hole, a cycle. JSON.stringify would drop or convert
 * some of these; a value whose canonical form is in doubt cannot be committed to.
 *
 * The thrown messages are fixed text and never quote the value.
 */

/** Matches a UTF-16 surrogate that is not half of a pair. */
const LONE_SURROGATE = /\p{Cs}/u;

/** The RFC 8785 serialization of `value`. Encode it as UTF-8 for the canonical bytes. */
export function canonicalizeJson(value: unknown): string {
  return serialize(value, new Set());
}

function serialize(value: unknown, open: Set<object>): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('JCS: NaN and Infinity have no JSON form (RFC 8785 section 3.2.2.3)');
      }
      // ECMAScript Number serialization, with -0 written as 0 (RFC 8785 Appendix B).
      return JSON.stringify(value);
    case 'string':
      return serializeString(value);
    case 'object':
      break;
    default:
      throw new Error('JCS: the value is not a JSON value');
  }

  const object = value as object;
  if (open.has(object)) throw new Error('JCS: a cyclic value has no JSON form');
  open.add(object);
  try {
    const proto: unknown = Object.getPrototypeOf(object);
    if (Array.isArray(object) && proto === Array.prototype) {
      const items: string[] = [];
      for (let i = 0; i < object.length; i += 1) {
        if (!(i in object)) throw new Error('JCS: an array hole has no JSON form');
        items.push(serialize(object[i], open));
      }
      return `[${items.join(',')}]`;
    }
    if (proto !== Object.prototype && proto !== null) {
      throw new Error('JCS: only plain objects and arrays have a JSON form here');
    }
    const members = object as Record<string, unknown>;
    // The default sort compares UTF-16 code units, which is the order section 3.2.3 requires.
    const names = Object.keys(members).sort();
    return `{${names
      .map((name) => `${serializeString(name)}:${serialize(members[name], open)}`)
      .join(',')}}`;
  } finally {
    open.delete(object);
  }
}

function serializeString(value: string): string {
  if (LONE_SURROGATE.test(value)) {
    throw new Error('JCS: a lone surrogate is not Unicode text (RFC 8785 section 3.2.2.2)');
  }
  // For well-formed text JSON.stringify escapes exactly what section 3.2.2.2 lists: the quote, the
  // backslash, and U+0000 to U+001F, as \b \t \n \f \r or lowercase \u00hh.
  return JSON.stringify(value);
}
