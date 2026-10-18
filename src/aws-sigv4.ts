/**
 * AWS Signature Version 4, for the one request `scan --check-validity` sends
 * to AWS: STS GetCallerIdentity, signed with a found secret access key.
 *
 * The secret access key keys an HMAC chain and goes in no header, path or
 * body. What the request carries is the access key ID, in the Credential
 * field of the Authorization header, and the signature. The steps are the
 * ones AWS documents: a canonical request; a string to sign over the
 * request's SHA-256 hash, the request time and the credential scope; a
 * signing key derived from the secret, the date, the region and the service;
 * and the signature, an HMAC of the string to sign under that key.
 */
import { createHash, createHmac } from 'crypto';

export interface SigV4Request {
  method: 'GET' | 'POST';
  /** The host the request is sent to; signed as the `host` header. */
  host: string;
  /** The canonical URI: an absolute path, already encoded. The request has no query. */
  path: string;
  /** Headers to sign beside host and x-amz-date, with the values the request sends. */
  headers: Readonly<Record<string, string>>;
  body: string;
  region: string;
  service: string;
}

export interface SigV4Key {
  accessKeyId: string;
  secretAccessKey: string;
}

/** The headers a signed request adds to the ones it signs. */
export interface SigV4Headers {
  'X-Amz-Date': string;
  Authorization: string;
}

const ALGORITHM = 'AWS4-HMAC-SHA256';

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function hmac(key: string | Buffer, text: string): Buffer {
  return createHmac('sha256', key).update(text, 'utf8').digest();
}

/** The request time as Signature Version 4 writes it, for example 20150830T123600Z. */
export function amzDate(now: Date): string {
  return now.toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
}

/** The names of the signed headers, lower-case and in name order, and the canonical request over them. */
function canonicalParts(request: SigV4Request, date: string): { signedHeaders: string; canonical: string } {
  const all: Record<string, string> = { host: request.host, 'x-amz-date': date };
  for (const [name, value] of Object.entries(request.headers)) all[name.toLowerCase()] = value;
  const names = Object.keys(all).sort();
  const headers = names.map((name) => `${name}:${all[name].trim().replace(/\s+/g, ' ')}\n`).join('');
  const signedHeaders = names.join(';');
  return { signedHeaders, canonical: [request.method, request.path, '', headers, signedHeaders, sha256Hex(request.body)].join('\n') };
}

/**
 * The canonical request: method, path, an empty query, the signed headers
 * with lower-case names in name order and each value trimmed with inner runs
 * of whitespace made one space, their names, and the body's SHA-256 hash.
 */
export function canonicalRequest(request: SigV4Request, date: string): string {
  return canonicalParts(request, date).canonical;
}

/** The X-Amz-Date and Authorization headers for a request signed at `now`. */
export function signSigV4(request: SigV4Request, key: SigV4Key, now: Date): SigV4Headers {
  const date = amzDate(now);
  const day = date.slice(0, 8);
  const scope = `${day}/${request.region}/${request.service}/aws4_request`;
  const { signedHeaders, canonical } = canonicalParts(request, date);
  const stringToSign = [ALGORITHM, date, scope, sha256Hex(canonical)].join('\n');
  let signingKey = hmac(`AWS4${key.secretAccessKey}`, day);
  for (const part of [request.region, request.service, 'aws4_request']) signingKey = hmac(signingKey, part);
  const signature = hmac(signingKey, stringToSign).toString('hex');
  return {
    'X-Amz-Date': date,
    Authorization: `${ALGORITHM} Credential=${key.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}
