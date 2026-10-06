/**
 * Encrypted bundle — moves a secret store to another machine (#175).
 *
 * A store on a machine-local backend (the OS keychain, the local encrypted
 * file) cannot be copied: the only way across was `secret get` on one machine
 * and `secret set` on the other, one name at a time, through a terminal and a
 * clipboard. `export` writes the selected names and values into one file
 * encrypted under a passphrase; `import` on the other machine decrypts it and
 * stores the entries in that machine's own backend.
 *
 * Format, one line of text:
 *
 *   secretless-bundle.v1.<header>.<ciphertext>.<tag>
 *
 * Each segment is base64url. The header is JSON naming the KDF (scrypt), its
 * parameters and salt, the cipher (AES-256-GCM) and its IV. Everything else —
 * every name, value and manifest field — is inside the ciphertext. The prefix
 * and header are the GCM additional data, so a changed parameter fails
 * authentication exactly like a changed byte of ciphertext does.
 *
 * One line, and a fixed prefix, because the bundle has to be recognisable
 * wherever a copy of it lands: `clean` redacts it from a transcript and `scan`
 * flags the file by its extension. Nothing about the source machine is written:
 * no host, user, path, backend or timestamp.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import { promisify } from 'util';

const scryptAsync = promisify(crypto.scrypt) as (
  password: crypto.BinaryLike,
  salt: crypto.BinaryLike,
  keylen: number,
  options: crypto.ScryptOptions,
) => Promise<Buffer>;

/** File extension `export` requires, and the one `scan` flags. */
export const BUNDLE_EXTENSION = '.secretless-bundle';

/** Environment variable a passphrase may be read from. Never an argument. */
export const PASSPHRASE_ENV = 'SECRETLESS_EXPORT_PASSPHRASE';

/** Shortest passphrase `export` accepts. The bundle is open to offline guessing. */
export const MIN_PASSPHRASE_LENGTH = 12;

const FORMAT_PREFIX = 'secretless-bundle.';
const V1_PREFIX = `${FORMAT_PREFIX}v1.`;

/**
 * A serialized bundle, wherever it appears. Linear: the segments are separated
 * by a literal `.` that none of the character classes admit.
 */
export const BUNDLE_TOKEN = /secretless-bundle\.v\d+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

/** Largest bundle file `import` reads. */
export const MAX_BUNDLE_BYTES = 10 * 1024 * 1024;

const SEGMENT = /^[A-Za-z0-9_-]+$/;

export interface KdfParams {
  n: number;
  r: number;
  p: number;
}

/** scrypt at 128 MiB. Read back from the header, so it can be raised later. */
export const DEFAULT_KDF: KdfParams = { n: 2 ** 17, r: 8, p: 1 };

/**
 * Bounds on the parameters `import` will run. A bundle is input from another
 * machine, and its header chooses how much memory scrypt allocates; these keep
 * a hostile header from asking for gigabytes.
 */
const MIN_LOG2_N = 14;
const MAX_LOG2_N = 18;
const MAX_R = 16;
const MAX_P = 4;
const MAX_SCRYPT_MEMORY = 256 * 1024 * 1024;

export interface BundleEntry {
  name: string;
  value: string;
  /** From the exporting project's `.secretless`, when it declares this name. */
  required?: boolean;
  description?: string;
}

interface BundleHeader {
  kdf: 'scrypt';
  n: number;
  r: number;
  p: number;
  salt: string;
  cipher: 'aes-256-gcm';
  iv: string;
}

function b64u(buf: Buffer): string {
  return buf.toString('base64url');
}

function scryptMemory(kdf: KdfParams): number {
  return 128 * kdf.n * kdf.r;
}

async function deriveKey(passphrase: string, salt: Buffer, kdf: KdfParams): Promise<Buffer> {
  // NFC so the same passphrase typed on two keyboards derives the same key.
  return scryptAsync(Buffer.from(passphrase.normalize('NFC'), 'utf-8'), salt, 32, {
    N: kdf.n,
    r: kdf.r,
    p: kdf.p,
    maxmem: 2 * scryptMemory(kdf),
  });
}

/** Encrypt entries into a bundle. Returns the file content. */
export async function sealBundle(
  entries: BundleEntry[],
  passphrase: string,
  kdf: KdfParams = DEFAULT_KDF,
): Promise<string> {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const header: BundleHeader = {
    kdf: 'scrypt',
    n: kdf.n,
    r: kdf.r,
    p: kdf.p,
    salt: b64u(salt),
    cipher: 'aes-256-gcm',
    iv: b64u(iv),
  };
  const signed = V1_PREFIX + b64u(Buffer.from(JSON.stringify(header), 'utf-8'));
  const key = await deriveKey(passphrase, salt, kdf);
  const plaintext = Buffer.from(JSON.stringify({ entries }), 'utf-8');
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    cipher.setAAD(Buffer.from(signed, 'ascii'));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return `${signed}.${b64u(ciphertext)}.${b64u(cipher.getAuthTag())}\n`;
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
}

export function notABundle(detail: string): Error {
  return new Error(
    `This file is not a readable secretless bundle: ${detail}.\n\n` +
    '  Nothing was written.\n\n' +
    '  Fix:     export it again on the source machine and copy the whole file',
  );
}

function parseHeader(segment: string): BundleHeader & { saltBuf: Buffer; ivBuf: Buffer } {
  let header: Partial<BundleHeader>;
  try {
    header = JSON.parse(Buffer.from(segment, 'base64url').toString('utf-8')) as Partial<BundleHeader>;
  } catch {
    throw notABundle('its header is not valid');
  }
  if (!header || typeof header !== 'object' || header.kdf !== 'scrypt' || header.cipher !== 'aes-256-gcm') {
    throw notABundle('its header names an unsupported key derivation or cipher');
  }
  const { n, r, p } = header;
  const log2n = typeof n === 'number' ? Math.log2(n) : NaN;
  if (
    !Number.isInteger(log2n) || log2n < MIN_LOG2_N || log2n > MAX_LOG2_N
    || !Number.isInteger(r) || (r as number) < 1 || (r as number) > MAX_R
    || !Number.isInteger(p) || (p as number) < 1 || (p as number) > MAX_P
    || scryptMemory({ n: n as number, r: r as number, p: p as number }) > MAX_SCRYPT_MEMORY
  ) {
    throw notABundle('its key derivation parameters are outside the supported range');
  }
  const saltBuf = typeof header.salt === 'string' && SEGMENT.test(header.salt) ? Buffer.from(header.salt, 'base64url') : Buffer.alloc(0);
  const ivBuf = typeof header.iv === 'string' && SEGMENT.test(header.iv) ? Buffer.from(header.iv, 'base64url') : Buffer.alloc(0);
  if (saltBuf.length < 16 || ivBuf.length !== 12) {
    throw notABundle('its salt or IV is missing');
  }
  return { ...(header as BundleHeader), saltBuf, ivBuf };
}

/**
 * Decrypt a bundle. Throws before returning anything when the passphrase is
 * wrong or any byte of the file was changed — GCM authenticates the header and
 * the ciphertext together, so the two cases cannot be told apart and are not.
 */
export async function openBundle(content: string, passphrase: string): Promise<BundleEntry[]> {
  const text = content.trim();
  if (!text.startsWith(FORMAT_PREFIX)) throw notABundle('it does not start with "secretless-bundle."');
  if (!text.startsWith(V1_PREFIX)) {
    throw notABundle('it was written by a newer version of this tool; upgrade, then import it again');
  }
  const segments = text.slice(V1_PREFIX.length).split('.');
  if (segments.length !== 3 || !segments.every((s) => SEGMENT.test(s))) {
    throw notABundle('it is truncated or has extra content');
  }
  const [headerSeg, ctSeg, tagSeg] = segments;
  const header = parseHeader(headerSeg);
  const tag = Buffer.from(tagSeg, 'base64url');
  // A shorter tag is accepted by GCM and authenticates less; insist on all 16 bytes.
  if (tag.length !== 16) throw notABundle('its authentication tag is truncated');

  const key = await deriveKey(passphrase, header.saltBuf, header);
  let plaintext: Buffer;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, header.ivBuf, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(V1_PREFIX + headerSeg, 'ascii'));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(Buffer.from(ctSeg, 'base64url')), decipher.final()]);
  } catch {
    throw new Error(
      'The bundle could not be decrypted: the passphrase is wrong, or the file was changed after export.\n\n' +
      '  Nothing was written.\n\n' +
      `  Fix:     run the import again with the passphrase used for export (prompted, or ${PASSPHRASE_ENV})`,
    );
  } finally {
    key.fill(0);
  }

  try {
    return parseEntries(plaintext.toString('utf-8'));
  } finally {
    plaintext.fill(0);
  }
}

function parseEntries(json: string): BundleEntry[] {
  let payload: unknown;
  try {
    payload = JSON.parse(json);
  } catch {
    throw notABundle('its decrypted content is not valid');
  }
  const raw = (payload as { entries?: unknown })?.entries;
  if (!Array.isArray(raw)) throw notABundle('its decrypted content has no entries');
  const seen = new Set<string>();
  const entries: BundleEntry[] = [];
  for (const item of raw) {
    const e = item as Partial<BundleEntry>;
    if (!e || typeof e.name !== 'string' || typeof e.value !== 'string') {
      throw notABundle('an entry has no name or value');
    }
    if (seen.has(e.name)) throw notABundle('it names the same secret twice');
    seen.add(e.name);
    const entry: BundleEntry = { name: e.name, value: e.value };
    if (typeof e.required === 'boolean') entry.required = e.required;
    if (typeof e.description === 'string') entry.description = e.description;
    entries.push(entry);
  }
  return entries;
}

/** Whether a file is a bundle: by its extension, or by the content's prefix. */
export function isBundleFile(filePath: string): boolean {
  if (filePath.toLowerCase().endsWith(BUNDLE_EXTENSION)) return true;
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, 'r');
    const head = Buffer.alloc(64);
    const read = fs.readSync(fd, head, 0, head.length, 0);
    return head.subarray(0, read).toString('utf-8').trimStart().startsWith(FORMAT_PREFIX);
  } catch {
    return false;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}
