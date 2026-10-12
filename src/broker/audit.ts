/**
 * Audit logger — append-only, signed JSONL audit trail for broker operations.
 *
 * Writes structured audit entries to ~/.secretless-ai/broker-audit.log in
 * JSON Lines format. Supports automatic log rotation at 50MB with 5 retained
 * files. NEVER logs credential values.
 *
 * Every record is signed (AAP §6.7). Each line carries two integrity fields:
 *
 *   - `prevHash`: SHA-256 (hex) of the bytes of the line before it in the same
 *     file, or {@link AUDIT_GENESIS_HASH} for the first line of a file;
 *   - `sig`: Ed25519 signature (base64url) over the record serialized without
 *     `sig`, which is always the last member.
 *
 * The signing key is created on first write at `<log>.key` (owner-only) and its
 * public half at `<log>.pub`. {@link verifyAuditLog} rejects an unsigned record,
 * a record altered after signing, a non-canonical line (whitespace, a duplicate
 * member), and a record removed, inserted or moved within the file. It cannot
 * detect records cut from the end of a file, or a log re-signed by someone who
 * holds the private key; pin the public key elsewhere to verify against.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import type { AuditEntry } from './types';

const DEFAULT_AUDIT_LOG = path.join(os.homedir(), '.secretless-ai', 'broker-audit.log');

/** Maximum log file size before rotation (50 MB). */
const MAX_FILE_SIZE = 50 * 1024 * 1024;

/** Number of rotated log files to retain. */
const MAX_RETAINED = 5;

/** `prevHash` of the first record in a file. */
export const AUDIT_GENESIS_HASH = '0'.repeat(64);

/** Bytes read per step when looking for the last line of the log. */
const TAIL_CHUNK = 4096;

/** Length of an Ed25519 signature in bytes. */
const ED25519_SIGNATURE_BYTES = 64;

const NEWLINE = 0x0a;

/** Result of verifying a signed audit log. */
export interface AuditVerification {
  /** True when every line is a signed record in an unbroken chain. */
  valid: boolean;
  /** Records that verified before the first failure (all of them when valid). */
  records: number;
  /** 1-based line number of the first line that failed. */
  failedLine?: number;
  /** Why that line failed. */
  reason?: string;
}

type SignedAuditRecord = AuditEntry & { prevHash: string; sig: string };

function sha256Hex(bytes: Buffer): string {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

/**
 * The last line of a file and whether the file ends with a newline.
 * Returns null when the file is missing or empty.
 */
function readTail(filePath: string): { lastLine: Buffer; endsWithNewline: boolean } | null {
  let fd: number;
  try {
    fd = fs.openSync(filePath, 'r');
  } catch {
    return null;
  }
  try {
    const size = fs.fstatSync(fd).size;
    if (size === 0) return null;

    let buf = Buffer.alloc(0);
    let pos = size;
    while (pos > 0) {
      const len = Math.min(TAIL_CHUNK, pos);
      pos -= len;
      const chunk = Buffer.alloc(len);
      fs.readSync(fd, chunk, 0, len, pos);
      buf = Buffer.concat([chunk, buf]);
      // A newline before the final byte bounds the last line.
      if (buf.lastIndexOf(NEWLINE, buf.length - 2) !== -1) break;
    }

    const endsWithNewline = buf[buf.length - 1] === NEWLINE;
    const end = endsWithNewline ? buf.length - 1 : buf.length;
    const start = buf.lastIndexOf(NEWLINE, end - 1) + 1;
    return { lastLine: buf.subarray(start, end), endsWithNewline };
  } finally {
    fs.closeSync(fd);
  }
}

function signingKeyPath(logPath: string): string {
  return `${logPath}.key`;
}

function publicKeyPath(logPath: string): string {
  return `${logPath}.pub`;
}

function parseSigningKey(pem: string, keyPath: string): crypto.KeyObject {
  let key: crypto.KeyObject;
  try {
    key = crypto.createPrivateKey(pem);
  } catch (err) {
    throw new Error(`audit signing key ${keyPath} cannot be read: ${(err as Error).message}`);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`audit signing key ${keyPath} is not an Ed25519 key`);
  }
  return key;
}

/** Load the log's signing key, creating it (and its public half) on first use. */
function loadOrCreateSigningKey(logPath: string): crypto.KeyObject {
  const keyPath = signingKeyPath(logPath);
  try {
    return parseSigningKey(fs.readFileSync(keyPath, 'utf-8'), keyPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  try {
    fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
      mode: 0o600,
      flag: 'wx',
    });
  } catch (err) {
    // Another logger on the same path created it first: sign with that key.
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      return parseSigningKey(fs.readFileSync(keyPath, 'utf-8'), keyPath);
    }
    throw err;
  }
  fs.writeFileSync(publicKeyPath(logPath), publicKey.export({ type: 'spki', format: 'pem' }), {
    mode: 0o644,
  });
  return privateKey;
}

/**
 * Verify a signed audit log against an Ed25519 public key (a KeyObject or SPKI
 * PEM). Stops at the first line that fails.
 */
export function verifyAuditLog(
  logPath: string,
  publicKey: crypto.KeyObject | string,
): AuditVerification {
  let key: crypto.KeyObject;
  try {
    key = typeof publicKey === 'string' ? crypto.createPublicKey(publicKey) : publicKey;
  } catch {
    return { valid: false, records: 0, reason: 'audit public key cannot be read' };
  }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    return { valid: false, records: 0, reason: 'audit public key is not an Ed25519 public key' };
  }

  let content: Buffer;
  try {
    content = fs.readFileSync(logPath);
  } catch {
    return { valid: false, records: 0, reason: 'audit log cannot be read' };
  }

  const lines: Buffer[] = [];
  let start = 0;
  for (let i = content.indexOf(NEWLINE); i !== -1; i = content.indexOf(NEWLINE, start)) {
    lines.push(content.subarray(start, i));
    start = i + 1;
  }
  // Bytes after the final newline are a line too: a record cut short fails below.
  if (start < content.length) lines.push(content.subarray(start));

  let expectedPrev = AUDIT_GENESIS_HASH;
  for (let index = 0; index < lines.length; index++) {
    const fail = (reason: string): AuditVerification => ({
      valid: false,
      records: index,
      failedLine: index + 1,
      reason,
    });
    const text = lines[index].toString('utf-8');

    let record: unknown;
    try {
      record = JSON.parse(text);
    } catch {
      return fail('line is not JSON');
    }
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      return fail('line is not a JSON object');
    }
    const fields = record as Record<string, unknown>;
    if (typeof fields.sig !== 'string' || typeof fields.prevHash !== 'string') {
      return fail('record is not signed');
    }
    // Only the exact bytes the logger wrote are accepted: no whitespace, no
    // duplicate member, `sig` last. Any other spelling of a signed record could
    // read differently to a consumer than to this verifier.
    const keys = Object.keys(fields);
    if (JSON.stringify(fields) !== text || keys[keys.length - 1] !== 'sig') {
      return fail('record is not in canonical form');
    }
    if (fields.prevHash !== expectedPrev) {
      return fail('hash chain broken: record does not follow the line before it');
    }
    const { sig, ...unsigned } = fields;
    const signature = Buffer.from(sig as string, 'base64url');
    if (signature.length !== ED25519_SIGNATURE_BYTES || signature.toString('base64url') !== sig) {
      return fail('signature is not an Ed25519 signature in canonical base64url');
    }
    if (!crypto.verify(null, Buffer.from(JSON.stringify(unsigned), 'utf-8'), key, signature)) {
      return fail('signature does not match the record');
    }
    expectedPrev = sha256Hex(lines[index]);
  }

  return { valid: true, records: lines.length };
}

export class AuditLogger {
  private readonly logPath: string;
  private fd: number | null = null;
  private signingKey: crypto.KeyObject | null = null;

  constructor(logPath?: string) {
    this.logPath = logPath ?? DEFAULT_AUDIT_LOG;
  }

  /**
   * Write a signed audit entry to the log file.
   * Creates the log directory, file and signing key if they do not exist.
   */
  log(entry: AuditEntry): void {
    const dir = path.dirname(this.logPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    // Check rotation before writing
    this.rotateIfNeeded();

    // Chain to the line now on disk, not to the last line this instance wrote:
    // another logger may share the file.
    const tail = readTail(this.logPath);
    const prevHash = tail ? sha256Hex(tail.lastLine) : AUDIT_GENESIS_HASH;

    // Integrity fields are the logger's to set, never the caller's.
    const { prevHash: _p, sig: _s, ...fields } = entry as SignedAuditRecord;
    const unsigned = { ...fields, prevHash };
    const sig = crypto
      .sign(null, Buffer.from(JSON.stringify(unsigned), 'utf-8'), this.key())
      .toString('base64url');

    // A file that ends mid-line gets a newline first, so the record is a line of its own.
    const prefix = tail && !tail.endsWithNewline ? '\n' : '';
    const line = prefix + JSON.stringify({ ...unsigned, sig }) + '\n';

    // Append-only write with restrictive permissions
    fs.appendFileSync(this.logPath, line, { mode: 0o600 });
  }

  /**
   * Create an audit entry from individual fields.
   * Convenience method that populates the timestamp automatically.
   */
  logEvent(
    eventType: string,
    agentId: string,
    credentialName: string,
    policyId: string,
    result: 'allowed' | 'denied',
    reason: string,
    latencyMs: number,
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      eventType,
      agentId,
      credentialName,
      policyId,
      result,
      reason,
      latencyMs,
    });
  }

  /**
   * Read recent audit entries (last N lines).
   * Returns entries in chronological order (oldest first), without their
   * integrity fields. This does not verify them; use {@link verify}.
   */
  readRecent(count: number): AuditEntry[] {
    if (!fs.existsSync(this.logPath)) return [];

    try {
      const content = fs.readFileSync(this.logPath, 'utf-8');
      const lines = content.trim().split('\n').filter(l => l.length > 0);
      const recent = lines.slice(-count);

      return recent.map(line => {
        try {
          const { prevHash: _p, sig: _s, ...entry } = JSON.parse(line) as SignedAuditRecord;
          return entry as AuditEntry;
        } catch {
          return null;
        }
      }).filter((e): e is AuditEntry => e !== null);
    } catch {
      return [];
    }
  }

  /** The audit public key (SPKI PEM), to pin for verification elsewhere. */
  publicKeyPem(): string {
    return crypto.createPublicKey(this.key()).export({ type: 'spki', format: 'pem' }) as string;
  }

  /**
   * Verify a log file (this logger's by default; a rotated file by path)
   * against this logger's signing key.
   */
  verify(filePath: string = this.logPath): AuditVerification {
    return verifyAuditLog(filePath, crypto.createPublicKey(this.key()));
  }

  /**
   * Close the audit logger and release file handles.
   */
  close(): void {
    if (this.fd !== null) {
      try {
        fs.closeSync(this.fd);
      } catch {
        // Ignore close errors
      }
      this.fd = null;
    }
  }

  private key(): crypto.KeyObject {
    if (!this.signingKey) {
      fs.mkdirSync(path.dirname(this.logPath), { recursive: true, mode: 0o700 });
      this.signingKey = loadOrCreateSigningKey(this.logPath);
    }
    return this.signingKey;
  }

  /** Rotate log file if it exceeds the size limit. */
  private rotateIfNeeded(): void {
    if (!fs.existsSync(this.logPath)) return;

    try {
      const stat = fs.statSync(this.logPath);
      if (stat.size < MAX_FILE_SIZE) return;
    } catch {
      return;
    }

    // Rotate: .4 -> .5 (deleted), .3 -> .4, .2 -> .3, .1 -> .2, current -> .1
    for (let i = MAX_RETAINED; i >= 1; i--) {
      const older = `${this.logPath}.${i}`;
      const newer = i === 1 ? this.logPath : `${this.logPath}.${i - 1}`;

      if (i === MAX_RETAINED) {
        // Delete the oldest
        try { fs.unlinkSync(older); } catch { /* ignore */ }
      }

      if (fs.existsSync(newer)) {
        try {
          fs.renameSync(newer, older);
        } catch {
          // If rename fails (cross-device), copy and truncate
          try {
            fs.copyFileSync(newer, older);
            fs.writeFileSync(newer, '', { mode: 0o600 });
          } catch {
            // Give up on this rotation step
          }
        }
      }
    }
  }
}
