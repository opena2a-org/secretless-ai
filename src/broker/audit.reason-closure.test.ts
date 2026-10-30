import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AUDIT_GENESIS_HASH, AuditLogger, verifyAuditLog } from './audit';
import { AUDIT_REASONS, type AuditEntry, type AuditReason } from './types';

/**
 * The audit chain has one write path, `AuditLogger.log`, and `logEvent` reaches it. Both accept
 * only a code from AUDIT_REASONS. A value that is not one, from a cast or a JavaScript caller, is
 * still written, as `unparsed:<length>` (its UTF-8 byte length, 0 for a value that is not a
 * string), and its text is written nowhere.
 */

const PLANTED = 'Planted Payee Odalys Brennecke';
const PLANTED_WORDS = ['Odalys', 'Brennecke', 'Brenneck'];

let tmpDir: string;
let logPath: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-reason-closure-'));
  logPath = path.join(tmpDir, 'broker-audit.log');
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function entry(reason: unknown): AuditEntry {
  return {
    timestamp: new Date().toISOString(),
    eventType: 'resolve',
    agentId: 'agent-1',
    credentialName: 'TEST_KEY',
    policyId: '',
    result: 'denied',
    reason: reason as string,
    latencyMs: 1,
  };
}

function expectNoPlantedWord(): void {
  const content = fs.readFileSync(logPath, 'utf-8');
  for (const word of PLANTED_WORDS) expect(content).not.toContain(word);
}

describe('the reason at the chain write path', () => {
  it('T2: logEvent writes a reason that is not a code as unparsed:<UTF-8 bytes>', () => {
    const logger = new AuditLogger(logPath);
    logger.logEvent('resolve', 'agent-1', 'TEST_KEY', '', 'denied', PLANTED as unknown as AuditReason, 1);
    logger.logEvent('resolve', 'agent-1', 'TEST_KEY', '', 'denied', 'Odalys Brennecké' as unknown as AuditReason, 1);

    expect(logger.readRecent(2).map((e) => e.reason)).toEqual(['unparsed:30', 'unparsed:17']);
    expectNoPlantedWord();
    expect(logger.verify()).toEqual({ valid: true, records: 2 });
  });

  it('T2: log, through a cast, writes a reason that is not a code as the marker', () => {
    const logger = new AuditLogger(logPath);
    logger.log(entry(PLANTED) as unknown as Parameters<AuditLogger['log']>[0]);

    const [written] = logger.readRecent(1);
    expect(written.reason).toBe('unparsed:30');
    // Every other member is written as given, in its place.
    expect(written).toEqual({ ...entry('unparsed:30'), timestamp: written.timestamp });
    expect(Object.keys(written)).toEqual(Object.keys(entry('')));
    expectNoPlantedWord();
  });

  it('T2: a reason that is not a string is written as unparsed:0', () => {
    const logger = new AuditLogger(logPath);
    for (const value of [42, null, undefined, { text: PLANTED }, [PLANTED]]) {
      logger.log(entry(value) as unknown as Parameters<AuditLogger['log']>[0]);
    }

    expect(logger.readRecent(5).map((e) => e.reason)).toEqual([
      'unparsed:0',
      'unparsed:0',
      'unparsed:0',
      'unparsed:0',
      'unparsed:0',
    ]);
    expectNoPlantedWord();
    expect(logger.verify()).toEqual({ valid: true, records: 5 });
  });

  it('T2: every code is written as given', () => {
    const logger = new AuditLogger(logPath);
    for (const code of AUDIT_REASONS) {
      logger.logEvent('resolve', 'agent-1', 'TEST_KEY', '', 'denied', code, 1);
    }

    expect(logger.readRecent(AUDIT_REASONS.length).map((e) => e.reason)).toEqual([...AUDIT_REASONS]);
    expect(logger.verify()).toEqual({ valid: true, records: AUDIT_REASONS.length });
  });

  it('T3: text built into a reason does not typecheck, in logEvent or in a log entry', () => {
    const logger = new AuditLogger(logPath);
    const detail = PLANTED;
    // @ts-expect-error a reason is a code from AUDIT_REASONS, never text built from a value
    logger.logEvent('error', 'broker', '', '', 'denied', `scanner did not load: ${detail}`, 0);
    logger.log({
      timestamp: new Date().toISOString(),
      eventType: 'error',
      agentId: 'broker',
      credentialName: '',
      policyId: '',
      result: 'denied',
      // @ts-expect-error the entry log accepts carries a code from AUDIT_REASONS
      reason: `scanner did not load: ${detail}`,
      latencyMs: 0,
    });

    // Run anyway, as JavaScript would: both are written as the marker.
    expect(logger.readRecent(2).map((e) => e.reason)).toEqual(['unparsed:52', 'unparsed:52']);
    expectNoPlantedWord();
  });
});

describe('records written before the codes', () => {
  /**
   * A log as the earlier logger wrote it, signed by its steps: each record without `sig`, with
   * `prevHash` (the genesis hash, then the SHA-256 of the line before), signed with Ed25519, and
   * written with `sig` last, one record per line. Its reasons are free text.
   */
  function writeEarlierLog(reasons: string[]): crypto.KeyObject {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(`${logPath}.key`, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(`${logPath}.pub`, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });

    let prevHash = AUDIT_GENESIS_HASH;
    let content = '';
    for (const reason of reasons) {
      const unsigned = { ...entry(reason), prevHash };
      const sig = crypto.sign(null, Buffer.from(JSON.stringify(unsigned), 'utf-8'), privateKey).toString('base64url');
      const line = JSON.stringify({ ...unsigned, sig });
      content += `${line}\n`;
      prevHash = crypto.createHash('sha256').update(Buffer.from(line, 'utf-8')).digest('hex');
    }
    fs.writeFileSync(logPath, content, { mode: 0o600 });
    return publicKey;
  }

  const EARLIER_REASONS = [
    'Broker started',
    'Denied by rule "deny-prod"',
    'Unauthorized access attempt from 127.0.0.1',
    'Resolution error: backend unavailable',
  ];

  it('T13: verifyAuditLog and readRecent accept records whose reasons are free text', () => {
    const publicKey = writeEarlierLog(EARLIER_REASONS);
    const logger = new AuditLogger(logPath);

    expect(verifyAuditLog(logPath, publicKey)).toEqual({ valid: true, records: 4 });
    expect(logger.readRecent(4).map((e) => e.reason)).toEqual(EARLIER_REASONS);
  });

  it('T13: a record written now chains after them, and the file verifies', () => {
    const publicKey = writeEarlierLog(EARLIER_REASONS);
    const logger = new AuditLogger(logPath);
    logger.logEvent('startup', 'broker', '', '', 'allowed', 'broker-started', 0);

    expect(verifyAuditLog(logPath, publicKey)).toEqual({ valid: true, records: 5 });
    expect(logger.readRecent(5).map((e) => e.reason)).toEqual([...EARLIER_REASONS, 'broker-started']);
  });
});
