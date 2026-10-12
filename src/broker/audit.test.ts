import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AuditLogger, AUDIT_GENESIS_HASH, verifyAuditLog } from './audit';
import type { AuditEntry } from './types';

describe('AuditLogger', () => {
  let tmpDir: string;
  let logPath: string;
  let logger: AuditLogger;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-audit-test-'));
    logPath = path.join(tmpDir, 'test-audit.log');
    logger = new AuditLogger(logPath);
  });

  afterEach(() => {
    logger.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function makeEntry(overrides?: Partial<AuditEntry>): AuditEntry {
    return {
      timestamp: new Date().toISOString(),
      eventType: 'resolve',
      agentId: 'test-agent',
      credentialName: 'TEST_CRED',
      policyId: 'rule-1',
      result: 'allowed',
      reason: 'Allowed by rule',
      latencyMs: 5,
      ...overrides,
    };
  }

  it('creates the log file on first write', () => {
    expect(fs.existsSync(logPath)).toBe(false);
    logger.log(makeEntry());
    expect(fs.existsSync(logPath)).toBe(true);
  });

  it('writes JSONL format (one JSON object per line)', () => {
    logger.log(makeEntry({ agentId: 'agent-1' }));
    logger.log(makeEntry({ agentId: 'agent-2' }));

    const content = fs.readFileSync(logPath, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(2);

    const entry1 = JSON.parse(lines[0]);
    expect(entry1.agentId).toBe('agent-1');

    const entry2 = JSON.parse(lines[1]);
    expect(entry2.agentId).toBe('agent-2');
  });

  it('never logs credential values', () => {
    // Audit entries intentionally do not have a "value" field
    const entry = makeEntry({ credentialName: 'SECRET_KEY' });
    logger.log(entry);

    const content = fs.readFileSync(logPath, 'utf-8');
    // The log should contain the credential NAME but not any value
    expect(content).toContain('SECRET_KEY');
    // Verify the entry shape has no value field
    const parsed = JSON.parse(content.trim());
    expect(parsed).not.toHaveProperty('value');
    expect(parsed).not.toHaveProperty('secret');
    expect(parsed).not.toHaveProperty('password');
  });

  it('records all required audit fields', () => {
    const entry = makeEntry({
      timestamp: '2026-01-15T10:30:00.000Z',
      eventType: 'resolve',
      agentId: 'scan-agent',
      credentialName: 'GITHUB_TOKEN',
      policyId: 'allow-scanner',
      result: 'allowed',
      reason: 'Allowed by rule "allow-scanner"',
      latencyMs: 12,
    });
    logger.log(entry);

    const content = fs.readFileSync(logPath, 'utf-8');
    const parsed = JSON.parse(content.trim());

    expect(parsed.timestamp).toBe('2026-01-15T10:30:00.000Z');
    expect(parsed.eventType).toBe('resolve');
    expect(parsed.agentId).toBe('scan-agent');
    expect(parsed.credentialName).toBe('GITHUB_TOKEN');
    expect(parsed.policyId).toBe('allow-scanner');
    expect(parsed.result).toBe('allowed');
    expect(parsed.reason).toContain('allow-scanner');
    expect(parsed.latencyMs).toBe(12);
  });

  it('logEvent convenience method populates timestamp', () => {
    logger.logEvent('resolve', 'agent-1', 'CRED', 'rule-1', 'allowed', 'ok', 3);

    const entries = logger.readRecent(1);
    expect(entries).toHaveLength(1);
    expect(entries[0].timestamp).toBeTruthy();
    expect(entries[0].agentId).toBe('agent-1');
  });

  it('reads recent entries in chronological order', () => {
    for (let i = 0; i < 5; i++) {
      logger.log(makeEntry({ agentId: `agent-${i}` }));
    }

    const recent = logger.readRecent(3);
    expect(recent).toHaveLength(3);
    expect(recent[0].agentId).toBe('agent-2');
    expect(recent[1].agentId).toBe('agent-3');
    expect(recent[2].agentId).toBe('agent-4');
  });

  it('returns empty array when log file does not exist', () => {
    const emptyLogger = new AuditLogger(path.join(tmpDir, 'nonexistent.log'));
    expect(emptyLogger.readRecent(10)).toEqual([]);
  });

  it('handles corrupted lines gracefully', () => {
    // Write a mix of valid and invalid lines
    fs.writeFileSync(logPath, [
      JSON.stringify(makeEntry({ agentId: 'valid-1' })),
      'not valid json',
      JSON.stringify(makeEntry({ agentId: 'valid-2' })),
    ].join('\n'));

    const entries = logger.readRecent(10);
    expect(entries).toHaveLength(2);
    expect(entries[0].agentId).toBe('valid-1');
    expect(entries[1].agentId).toBe('valid-2');
  });

  describe('log rotation', () => {
    it('rotates when file exceeds 50MB', () => {
      // Create a log file just over the size limit
      const bigContent = 'x'.repeat(50 * 1024 * 1024 + 1);
      fs.writeFileSync(logPath, bigContent);

      // Writing a new entry should trigger rotation
      logger.log(makeEntry());

      // The rotated file should exist
      expect(fs.existsSync(`${logPath}.1`)).toBe(true);
      // The current log file should have only the new entry
      const content = fs.readFileSync(logPath, 'utf-8');
      const parsed = JSON.parse(content.trim());
      expect(parsed.agentId).toBe('test-agent');
    });

    it('retains up to 5 rotated files', () => {
      // Create rotated files .1 through .5
      for (let i = 1; i <= 5; i++) {
        fs.writeFileSync(`${logPath}.${i}`, `old-${i}`);
      }

      // Create a current file over the limit
      const bigContent = 'x'.repeat(50 * 1024 * 1024 + 1);
      fs.writeFileSync(logPath, bigContent);

      // Trigger rotation
      logger.log(makeEntry());

      // .5 (oldest) should be replaced with what was .4
      expect(fs.readFileSync(`${logPath}.5`, 'utf-8')).toBe('old-4');
      // .1 should be the rotated current file (big content)
      expect(fs.existsSync(`${logPath}.1`)).toBe(true);
    });

    it('does not rotate when under the size limit', () => {
      fs.writeFileSync(logPath, 'small content\n');
      logger.log(makeEntry());

      expect(fs.existsSync(`${logPath}.1`)).toBe(false);
      const lines = fs.readFileSync(logPath, 'utf-8').trim().split('\n');
      expect(lines).toHaveLength(2); // original line + new entry
    });
  });

  it('creates parent directories if needed', () => {
    const nestedLog = path.join(tmpDir, 'sub', 'dir', 'audit.log');
    const nestedLogger = new AuditLogger(nestedLog);
    nestedLogger.log(makeEntry());
    expect(fs.existsSync(nestedLog)).toBe(true);
    nestedLogger.close();
  });

  describe('signed audit', () => {
    function lines(): string[] {
      return fs.readFileSync(logPath, 'utf-8').split('\n').filter(l => l.length > 0);
    }

    function writeLines(content: string[]): void {
      fs.writeFileSync(logPath, content.join('\n') + '\n');
    }

    function logThree(): void {
      logger.log(makeEntry({ agentId: 'agent-1', result: 'allowed' }));
      logger.log(makeEntry({ agentId: 'agent-2', result: 'allowed' }));
      logger.log(makeEntry({ agentId: 'agent-3', result: 'denied' }));
    }

    it('signs every record and chains it to the line before it', () => {
      logThree();
      const records = lines().map(l => JSON.parse(l));
      expect(records).toHaveLength(3);
      for (const record of records) {
        expect(typeof record.prevHash).toBe('string');
        expect(typeof record.sig).toBe('string');
      }
      expect(records[0].prevHash).toBe(AUDIT_GENESIS_HASH);
      expect(records[1].prevHash).not.toBe(records[0].prevHash);

      expect(logger.verify()).toEqual({ valid: true, records: 3 });
    });

    it('verifies against the public key written beside the log', () => {
      logThree();
      const publicKey = fs.readFileSync(`${logPath}.pub`, 'utf-8');
      expect(verifyAuditLog(logPath, publicKey)).toEqual({ valid: true, records: 3 });
      expect(logger.publicKeyPem()).toBe(publicKey);
    });

    it('keeps the signing key readable by its owner only', () => {
      logger.log(makeEntry());
      expect(fs.statSync(`${logPath}.key`).mode & 0o077).toBe(0);
    });

    it('rejects an unsigned record', () => {
      logThree();
      fs.appendFileSync(logPath, JSON.stringify(makeEntry({ agentId: 'unsigned' })) + '\n');

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.records).toBe(3);
      expect(result.failedLine).toBe(4);
      expect(result.reason).toMatch(/not signed/);
    });

    it('rejects an unsigned record appended with no trailing newline', () => {
      logThree();
      fs.appendFileSync(logPath, JSON.stringify(makeEntry({ agentId: 'unsigned' })));

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.records).toBe(3);
      expect(result.failedLine).toBe(4);
      expect(result.reason).toMatch(/not signed/);
    });

    it('rejects a line that is not JSON inserted between signed records', () => {
      logThree();
      const content = lines();
      // JSON.parse refuses NaN, which some JSON readers accept as a number.
      const inserted = JSON.stringify(makeEntry({ agentId: 'inserted' }))
        .replace('"latencyMs":5', '"latencyMs":NaN');
      content.splice(1, 0, inserted);
      writeLines(content);

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.records).toBe(1);
      expect(result.failedLine).toBe(2);
      expect(result.reason).toMatch(/not JSON/);
    });

    it('rejects a log that holds only unsigned records', () => {
      logger.log(makeEntry());
      writeLines([JSON.stringify(makeEntry()), JSON.stringify(makeEntry())]);

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.failedLine).toBe(1);
    });

    it('rejects a record whose decision was changed after signing', () => {
      logThree();
      const content = lines();
      content[2] = content[2].replace('"result":"denied"', '"result":"allowed"');
      writeLines(content);

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.failedLine).toBe(3);
      expect(result.reason).toMatch(/signature/);
    });

    it('rejects a log with a record removed from the middle', () => {
      logThree();
      const content = lines();
      writeLines([content[0], content[2]]);

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.failedLine).toBe(2);
      expect(result.reason).toMatch(/chain/);
    });

    it('rejects a log with its first record removed', () => {
      logThree();
      writeLines(lines().slice(1));

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.failedLine).toBe(1);
    });

    it('rejects reordered records', () => {
      logThree();
      const content = lines();
      writeLines([content[0], content[2], content[1]]);

      expect(logger.verify().valid).toBe(false);
    });

    it('rejects a signed record carrying a decoy duplicate member', () => {
      logThree();
      const content = lines();
      // The decoy stands where the signed member stood, so key order is
      // unchanged and the signed member still parses last: the signature alone
      // would hold, and a reader that keeps the first member would see a
      // different decision.
      content[2] = content[2].replace('"result":"denied"', '"result":"allowed","result":"denied"');
      writeLines(content);

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.failedLine).toBe(3);
      expect(result.reason).toMatch(/canonical/);
    });

    it('rejects a log signed by a different key', () => {
      logThree();
      const otherPath = path.join(tmpDir, 'other.log');
      const other = new AuditLogger(otherPath);
      other.log(makeEntry());

      expect(verifyAuditLog(logPath, other.publicKeyPem()).valid).toBe(false);
      expect(other.verify(logPath).valid).toBe(false);
    });

    it('keeps one chain when two loggers write the same file', () => {
      const second = new AuditLogger(logPath);
      logger.log(makeEntry({ agentId: 'first' }));
      second.log(makeEntry({ agentId: 'second' }));
      logger.log(makeEntry({ agentId: 'first-again' }));

      expect(logger.verify()).toEqual({ valid: true, records: 3 });
      expect(second.publicKeyPem()).toBe(logger.publicKeyPem());
    });

    it('starts a record on its own line when the file ends mid-line', () => {
      logger.log(makeEntry());
      fs.appendFileSync(logPath, 'partial');
      logger.log(makeEntry({ agentId: 'after-partial' }));

      const content = lines();
      expect(content[1]).toBe('partial');
      expect(JSON.parse(content[2]).agentId).toBe('after-partial');
    });

    it('chains past a record longer than one tail read', () => {
      logger.log(makeEntry({ reason: 'r'.repeat(10_000) }));
      logger.log(makeEntry({ agentId: 'after-long' }));
      logger.log(makeEntry({ agentId: 'after-long-2' }));

      expect(logger.verify()).toEqual({ valid: true, records: 3 });
    });

    it('rejects a record whose signature was truncated', () => {
      logThree();
      const content = lines();
      content[2] = content[2].replace(/"sig":"([^"]+)"/, (_m, sig: string) => `"sig":"${sig.slice(0, 40)}"`);
      writeLines(content);

      const result = logger.verify();
      expect(result.valid).toBe(false);
      expect(result.failedLine).toBe(3);
    });

    it('names the key file when the signing key cannot be read', () => {
      fs.writeFileSync(`${logPath}.key`, 'not a key', { mode: 0o600 });
      expect(() => logger.log(makeEntry())).toThrow(/audit signing key .*cannot be read/);
    });

    it('starts a fresh chain in the new file after rotation', () => {
      fs.writeFileSync(logPath, 'x'.repeat(50 * 1024 * 1024 + 1));
      logger.log(makeEntry({ agentId: 'after-rotation' }));
      logger.log(makeEntry({ agentId: 'after-rotation-2' }));

      expect(logger.verify()).toEqual({ valid: true, records: 2 });
    });

    it('reports a missing log as not verified', () => {
      const result = verifyAuditLog(path.join(tmpDir, 'absent.log'), logger.publicKeyPem());
      expect(result.valid).toBe(false);
      expect(result.records).toBe(0);
    });

    it('returns entries without the integrity fields from readRecent', () => {
      logger.log(makeEntry({ agentId: 'plain' }));
      const [entry] = logger.readRecent(1);
      expect(entry.agentId).toBe('plain');
      expect(entry).not.toHaveProperty('sig');
      expect(entry).not.toHaveProperty('prevHash');
    });
  });
});
