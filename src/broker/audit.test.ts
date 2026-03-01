import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AuditLogger } from './audit';
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
});
