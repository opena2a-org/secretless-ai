import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CredentialEventEmitter, type CredentialEvent } from './events';
import { AuditLogger } from './audit';

describe('CredentialEventEmitter', () => {
  let mockLogger: AuditLogger;
  let loggedEvents: Array<{
    eventType: string;
    agentId: string;
    credentialName: string;
    policyId: string;
    result: string;
    reason: string;
  }>;

  beforeEach(() => {
    loggedEvents = [];
    mockLogger = {
      logEvent: vi.fn((eventType, agentId, credentialName, policyId, result, reason) => {
        loggedEvents.push({ eventType, agentId, credentialName, policyId, result, reason });
      }),
      log: vi.fn(),
      readRecent: vi.fn().mockReturnValue([]),
      close: vi.fn(),
    } as unknown as AuditLogger;
  });

  describe('emitRequested', () => {
    it('logs a credential.requested event', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      emitter.emitRequested('agent-001', 'secret://keychain/db', 'db:read');

      expect(loggedEvents).toHaveLength(1);
      expect(loggedEvents[0].eventType).toBe('credential.requested');
      expect(loggedEvents[0].agentId).toBe('agent-001');
      expect(loggedEvents[0].credentialName).toBe('secret://keychain/db');
      expect(loggedEvents[0].result).toBe('allowed');
    });
  });

  describe('emitGranted', () => {
    it('logs a credential.granted event with trust score', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      emitter.emitGranted('agent-001', 'secret://keychain/db', {
        trustScore: 0.85,
        ttlSeconds: 300,
        policyRuleId: 'allow-dev',
        backend: 'keychain',
      });

      expect(loggedEvents).toHaveLength(1);
      expect(loggedEvents[0].eventType).toBe('credential.granted');
      expect(loggedEvents[0].result).toBe('allowed');
    });
  });

  describe('emitDenied', () => {
    it('logs a credential.denied event', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      emitter.emitDenied('agent-001', 'secret://keychain/admin', 'Trust score too low', {
        trustScore: 0.3,
        policyRuleId: 'deny-low-trust',
      });

      expect(loggedEvents).toHaveLength(1);
      expect(loggedEvents[0].eventType).toBe('credential.denied');
      expect(loggedEvents[0].result).toBe('denied');
      expect(loggedEvents[0].reason).toBe('Trust score too low');
    });
  });

  describe('emitExpired', () => {
    it('logs a credential.expired event for used credentials', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      emitter.emitExpired('agent-001', 'secret://vault/key', true);

      expect(loggedEvents).toHaveLength(1);
      expect(loggedEvents[0].eventType).toBe('credential.expired');
      expect(loggedEvents[0].reason).toContain('after use');
    });

    it('logs a credential.expired event for unused credentials', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      emitter.emitExpired('agent-001', 'secret://vault/key', false);

      expect(loggedEvents).toHaveLength(1);
      expect(loggedEvents[0].reason).toContain('unused');
    });
  });

  describe('emitRevoked', () => {
    it('logs a credential.revoked event', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      emitter.emitRevoked('agent-001', 'secret://keychain/db', 'Admin action');

      expect(loggedEvents).toHaveLength(1);
      expect(loggedEvents[0].eventType).toBe('credential.revoked');
      expect(loggedEvents[0].result).toBe('denied');
    });
  });

  describe('emitLeakDetected', () => {
    it('logs a credential.leak_detected event as denied', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      emitter.emitLeakDetected('agent-001', 'secret://env/API_KEY', 'Found in LLM context window');

      expect(loggedEvents).toHaveLength(1);
      expect(loggedEvents[0].eventType).toBe('credential.leak_detected');
      expect(loggedEvents[0].result).toBe('denied');
    });
  });

  describe('emitRotated', () => {
    it('logs a credential.rotated event from system', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      emitter.emitRotated('secret://keychain/db', 'Scheduled rotation');

      expect(loggedEvents).toHaveLength(1);
      expect(loggedEvents[0].eventType).toBe('credential.rotated');
      expect(loggedEvents[0].agentId).toBe('system');
      expect(loggedEvents[0].result).toBe('allowed');
    });
  });

  describe('AIM forwarding', () => {
    it('does not throw when AIM URL is not configured', () => {
      const emitter = new CredentialEventEmitter(mockLogger);
      expect(() => emitter.emitRequested('agent-001', 'ref', 'cap')).not.toThrow();
    });

    it('does not throw when AIM URL is configured but unreachable', () => {
      const emitter = new CredentialEventEmitter(mockLogger, 'http://localhost:1/audit');
      expect(() => emitter.emitDenied('agent-001', 'ref', 'reason')).not.toThrow();
    });
  });
});
