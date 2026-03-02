import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PolicyEngine, matchGlob, isWithinTimeWindow } from './policy';
import { RateLimiter } from './rate-limiter';
import type { PolicyRule, AgentIdentity } from './types';

describe('PolicyEngine', () => {
  let engine: PolicyEngine;
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = new RateLimiter();
    engine = new PolicyEngine({ rateLimiter });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('default deny', () => {
    it('denies all requests when no rules are loaded', () => {
      const result = engine.evaluate('any-agent', 'ANY_CREDENTIAL');
      expect(result.allowed).toBe(false);
      expect(result.matchedRuleId).toBe('');
      expect(result.reason).toContain('default deny');
    });
  });

  describe('allow rules', () => {
    it('allows matching agent and credential', () => {
      engine.loadRules([{
        id: 'allow-scanner',
        agentSelector: 'scanner-*',
        credentialSelector: 'GITHUB_TOKEN',
        constraints: {},
        effect: 'allow',
      }]);

      const result = engine.evaluate('scanner-01', 'GITHUB_TOKEN');
      expect(result.allowed).toBe(true);
      expect(result.matchedRuleId).toBe('allow-scanner');
    });

    it('denies non-matching agent', () => {
      engine.loadRules([{
        id: 'allow-scanner',
        agentSelector: 'scanner-*',
        credentialSelector: 'GITHUB_TOKEN',
        constraints: {},
        effect: 'allow',
      }]);

      const result = engine.evaluate('deploy-agent', 'GITHUB_TOKEN');
      expect(result.allowed).toBe(false);
    });

    it('denies non-matching credential', () => {
      engine.loadRules([{
        id: 'allow-scanner',
        agentSelector: 'scanner-*',
        credentialSelector: 'GITHUB_TOKEN',
        constraints: {},
        effect: 'allow',
      }]);

      const result = engine.evaluate('scanner-01', 'AWS_SECRET');
      expect(result.allowed).toBe(false);
    });

    it('uses wildcard * to match any value', () => {
      engine.loadRules([{
        id: 'allow-all',
        agentSelector: '*',
        credentialSelector: '*',
        constraints: {},
        effect: 'allow',
      }]);

      const result = engine.evaluate('any-agent', 'ANY_CRED');
      expect(result.allowed).toBe(true);
    });
  });

  describe('deny rules', () => {
    it('deny rules are evaluated before allow rules', () => {
      engine.loadRules([
        {
          id: 'allow-all',
          agentSelector: '*',
          credentialSelector: '*',
          constraints: {},
          effect: 'allow',
        },
        {
          id: 'deny-prod',
          agentSelector: '*',
          credentialSelector: 'PROD_*',
          constraints: {},
          effect: 'deny',
        },
      ]);

      const result = engine.evaluate('any-agent', 'PROD_DB_PASSWORD');
      expect(result.allowed).toBe(false);
      expect(result.matchedRuleId).toBe('deny-prod');
    });

    it('deny rules block even when listed after allow rules', () => {
      engine.loadRules([
        {
          id: 'allow-scanner',
          agentSelector: 'scanner-*',
          credentialSelector: '*',
          constraints: {},
          effect: 'allow',
        },
        {
          id: 'deny-aws',
          agentSelector: '*',
          credentialSelector: 'AWS_*',
          constraints: {},
          effect: 'deny',
        },
      ]);

      const result = engine.evaluate('scanner-01', 'AWS_SECRET_KEY');
      expect(result.allowed).toBe(false);
      expect(result.matchedRuleId).toBe('deny-aws');
    });
  });

  describe('constraints', () => {
    it('enforces rate limit', () => {
      engine.loadRules([{
        id: 'limited',
        agentSelector: '*',
        credentialSelector: '*',
        constraints: { rateLimit: { maxPerMinute: 2 } },
        effect: 'allow',
      }]);

      expect(engine.evaluate('agent', 'CRED').allowed).toBe(true);
      expect(engine.evaluate('agent', 'CRED').allowed).toBe(true);
      expect(engine.evaluate('agent', 'CRED').allowed).toBe(false);
    });

    it('enforces minimum trust score', () => {
      engine.loadRules([{
        id: 'trusted-only',
        agentSelector: '*',
        credentialSelector: '*',
        constraints: { minTrustScore: 0.8 },
        effect: 'allow',
      }]);

      const highTrust: AgentIdentity = {
        agentId: 'agent-1',
        trustScore: 0.95,
        capabilities: [],
        verified: true,
      };

      const lowTrust: AgentIdentity = {
        agentId: 'agent-2',
        trustScore: 0.5,
        capabilities: [],
        verified: true,
      };

      expect(engine.evaluate('agent-1', 'CRED', highTrust).allowed).toBe(true);
      expect(engine.evaluate('agent-2', 'CRED', lowTrust).allowed).toBe(false);
    });

    it('denies when trust score required but no identity', () => {
      engine.loadRules([{
        id: 'trusted-only',
        agentSelector: '*',
        credentialSelector: '*',
        constraints: { minTrustScore: 0.5 },
        effect: 'allow',
      }]);

      const result = engine.evaluate('agent-1', 'CRED');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('no agent identity');
    });

    it('enforces required capability', () => {
      engine.loadRules([{
        id: 'cap-required',
        agentSelector: '*',
        credentialSelector: '*',
        constraints: { requireCapability: 'read-secrets' },
        effect: 'allow',
      }]);

      const withCap: AgentIdentity = {
        agentId: 'agent-1',
        trustScore: 0.9,
        capabilities: ['read-secrets', 'scan'],
        verified: true,
      };

      const withoutCap: AgentIdentity = {
        agentId: 'agent-2',
        trustScore: 0.9,
        capabilities: ['scan'],
        verified: true,
      };

      expect(engine.evaluate('agent-1', 'CRED', withCap).allowed).toBe(true);
      expect(engine.evaluate('agent-2', 'CRED', withoutCap).allowed).toBe(false);
    });

    it('denies when capability required but no identity', () => {
      engine.loadRules([{
        id: 'cap-required',
        agentSelector: '*',
        credentialSelector: '*',
        constraints: { requireCapability: 'deploy' },
        effect: 'allow',
      }]);

      const result = engine.evaluate('agent', 'CRED');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('no agent identity');
    });

    it('enforces time window during business hours', () => {
      const now = new Date();
      // Set time to 12:00 (always within 09:00-17:00)
      vi.spyOn(Date.prototype, 'getHours').mockReturnValue(12);
      vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);

      engine.loadRules([{
        id: 'business-hours',
        agentSelector: '*',
        credentialSelector: '*',
        constraints: { timeWindow: { start: '09:00', end: '17:00' } },
        effect: 'allow',
      }]);

      expect(engine.evaluate('agent', 'CRED').allowed).toBe(true);
    });

    it('denies outside time window', () => {
      // Set time to 03:00 (outside 09:00-17:00)
      vi.spyOn(Date.prototype, 'getHours').mockReturnValue(3);
      vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);

      engine.loadRules([{
        id: 'business-hours',
        agentSelector: '*',
        credentialSelector: '*',
        constraints: { timeWindow: { start: '09:00', end: '17:00' } },
        effect: 'allow',
      }]);

      const result = engine.evaluate('agent', 'CRED');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Outside allowed time window');
    });
  });

  describe('loading from file', () => {
    let tmpDir: string;
    let policyFile: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-policy-test-'));
      policyFile = path.join(tmpDir, 'policies.json');
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('loads policies from a JSON file', () => {
      const policies = {
        rules: [{
          id: 'test-rule',
          agentSelector: '*',
          credentialSelector: '*',
          constraints: {},
          effect: 'allow',
        }],
      };
      fs.writeFileSync(policyFile, JSON.stringify(policies));

      const fileEngine = new PolicyEngine({ policyFile });
      const count = fileEngine.loadPolicies();
      expect(count).toBe(1);
      expect(fileEngine.evaluate('agent', 'CRED').allowed).toBe(true);
    });

    it('returns zero when policy file does not exist', () => {
      const fileEngine = new PolicyEngine({ policyFile: path.join(tmpDir, 'nonexistent.json') });
      const count = fileEngine.loadPolicies();
      expect(count).toBe(0);
    });

    it('throws on invalid policy file', () => {
      fs.writeFileSync(policyFile, 'not json');
      const fileEngine = new PolicyEngine({ policyFile });
      expect(() => fileEngine.loadPolicies()).toThrow('Failed to load policies');
    });

    it('loads policies from a bare JSON array', () => {
      const policies = [{
        id: 'bare-rule',
        agentSelector: 'scanner-*',
        credentialSelector: 'GITHUB_TOKEN',
        constraints: {},
        effect: 'allow',
      }];
      fs.writeFileSync(policyFile, JSON.stringify(policies));

      const fileEngine = new PolicyEngine({ policyFile });
      const count = fileEngine.loadPolicies();
      expect(count).toBe(1);
      expect(fileEngine.evaluate('scanner-01', 'GITHUB_TOKEN').allowed).toBe(true);
      expect(fileEngine.evaluate('deploy-agent', 'GITHUB_TOKEN').allowed).toBe(false);
    });

    it('throws on missing rules array', () => {
      fs.writeFileSync(policyFile, JSON.stringify({ notRules: [] }));
      const fileEngine = new PolicyEngine({ policyFile });
      expect(() => fileEngine.loadPolicies()).toThrow('must contain a "rules" array');
    });

    it('validates rule structure', () => {
      fs.writeFileSync(policyFile, JSON.stringify({ rules: [{ invalid: true }] }));
      const fileEngine = new PolicyEngine({ policyFile });
      expect(() => fileEngine.loadPolicies()).toThrow('non-empty "id"');
    });
  });

  describe('ruleCount and getRules', () => {
    it('reports zero rules when empty', () => {
      expect(engine.ruleCount).toBe(0);
    });

    it('reports correct rule count after loading', () => {
      engine.loadRules([
        { id: 'a', agentSelector: '*', credentialSelector: '*', constraints: {}, effect: 'allow' },
        { id: 'b', agentSelector: '*', credentialSelector: '*', constraints: {}, effect: 'deny' },
      ]);
      expect(engine.ruleCount).toBe(2);
    });

    it('returns a copy of rules', () => {
      const rules: PolicyRule[] = [
        { id: 'a', agentSelector: '*', credentialSelector: '*', constraints: {}, effect: 'allow' },
      ];
      engine.loadRules(rules);
      const returned = engine.getRules();
      expect(returned).toEqual(rules);
      // Verify it is a copy
      returned[0].id = 'modified';
      expect(engine.getRules()[0].id).toBe('a');
    });
  });
});

describe('matchGlob', () => {
  it('matches exact strings', () => {
    expect(matchGlob('scanner-01', 'scanner-01')).toBe(true);
    expect(matchGlob('scanner-01', 'scanner-02')).toBe(false);
  });

  it('matches * wildcard', () => {
    expect(matchGlob('scanner-*', 'scanner-01')).toBe(true);
    expect(matchGlob('scanner-*', 'scanner-abc')).toBe(true);
    expect(matchGlob('scanner-*', 'deploy-01')).toBe(false);
  });

  it('matches * as full wildcard', () => {
    expect(matchGlob('*', 'anything')).toBe(true);
    expect(matchGlob('*', '')).toBe(true);
  });

  it('matches ? single-char wildcard', () => {
    expect(matchGlob('agent-?', 'agent-1')).toBe(true);
    expect(matchGlob('agent-?', 'agent-12')).toBe(false);
  });

  it('handles multiple wildcards', () => {
    expect(matchGlob('*-*', 'scan-agent')).toBe(true);
    expect(matchGlob('*-*', 'standalone')).toBe(false);
  });

  it('escapes regex special characters', () => {
    expect(matchGlob('agent.v1', 'agent.v1')).toBe(true);
    expect(matchGlob('agent.v1', 'agentXv1')).toBe(false);
  });
});

describe('isWithinTimeWindow', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns true within normal window', () => {
    vi.spyOn(Date.prototype, 'getHours').mockReturnValue(12);
    vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);
    expect(isWithinTimeWindow('09:00', '17:00')).toBe(true);
  });

  it('returns false outside normal window', () => {
    vi.spyOn(Date.prototype, 'getHours').mockReturnValue(20);
    vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);
    expect(isWithinTimeWindow('09:00', '17:00')).toBe(false);
  });

  it('handles overnight window (before midnight)', () => {
    vi.spyOn(Date.prototype, 'getHours').mockReturnValue(23);
    vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);
    expect(isWithinTimeWindow('22:00', '06:00')).toBe(true);
  });

  it('handles overnight window (after midnight)', () => {
    vi.spyOn(Date.prototype, 'getHours').mockReturnValue(3);
    vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);
    expect(isWithinTimeWindow('22:00', '06:00')).toBe(true);
  });

  it('handles overnight window (outside)', () => {
    vi.spyOn(Date.prototype, 'getHours').mockReturnValue(12);
    vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);
    expect(isWithinTimeWindow('22:00', '06:00')).toBe(false);
  });

  it('includes boundary values', () => {
    vi.spyOn(Date.prototype, 'getHours').mockReturnValue(9);
    vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);
    expect(isWithinTimeWindow('09:00', '17:00')).toBe(true);

    vi.spyOn(Date.prototype, 'getHours').mockReturnValue(17);
    vi.spyOn(Date.prototype, 'getMinutes').mockReturnValue(0);
    expect(isWithinTimeWindow('09:00', '17:00')).toBe(true);
  });
});
