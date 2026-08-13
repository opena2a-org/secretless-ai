import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PolicyEngine, matchGlob, isWithinTimeWindow, KNOWN_RULE_KEYS, KNOWN_CONSTRAINT_KEYS, KNOWN_ENVELOPE_KEYS } from './policy';
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

/**
 * A constraint the engine cannot apply must REFUSE the rule, never widen it.
 *
 * Measured on 0.22.0 before this landed: each malformed shape below loaded as a
 * rule with `constraints: {}` and `evaluate()` returned
 * `{allowed: true, reason: 'Allowed by rule "r1"'}` — the restrictive half of
 * the operator's rule dropped, the permissive half kept, and `loadPolicies()`
 * reporting 1 so every status surface showed the policy as loaded.
 */
describe('PolicyEngine — an unappliable constraint refuses the rule', () => {
  const tmpFiles: string[] = [];

  function policyFile(constraints: unknown): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-'));
    const file = path.join(dir, 'p.json');
    fs.writeFileSync(
      file,
      JSON.stringify({
        rules: [
          {
            id: 'r1',
            agentSelector: '*',
            credentialSelector: '*',
            effect: 'allow',
            constraints,
          },
        ],
      }),
    );
    tmpFiles.push(file);
    return file;
  }

  afterEach(() => {
    for (const f of tmpFiles.splice(0)) {
      try {
        fs.rmSync(path.dirname(f), { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    }
  });

  // Each row is a shape a YAML-to-JSON conversion, a templating layer or an
  // env-var substitution actually produces.
  const MALFORMED: Array<[string, unknown]> = [
    ['timeWindow as numbers', { timeWindow: { start: 0, end: 1 } }],
    ['timeWindow not "HH:MM"', { timeWindow: { start: '0:00', end: 'noon' } }],
    ['rateLimit as a numeric string', { rateLimit: { maxPerMinute: '1' } }],
    ['rateLimit zero', { rateLimit: { maxPerMinute: 0 } }],
    ['minTrustScore as a string', { minTrustScore: '80' }],
    ['requireCapability as a number', { requireCapability: 7 }],
    ['scopeCheck as a string', { scopeCheck: 'true' }],
    ['an unknown constraint key', { maxUses: 5 }],
    ['constraints as an array', ['timeWindow']],
  ];

  for (const [label, constraints] of MALFORMED) {
    it(`refuses to load: ${label}`, () => {
      const e = new PolicyEngine({ policyFile: policyFile(constraints) });
      expect(() => e.loadPolicies()).toThrow();
    });

    /**
     * The security property, asserted separately from the throw.
     *
     * A rule that cannot be applied must never end up granting. Checking the
     * throw alone would still pass if some later change caught the error and
     * carried on with a widened rule, which is exactly the shape being fixed.
     */
    it(`never grants after: ${label}`, () => {
      const e = new PolicyEngine({ policyFile: policyFile(constraints) });
      try {
        e.loadPolicies();
      } catch {
        /* refusing to load is the fix; the assertion below is the invariant */
      }
      expect(e.evaluate('agent-x', 'STRIPE_SECRET_KEY').allowed).toBe(false);
    });
  }

  it('still loads and still ENFORCES a well-formed constraint', () => {
    // The negative direction: refusing malformed input must not have been
    // bought by refusing everything.
    const e = new PolicyEngine({ policyFile: policyFile({ timeWindow: { start: '00:00', end: '00:01' } }) });
    expect(e.loadPolicies()).toBe(1);
    expect(e.getRules()[0].constraints).toEqual({ timeWindow: { start: '00:00', end: '00:01' } });
  });

  it('accepts a rule with no constraints at all', () => {
    const e = new PolicyEngine({ policyFile: policyFile(undefined) });
    expect(e.loadPolicies()).toBe(1);
  });
});

/**
 * A rule field we do not read is refused, not ignored.
 *
 * The sibling block above closes the same fail-open one level down: a
 * constraint whose VALUE we cannot type-match. This closes the container.
 * Misspelling `constraints` left `r.constraints` undefined, so the whole
 * constraint block never ran and the rule loaded as an unconstrained ALLOW,
 * while `loadPolicies()`, `getRules()` and `/health` all reported it loaded —
 * verbatim the failure mode the constraint-key fix was written for, still
 * reachable in the build that fixed it.
 */
describe('PolicyEngine — a rule field we do not read refuses the rule', () => {
  const tmpDirs: string[] = [];

  function policyFileFor(rule: Record<string, unknown>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-toplevel-'));
    tmpDirs.push(dir);
    const file = path.join(dir, 'p.json');
    fs.writeFileSync(file, JSON.stringify({ rules: [rule] }));
    return file;
  }

  const BASE = { id: 'r1', agentSelector: '*', credentialSelector: '*', effect: 'allow' };
  // A window that has already closed, so an HONOURED constraint must deny.
  // Using a constraint that DENIES is what makes the controls discriminate:
  // a rule that loads with its constraints intact returns allowed=false, and a
  // rule that silently lost them returns allowed=true.
  const CLOSED_WINDOW = { timeWindow: { start: '00:00', end: '00:01' } };

  afterEach(() => {
    for (const d of tmpDirs.splice(0)) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  // POSITIVE CONTROLS. Both pass before and after the fix. Without them a
  // validator that refused every rule would satisfy the arms below.
  it('CONTROL: the correctly spelled container still loads and still denies', () => {
    const engine = new PolicyEngine({ policyFile: policyFileFor({ ...BASE, constraints: CLOSED_WINDOW }) });
    expect(engine.loadPolicies()).toBe(1);
    expect(engine.getRules()[0].constraints.timeWindow).toEqual(CLOSED_WINDOW.timeWindow);
    expect(engine.evaluate('agent-1', 'DEPLOY_TOKEN').allowed).toBe(false);
  });

  it('CONTROL: a rule with no constraints at all is still legitimate', () => {
    // "constraints absent" cannot itself be an error — an unconstrained allow
    // rule is a real thing an operator writes.
    const engine = new PolicyEngine({ policyFile: policyFileFor({ ...BASE }) });
    expect(engine.loadPolicies()).toBe(1);
    expect(engine.evaluate('agent-1', 'DEPLOY_TOKEN').allowed).toBe(true);
  });

  const UNKNOWN_FIELDS: Array<[string, Record<string, unknown>]> = [
    ['contraints — the measured typo', { ...BASE, contraints: CLOSED_WINDOW }],
    ['constraint — singular', { ...BASE, constraint: CLOSED_WINDOW }],
    ['a documentation annotation', { ...BASE, constraints: CLOSED_WINDOW, description: 'allow deploys' }],
    ['an invented field', { ...BASE, constraints: CLOSED_WINDOW, priority: 10 }],
    ['effect misspelled, so the real effect is absent', { ...BASE, efect: 'deny' }],
  ];

  it.each(UNKNOWN_FIELDS)('refuses a rule carrying %s', (_label, rule) => {
    const engine = new PolicyEngine({ policyFile: policyFileFor(rule) });
    expect(() => engine.loadPolicies()).toThrow();
  });

  it('the refusal names the offending field and the legal set', () => {
    const engine = new PolicyEngine({ policyFile: policyFileFor({ ...BASE, contraints: CLOSED_WINDOW }) });
    let message = '';
    try { engine.loadPolicies(); } catch (err) { message = (err as Error).message; }
    expect(message).toContain('contraints');
    expect(message).toContain('did you mean "constraints"');
    for (const key of ['id', 'agentSelector', 'credentialSelector', 'constraints', 'effect']) {
      expect(message).toContain(key);
    }
  });

  // The property, stated once: no rule that carries an unreadable field may
  // ever load. Asserting the rule SET rather than an error string, because a
  // refusal that loaded the rule anyway would still throw somewhere.
  it('nothing is loaded when a rule is refused', () => {
    const engine = new PolicyEngine({ policyFile: policyFileFor({ ...BASE, contraints: CLOSED_WINDOW }) });
    try { engine.loadPolicies(); } catch { /* expected */ }
    expect(engine.getRules()).toEqual([]);
    expect(engine.evaluate('agent-1', 'DEPLOY_TOKEN').allowed).toBe(false);
  });
});

/**
 * A constraint we parse but do not enforce is refused, not accepted.
 *
 * `scopeCheck` sat in the known-constraint set and was documented as "deny if
 * credential permissions expanded since last baseline". It could not deny:
 * `checkConstraints` called `compareToBaseline(credentialName, '', [])`, and
 * expansion is computed from that empty current-permission list, so it was
 * false for every baseline. Measured before removal — the same comparison
 * returns hasExpanded: true when handed real permissions, so the call site was
 * what disabled it, not the comparison.
 */
describe('PolicyEngine — an unenforced constraint refuses the rule', () => {
  const tmpDirs: string[] = [];

  function engineFor(constraints: unknown): PolicyEngine {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-unenforced-'));
    tmpDirs.push(dir);
    const file = path.join(dir, 'p.json');
    fs.writeFileSync(file, JSON.stringify({
      rules: [{ id: 'r1', agentSelector: '*', credentialSelector: '*', effect: 'allow', constraints }],
    }));
    return new PolicyEngine({ policyFile: file });
  }

  afterEach(() => {
    for (const d of tmpDirs.splice(0)) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  it.each([
    ['true', true],
    ['false', false],
    ['a string', 'true'],
  ])('refuses scopeCheck: %s rather than reporting a gate that is not there', (_label, value) => {
    const engine = engineFor({ scopeCheck: value });
    expect(() => engine.loadPolicies()).toThrow(/does not enforce scopeCheck/);
  });

  it('says it is unenforced, not that it is unknown', () => {
    // The distinction is the whole point: "unknown constraint" would tell an
    // operator they typed it wrong. They did not — we removed it.
    const engine = engineFor({ scopeCheck: true });
    let message = '';
    try { engine.loadPolicies(); } catch (err) { message = (err as Error).message; }
    expect(message).toContain('does not enforce');
    expect(message).not.toContain('unknown constraint');
  });

  it('CONTROL: the constraints that ARE enforced still load', () => {
    const engine = engineFor({ timeWindow: { start: '00:00', end: '23:59' }, minTrustScore: 80 });
    expect(engine.loadPolicies()).toBe(1);
    expect(engine.getRules()[0].constraints.minTrustScore).toBe(80);
  });
});

/**
 * Gate integrity: no suite may read the developer's real policy file.
 *
 * `PolicyEngine` defaults to ~/.secretless-ai/broker-policies.json, so a
 * `BrokerServer` built without an explicit `policyFile` takes its authorization
 * rules from whatever is on the machine running the tests. The AAP conformance
 * suite did exactly that and was green because that file happened to validate —
 * it started failing the moment policy validation got stricter, which means it
 * had never been measuring what it claimed. Fixing the one instance leaves the
 * class open, so this asserts the class.
 */
describe('no test constructs BrokerServer against the machine policy file', () => {
  const SRC = path.resolve(__dirname, '..');

  function testFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { out.push(...testFiles(full)); continue; }
      if (entry.name.endsWith('.test.ts')) out.push(full);
    }
    return out;
  }

  it('every `new BrokerServer(` in a test passes an explicit policyFile', () => {
    const offenders: string[] = [];
    let constructions = 0;

    for (const file of testFiles(SRC)) {
      const text = fs.readFileSync(file, 'utf-8');
      let idx = text.indexOf('new BrokerServer(');
      while (idx !== -1) {
        // Skip the literal inside this guard's own source. A real construction
        // is preceded by whitespace or `=`, never by a quote.
        if (idx > 0 && `'"\``.includes(text[idx - 1])) {
          idx = text.indexOf('new BrokerServer(', idx + 1);
          continue;
        }
        constructions++;
        // The config object is the first argument; scan to the end of the call.
        const window = text.slice(idx, idx + 600);
        if (!window.includes('policyFile')) {
          const line = text.slice(0, idx).split('\n').length;
          offenders.push(`${path.relative(SRC, file)}:${line}`);
        }
        idx = text.indexOf('new BrokerServer(', idx + 1);
      }
    }

    // A guard that found no constructions would pass whether or not the class
    // exists. Pin it on there being something to check.
    expect(constructions).toBeGreaterThan(0);
    expect(offenders).toEqual([]);
  });
});

/**
 * The same predicate at every nesting level of operator-authored input.
 *
 * This defect has now been found four times, each a level further out or in:
 * a constraint VALUE we could not type-match; the constraints CONTAINER
 * misspelled; a sibling of `rules` in the ENVELOPE; and a SUB-KEY inside a
 * structured constraint. Each fix matched the last instance rather than the
 * class, which is why there was always another one. The question these assert
 * is level-independent: is there an input that makes the rule WIDER than the
 * operator wrote, while every surface reports it loaded?
 */
describe('PolicyEngine — no level of policy input silently drops what it cannot read', () => {
  const tmpDirs: string[] = [];

  function engineFor(doc: unknown): PolicyEngine {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-levels-'));
    tmpDirs.push(dir);
    const file = path.join(dir, 'p.json');
    fs.writeFileSync(file, JSON.stringify(doc));
    return new PolicyEngine({ policyFile: file });
  }

  afterEach(() => {
    for (const d of tmpDirs.splice(0)) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  const ALLOW_ALL = { id: 'a1', agentSelector: '*', credentialSelector: '*', effect: 'allow' };
  const DENY_ALL = { id: 'deny-all', agentSelector: '*', credentialSelector: '*', effect: 'deny' };

  describe('the envelope', () => {
    it('CONTROL: a deny rule under the real key denies', () => {
      const engine = engineFor({ version: 1, rules: [DENY_ALL] });
      expect(engine.loadPolicies()).toBe(1);
      expect(engine.evaluate('agent-1', 'AWS_KEY').allowed).toBe(false);
    });

    it('refuses a sibling of `rules` rather than loading only half the policy', () => {
      // Measured pre-fix: loaded=1, allowed=true, matched the allow rule. The
      // operator's deny rules were never in the engine and nothing said so.
      const engine = engineFor({ rules: [ALLOW_ALL], denyRules: [DENY_ALL] });
      expect(() => engine.loadPolicies()).toThrow(/denyRules/);
    });

    it('a bare array is still accepted', () => {
      const engine = engineFor([DENY_ALL]);
      expect(engine.loadPolicies()).toBe(1);
    });
  });

  describe('a constraint sub-key', () => {
    const base = { id: 'r1', agentSelector: '*', credentialSelector: '*', effect: 'allow' };

    it('CONTROL: the sub-keys we do read still load and still enforce', () => {
      const engine = engineFor({ rules: [{ ...base, constraints: { timeWindow: { start: '00:00', end: '00:01' } } }] });
      expect(engine.loadPolicies()).toBe(1);
      expect(engine.evaluate('agent-1', 'AWS_KEY').allowed).toBe(false);
    });

    it.each([
      ['rateLimit.maxPerHour — a cap we would silently drop', { rateLimit: { maxPerMinute: 60, maxPerHour: 1 } }],
      ['timeWindow.End — a near-miss of end', { timeWindow: { start: '00:00', end: '23:59', End: '00:01' } }],
      ['timeWindow.days — a restriction we do not implement', { timeWindow: { start: '00:00', end: '23:59', days: ['sun'] } }],
      ['timeWindow.timezone — the window is server-local', { timeWindow: { start: '00:00', end: '23:59', timezone: 'UTC' } }],
    ])('refuses %s', (_label, constraints) => {
      const engine = engineFor({ rules: [{ ...base, constraints }] });
      expect(() => engine.loadPolicies()).toThrow();
    });
  });

  describe('an empty value that deletes the restriction', () => {
    const base = { id: 'r1', agentSelector: '*', credentialSelector: '*', effect: 'allow' };

    it('CONTROL: a named capability with no identity denies', () => {
      const engine = engineFor({ rules: [{ ...base, constraints: { requireCapability: 'deploy' } }] });
      expect(engine.loadPolicies()).toBe(1);
      expect(engine.evaluate('agent-1', 'AWS_KEY').allowed).toBe(false);
    });

    it('refuses requireCapability: "" rather than skipping the gate', () => {
      // Pre-fix the enforcement branch guarded on truthiness, so "" skipped the
      // whole block INCLUDING its fail-closed no-identity arm: allowed=true.
      const engine = engineFor({ rules: [{ ...base, constraints: { requireCapability: '' } }] });
      expect(() => engine.loadPolicies()).toThrow(/must not be empty/);
    });

    it('refuses an empty selector, which matches nothing and so never denies', () => {
      const engine = engineFor({ rules: [{ ...DENY_ALL, agentSelector: '' }] });
      expect(() => engine.loadPolicies()).toThrow(/non-empty/);
    });
  });
});

/**
 * The pin CISO found claimed but absent.
 *
 * `KNOWN_CONSTRAINT_KEYS` carried a comment stating it was "pinned by a test
 * against PolicyConstraints". No such test existed — the symbol appeared in one
 * file and no test file. A source comment asserting a test we do not have is
 * the same class as a scanner reporting clean without looking, and it was
 * shipped inside the commit fixing an authorization fail-open.
 *
 * The oracle is the TYPE DECLARATION, read from source. Deriving it from the
 * runtime Set would let the two agree by construction and pin nothing.
 */
describe('the key allowlists are pinned to the type declarations', () => {
  const TYPES = fs.readFileSync(path.resolve(__dirname, 'types.ts'), 'utf-8');

  function fieldsOf(interfaceName: string): string[] {
    const start = TYPES.indexOf(`export interface ${interfaceName} {`);
    expect(start, `${interfaceName} not found in types.ts`).toBeGreaterThan(-1);
    const body = TYPES.slice(start, TYPES.indexOf('\n}', start));
    return [...body.matchAll(/^\s{2}([a-zA-Z][a-zA-Z0-9]*)\??:/gm)].map((m) => m[1]);
  }

  it('KNOWN_RULE_KEYS is exactly the fields of PolicyRule', () => {
    const declared = fieldsOf('PolicyRule');
    // Guard the guard: a regex that stopped matching would make this vacuous.
    expect(declared.length).toBe(5);
    expect([...KNOWN_RULE_KEYS].sort()).toEqual(declared.sort());
  });

  it('KNOWN_CONSTRAINT_KEYS is exactly the fields of PolicyConstraints', () => {
    const declared = fieldsOf('PolicyConstraints');
    expect(declared.length).toBeGreaterThan(0);
    expect([...KNOWN_CONSTRAINT_KEYS].sort()).toEqual(declared.sort());
  });

  it('a constraint in the promise set has an enforcement branch', () => {
    // The set's own comment calls it "a promise about what is applied, not a
    // list of what parses". scopeCheck sat in it for thirteen published
    // versions while its branch could not deny. This asserts the promise.
    const impl = fs.readFileSync(path.resolve(__dirname, 'policy.ts'), 'utf-8');
    const checkConstraints = impl.slice(impl.indexOf('private checkConstraints('), impl.indexOf('export function matchGlob'));
    for (const key of KNOWN_CONSTRAINT_KEYS) {
      expect(checkConstraints, `${key} is promised but never read in checkConstraints`).toContain(`constraints.${key}`);
    }
  });

  it('KNOWN_ENVELOPE_KEYS covers what the documented example writes', () => {
    const doc = fs.readFileSync(path.resolve(__dirname, '..', '..', 'docs', 'use-cases', 'run-broker.md'), 'utf-8');
    // The example a user copies must load. If the docs grow a key, this fails
    // before an operator's file does.
    for (const key of ['version', 'rules']) {
      expect(doc).toContain(`"${key}"`);
      expect(KNOWN_ENVELOPE_KEYS.has(key)).toBe(true);
    }
  });
});
