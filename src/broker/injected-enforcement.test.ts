import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PolicyEngine } from './policy';
import { RateLimiter } from './rate-limiter';
import { BrokerServer } from './server';
import type { CredentialResolver } from './resolver';

/**
 * A constructor argument cannot replace an enforcement path.
 *
 * `new PolicyEngine({ rateLimiter })` took the limiter as the sole
 * implementation of the `rateLimit` constraint, and
 * `new BrokerServer(config, { policy })` took the whole engine. A limiter that
 * always answered "under the limit", or an engine whose `evaluate()` always
 * allowed, weakened the decisions below the policy that was loaded while every
 * surface still reported that policy. Both options are refused at construction;
 * the controls show the engine's own limiter and the server's own engine still
 * enforce what the policy says.
 */
describe('enforcement paths cannot be supplied by the caller', () => {
  let tmpDir: string;
  let policyFile: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-inject-'));
    policyFile = path.join(tmpDir, 'broker-policies.json');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const ONE_PER_MINUTE = [{
    id: 'r1', agentSelector: '*', credentialSelector: '*', effect: 'allow' as const,
    constraints: { rateLimit: { maxPerMinute: 1 } },
  }];

  it('PolicyEngine refuses a rateLimiter whose check() always passes', () => {
    const always = new RateLimiter();
    always.check = () => true;

    // Pre-fix this constructed, and three evaluations at maxPerMinute 1 all allowed.
    expect(() => new PolicyEngine({ policyFile, rateLimiter: always } as never))
      .toThrow(/does not accept a rateLimiter/);
  });

  it('CONTROL: the engine\'s own limiter enforces maxPerMinute 1', () => {
    const engine = new PolicyEngine({ policyFile });
    engine.loadRules(ONE_PER_MINUTE);
    expect([1, 2, 3].map(() => engine.evaluate('a1', 'K').allowed)).toEqual([true, false, false]);
  });

  it('CONTROL: an explicit rateLimiter of undefined supplies nothing and is accepted', () => {
    const engine = new PolicyEngine({ policyFile, rateLimiter: undefined } as never);
    engine.loadRules(ONE_PER_MINUTE);
    expect([1, 2].map(() => engine.evaluate('a1', 'K').allowed)).toEqual([true, false]);
  });

  it('BrokerServer refuses a policy engine that always allows', () => {
    const permissive = {
      evaluate: () => ({ allowed: true, matchedRuleId: 'any', reason: '' }),
      loadPolicies: async () => 0,
    };
    // Pre-fix this constructed and the server used `permissive` for every decision.
    expect(() => new BrokerServer(
      { socketPath: path.join(tmpDir, 'b.sock'), httpPort: 0, policyFile, auditLog: path.join(tmpDir, 'a.log') },
      { policy: permissive, resolver: {} as CredentialResolver, aimClient: null } as never,
    )).toThrow(/does not accept a policy dependency/);
  });

  it('CONTROL: BrokerServer builds its own engine from config.policyFile', () => {
    const server = new BrokerServer(
      { socketPath: path.join(tmpDir, 'b.sock'), httpPort: 0, policyFile, auditLog: path.join(tmpDir, 'a.log') },
      { resolver: {} as CredentialResolver, aimClient: null },
    );
    const engine = (server as unknown as { policy: unknown }).policy;
    expect(engine).toBeInstanceOf(PolicyEngine);
    expect((engine as unknown as { policyFile: string }).policyFile).toBe(policyFile);
  });
});
