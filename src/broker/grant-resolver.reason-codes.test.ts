/**
 * Every way a grant resolution ends is recorded with a code from GRANT_AUDIT_REASONS, and every
 * code in that set is reached by one of them. The grant policy names the predicate that denied
 * with a code as well, so the record keeps which check decided without the text that explains it.
 */

import * as crypto from 'crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
  Atx,
  AtxVerificationResult,
  AtxVerifier,
  ResolutionContext,
} from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import type { AimClient } from './aim-client';
import type { AuditLogger } from './audit';
import { generateBrokerSigningKey } from './cpi/assertion';
import { ExchangeProvider } from './cpi/exchange';
import { MapProviderRegistry } from './cpi/registry';
import type { CpiMode, CredentialProvider, ScopedCredential } from './cpi/types';
import { GrantPolicy, type GrantEvaluation } from './grant-policy';
import { GrantResolver } from './grant-resolver';
import { GRANT_AUDIT_REASONS, type AuditEntry } from './types';
import { EphemeralWorker, type AgentOperation, type DownstreamCaller } from './worker';

const CTX: ResolutionContext = {
  agentId: 'aim_payments_agent',
  agentDid: 'did:opena2a:agent:acme/payments-agent',
  issuerDid: 'did:opena2a:authority:opena2a.org',
  issuerChain: ['did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
  trustScore: 0.95,
  capabilities: ['payments:write'],
  oasbLevel: 'L2',
  signedCapabilities: true,
};

const PAYMENT: AgentOperation = {
  method: 'POST',
  path: '/payments',
  body: { payee: 'Fictional Payee Ltd', amount: '120.00' },
};

function bindingDoc(mode: CpiMode = 'exchange'): Record<string, unknown> {
  return {
    grant: 'grant://payments',
    match: { trustClass: 'payments:write', minTrustLevel: 3, oasbLevel: '>=L2' },
    resolve: {
      mode,
      providerId: 'payments-idp',
      scope: 'payments.write',
      audience: 'https://bank.example',
      ttlSeconds: 300,
    },
  };
}

function credential(): ScopedCredential {
  return { token: crypto.randomBytes(16).toString('hex'), tokenType: 'Bearer', expiresInSeconds: 300 };
}

function providerFor(mode: CpiMode): CredentialProvider {
  return { modes: [mode], resolve: async () => credential() };
}

const SIGNING_KEY = generateBrokerSigningKey('https://broker.bank.example', 'broker-key-1');

function exchange(): CredentialProvider {
  return new ExchangeProvider({ tokenEndpoint: 'https://idp.bank.example/token' }, SIGNING_KEY, {
    exchange: async () => ({ access_token: crypto.randomBytes(16).toString('hex'), expires_in: 300 }),
  });
}

function fails(): never {
  throw new Error('a failure');
}

const verifying = (result: AtxVerificationResult): AtxVerifier => ({ verify: () => result });

function aimSaying(verified: boolean): AimClient {
  return {
    getAgentIdentity: async () => ({ agentId: CTX.agentId, trustScore: 0.9, capabilities: [], verified }),
  } as unknown as AimClient;
}

/** A loaded policy whose evaluation answers `answer` (or throws, when `answer` throws). */
function policyAnswering(answer: () => GrantEvaluation): GrantPolicy {
  const policy = new GrantPolicy([bindingDoc()]);
  vi.spyOn(policy, 'evaluate').mockImplementation(answer);
  return policy;
}

interface Scenario {
  verifier?: AtxVerifier;
  context?: Record<string, unknown>;
  aim?: AimClient;
  policy?: GrantPolicy;
  mode?: CpiMode;
  /** `null`: no provider is registered under the binding's provider id. */
  provider?: CredentialProvider | null;
  caller?: DownstreamCaller;
  grant?: string;
  operation?: AgentOperation;
}

interface Ended {
  entries: AuditEntry[];
  /** How many times the downstream caller ran. */
  calls: number;
}

async function run(s: Scenario): Promise<Ended> {
  const entries: AuditEntry[] = [];
  let calls = 0;
  const ctx = { ...CTX, ...s.context } as ResolutionContext;
  const caller: DownstreamCaller = s.caller ?? {
    deliversSalt: true,
    call: async () => ({ status: 201, body: { paymentId: 'pay-1' } }),
  };
  const counting: DownstreamCaller = {
    deliversSalt: caller.deliversSalt,
    call: (...args) => {
      calls += 1;
      return caller.call(...args);
    },
  };
  const providers = new MapProviderRegistry();
  if (s.provider !== null) providers.register('payments-idp', s.provider ?? exchange());
  const resolver = new GrantResolver({
    verifier: s.verifier ?? verifying({ valid: true, context: ctx }),
    policy: s.policy ?? new GrantPolicy([bindingDoc(s.mode)]),
    providers,
    worker: new EphemeralWorker(counting),
    audit: { log: (entry: AuditEntry) => void entries.push(entry) } as unknown as AuditLogger,
    aimClient: s.aim ?? null,
  });
  await resolver.resolve({
    agentId: 'did:example:payments-agent',
    atx: {} as Atx,
    grant: s.grant ?? 'grant://payments',
    operation: s.operation ?? PAYMENT,
  });
  return { entries, calls };
}

/** [how the resolution ends, the scenario, the code its record carries]. */
const ENDINGS: Array<[string, () => Scenario, string]> = [
  ...(
    [
      ['UNSUPPORTED_VERSION', 'atx-unsupported-version'],
      ['EXPIRED', 'atx-expired'],
      ['REVOKED', 'atx-revoked'],
      ['UNTRUSTED_ISSUER', 'atx-untrusted-issuer'],
      ['SIGNATURE_INVALID', 'atx-signature-invalid'],
      ['MALFORMED', 'atx-malformed'],
    ] as const
  ).map(([category, code]): [string, () => Scenario, string] => [
    `an ATX rejected as ${category}`,
    () => ({ verifier: verifying({ valid: false, rejectCategory: category }) }),
    code,
  ]),
  ['an ATX rejected with no category', () => ({ verifier: verifying({ valid: false }) }), 'atx-rejected'],
  [
    'an ATX rejected with a category this build does not know',
    () => ({ verifier: verifying({ valid: false, rejectCategory: 'toString' as never }) }),
    'atx-rejected',
  ],
  ['an ATX that verifies with no context', () => ({ verifier: verifying({ valid: true }) }), 'atx-rejected'],
  ['a verifier that throws', () => ({ verifier: { verify: fails } }), 'atx-verifier-error'],
  ['an agent AIM reports as not verified', () => ({ aim: aimSaying(false) }), 'aim-agent-unverified'],
  [
    'an AIM lookup that throws',
    () => ({ aim: { getAgentIdentity: async () => fails() } as unknown as AimClient }),
    'aim-lookup-error',
  ],
  ['a grant string that is not a grant reference', () => ({ grant: 'secret://vault/payments' }), 'grant-reference-invalid'],
  ['a grant reference no binding governs', () => ({ grant: 'grant://refunds' }), 'policy-no-binding'],
  [
    'a credential that does not sign its capabilities',
    () => ({ context: { signedCapabilities: false } }),
    'policy-capabilities-unsigned',
  ],
  [
    'a credential with no capability list',
    () => ({ context: { capabilities: 'payments:write' } }),
    'policy-no-capability-list',
  ],
  [
    'a credential without the trust class',
    () => ({ context: { capabilities: ['payments:read'] } }),
    'policy-trust-class-missing',
  ],
  [
    'a trust level that is not a number',
    () => ({ context: { trustLevel: Number.NaN } }),
    'policy-trust-level-not-number',
  ],
  ['a trust level below the minimum', () => ({ context: { trustLevel: 2 } }), 'policy-trust-level-below-minimum'],
  ['no OASB level', () => ({ context: { oasbLevel: undefined } }), 'policy-oasb-level-absent'],
  ['an OASB level no floor ranks', () => ({ context: { oasbLevel: 'L9' } }), 'policy-oasb-level-unrankable'],
  ['an OASB level below the floor', () => ({ context: { oasbLevel: 'L1' } }), 'policy-oasb-level-below-floor'],
  [
    'a denial whose code this build does not know',
    () => ({
      policy: policyAnswering(
        () => ({ allowed: false, reason: 'denied', code: 'not-a-code' }) as unknown as GrantEvaluation,
      ),
    }),
    'policy-denied',
  ],
  ['a policy that throws', () => ({ policy: policyAnswering(fails) }), 'policy-error'],
  ['no provider registered for the binding', () => ({ provider: null }), 'provider-not-registered'],
  ['a provider without the binding mode', () => ({ provider: providerFor('retrieve') }), 'provider-mode-unsupported'],
  [
    'a provider that throws',
    () => ({ provider: { modes: ['exchange'], resolve: async () => fails() } }),
    'provider-error',
  ],
  [
    'a provider that returns no credential',
    () => ({
      provider: { modes: ['exchange'], resolve: async () => null as unknown as ScopedCredential },
    }),
    'provider-returned-no-credential',
  ],
  [
    'an operation path that leaves the origin',
    () => ({ operation: { method: 'GET', path: '//elsewhere.example/collect' } }),
    'operation-path-refused',
  ],
  [
    'an operation outside the JSON value space',
    () => ({ operation: { method: 'POST', path: '/payments', body: { when: new Date(0) } } }),
    'operation-not-canonical',
  ],
  [
    'a downstream call that fails',
    () => ({ caller: { deliversSalt: true, call: async () => fails() } }),
    'downstream-error',
  ],
  ['an operation resolved in Exchange mode', () => ({}), 'resolved-exchange'],
  [
    'an operation resolved in Retrieve mode',
    () => ({ mode: 'retrieve', provider: providerFor('retrieve') }),
    'resolved-retrieve',
  ],
  [
    'an operation resolved in Assume mode',
    () => ({ mode: 'assume', provider: providerFor('assume') }),
    'resolved-assume',
  ],
];

afterEach(() => {
  vi.restoreAllMocks();
});

describe('grant record: the reason is a code from a closed set', () => {
  it.each(ENDINGS)('records %s as %s', async (_label, scenario, code) => {
    const { entries } = await run(scenario());
    expect(entries.map((entry) => entry.reason)).toEqual([code]);
    expect(entries[0].result).toBe(code.startsWith('resolved-') ? 'allowed' : 'denied');
  });

  it('reaches every code in the set, and only codes in the set', () => {
    expect([...new Set(ENDINGS.map(([, , code]) => code))].sort()).toEqual(
      [...GRANT_AUDIT_REASONS].sort(),
    );
  });

  it('holds codes only: lower-case words joined by hyphens, each listed once', () => {
    expect(GRANT_AUDIT_REASONS.every((code) => /^[a-z]+(-[a-z]+)*$/.test(code))).toBe(true);
    expect(new Set(GRANT_AUDIT_REASONS).size).toBe(GRANT_AUDIT_REASONS.length);
  });

  it('forwards nothing and commits to nothing when the path is refused or the operation has no JSON form', async () => {
    const refused = await run({ operation: { method: 'GET', path: '@elsewhere.example/collect' } });
    const odd = await run({
      operation: { method: 'POST', path: '/payments', body: { amount: Number.NaN } },
    });
    for (const ended of [refused, odd]) {
      expect(ended.calls).toBe(0);
      expect('operationCommitment' in ended.entries[0]).toBe(false);
    }
  });

  it('keeps the commitment when the downstream call fails: the resource may hold the salt', async () => {
    const ended = await run({ caller: { deliversSalt: true, call: async () => fails() } });
    expect(ended.calls).toBe(1);
    expect(ended.entries[0].operationCommitment).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('GrantPolicy: the code a denial names', () => {
  it('names policy-no-binding for a grant name that is not a string, and no code when it grants', () => {
    const policy = new GrantPolicy([bindingDoc()]);
    expect(policy.evaluate(42 as unknown as string, CTX).code).toBe('policy-no-binding');
    const granted = policy.evaluate('payments', CTX);
    expect(granted.allowed).toBe(true);
    expect(granted.code).toBeUndefined();
  });

  it('configures exactly the grant references its bindings govern', () => {
    const policy = new GrantPolicy([bindingDoc()]);
    expect(policy.configures('grant://payments')).toBe(true);
    for (const other of ['grant://refunds', 'grant://payments ', 'GRANT://payments', 'payments', 42, null]) {
      expect(policy.configures(other)).toBe(false);
    }
  });
});
