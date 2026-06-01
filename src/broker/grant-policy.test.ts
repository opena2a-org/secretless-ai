import { describe, it, expect } from 'vitest';
import { GrantPolicy, type GrantBinding } from './grant-policy';
import type { ResolutionContext } from './atx';

const CTX: ResolutionContext = {
  agentId: 'aim_orders_reader',
  agentDid: 'did:opena2a:agent:acme/orders-reader',
  issuerDid: 'did:opena2a:authority:opena2a.org',
  issuerChain: ['did:opena2a:authority:partner.example', 'did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
  trustScore: 0.95,
  capabilities: ['orders:read'],
  oasbLevel: 'L2',
};

const BINDING: GrantBinding = {
  grant: 'grant://orders-db',
  match: {
    trustClass: 'orders:read',
    minTrustLevel: 3,
    oasbLevel: '>=L2',
    issuerChainIncludes: { partnersSet: 'trusted-partners' },
    jurisdiction: { in: ['us', 'eu'] },
  },
  resolve: {
    mode: 'exchange',
    providerId: 'orders-idp',
    scope: 'orders.read',
    audience: 'https://api.orders.internal',
    ttlSeconds: 300,
  },
};

describe('GrantPolicy (decision/enforcement split, AAP §3/§7)', () => {
  it('grants when the ATX satisfies the enforced predicates', () => {
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', CTX);
    expect(r.allowed).toBe(true);
    expect(r.binding?.resolve.mode).toBe('exchange');
  });

  it('default-denies an unknown grant', () => {
    const r = new GrantPolicy([BINDING]).evaluate('payroll-db', CTX);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/default deny/);
  });

  it('denies when the ATX lacks the required trust class', () => {
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', { ...CTX, capabilities: ['weather:read'] });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/trust class/);
  });

  it('denies when below the minimum trust level', () => {
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', { ...CTX, trustLevel: 1 });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/trust level/);
  });

  it('denies when below the required OASB level', () => {
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', { ...CTX, oasbLevel: 'L1' });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/OASB/);
  });

  it('parses but does not enforce federation/jurisdiction predicates in v1', () => {
    // An out-of-jurisdiction agent (v3 concern) and a non-partner-only chain still pass v1,
    // because only trustClass/minTrustLevel/oasbLevel are enforced (AAP §7.1).
    const r = new GrantPolicy([BINDING]).evaluate('orders-db', {
      ...CTX,
      jurisdiction: ['cn'],
      issuerChain: ['did:opena2a:authority:opena2a.org'],
    });
    expect(r.allowed).toBe(true);
  });
});
