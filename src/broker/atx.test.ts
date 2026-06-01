import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import {
  LocalAtxVerifier,
  canonicalPayload,
  normalizeRfc3339,
  type Atx,
  type AtxTrustAnchors,
} from './atx';

// ---------------------------------------------------------------------------
// Shared AAP test fixtures. Kept inside a *.test.ts file so they are excluded
// from the build (tsconfig excludes src/**/*.test.ts) and never ship in dist.
// ---------------------------------------------------------------------------

export const TEST_ISSUER = 'did:opena2a:authority:opena2a.org';
export const TEST_CLOCK = new Date('2026-06-01T12:00:00Z');

export function makeKeypair(): { privateKey: crypto.KeyObject; pubHex: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const pubHex = Buffer.from(jwk.x, 'base64url').toString('hex');
  return { privateKey, pubHex };
}

/** Build a valid, Ed25519-signed ATX (and the matching public key hex). */
export function makeSignedAtx(overrides: Partial<Atx> = {}): { atx: Atx; pubHex: string } {
  const { privateKey, pubHex } = makeKeypair();
  const base: Atx = {
    atcVersion: '1.0',
    agentId: 'aim_orders_reader',
    agentDid: 'did:opena2a:agent:acme/orders-reader',
    version: '1.0.0',
    contentHash: 'sha256:abc123',
    buildAttestation: 'sha256:def456',
    issuerDid: TEST_ISSUER,
    issuerChain: [TEST_ISSUER],
    trustLevel: 4,
    trustScore: 0.95,
    issuedAt: '2026-05-25T00:00:00Z',
    expiresAt: '2026-06-08T00:00:00Z',
    capabilities: ['orders:read'],
    scanSummary: { oasbLevel: 'L2' },
    signatures: [],
    ...overrides,
  };
  const sig = crypto.sign(null, canonicalPayload(base), privateKey);
  base.signatures = [{ keyId: 'test#ed25519', algorithm: 'Ed25519', value: sig.toString('base64') }];
  return { atx: base, pubHex };
}

export function makeTrustAnchors(
  pubHex: string,
  extra: Partial<AtxTrustAnchors> = {},
): AtxTrustAnchors {
  return {
    trustedIssuers: [TEST_ISSUER],
    publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: pubHex }],
    crl: { entries: [] },
    now: () => TEST_CLOCK,
    ...extra,
  };
}

// ---------------------------------------------------------------------------

describe('LocalAtxVerifier', () => {
  it('accepts a valid Ed25519-signed ATX and derives a backend-free context', () => {
    const { atx, pubHex } = makeSignedAtx();
    const result = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);

    expect(result.valid).toBe(true);
    expect(result.context).toMatchObject({
      agentId: 'aim_orders_reader',
      issuerDid: TEST_ISSUER,
      trustLevel: 4,
      capabilities: ['orders:read'],
      oasbLevel: 'L2',
    });
    // The derived context must not carry any backend/host/token fields.
    expect(JSON.stringify(result.context)).not.toMatch(/token|secret|host|password|endpoint/i);
  });

  it('rejects an unsupported schema version', () => {
    const { atx, pubHex } = makeSignedAtx({ atcVersion: '2.0' });
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('UNSUPPORTED_VERSION');
  });

  it('rejects an expired ATX', () => {
    const { atx, pubHex } = makeSignedAtx({ expiresAt: '2026-05-01T00:00:00Z' });
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('EXPIRED');
  });

  it('rejects a revoked ATX (revoked field)', () => {
    const { atx, pubHex } = makeSignedAtx({ revoked: true });
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('REVOKED');
  });

  it('rejects an ATX whose agent is on the CRL', () => {
    const { atx, pubHex } = makeSignedAtx();
    const anchors = makeTrustAnchors(pubHex, {
      crl: { entries: [{ agentId: 'aim_orders_reader', reason: 'compromise' }] },
    });
    const r = new LocalAtxVerifier(anchors).verify(atx);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('REVOKED');
  });

  it('rejects an untrusted issuer', () => {
    const { atx, pubHex } = makeSignedAtx({ issuerDid: 'did:opena2a:authority:attacker.example' });
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('UNTRUSTED_ISSUER');
  });

  it('rejects a tampered signature', () => {
    const { atx, pubHex } = makeSignedAtx();
    // Flip the payload after signing: change trustScore so canonical form no longer matches.
    const tampered: Atx = { ...atx, trustScore: 0.10 };
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(tampered);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('SIGNATURE_INVALID');
  });

  it('rejects when no public key matches', () => {
    const { atx } = makeSignedAtx();
    const other = makeKeypair();
    const r = new LocalAtxVerifier(makeTrustAnchors(other.pubHex)).verify(atx);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('SIGNATURE_INVALID');
  });

  it('records ML-DSA-65 presence without silently skipping it', () => {
    const { atx, pubHex } = makeSignedAtx();
    atx.signatures.push({ keyId: 'test#pqc', algorithm: 'ML-DSA-65', value: 'AA==' });
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(true);
    expect(r.mldsaPresent).toBe(true);
  });
});

describe('canonical form', () => {
  it('matches the documented Go/Python pipe-joined order with %.6f trustScore', () => {
    const { atx } = makeSignedAtx({ trustScore: 0.5 });
    const payload = canonicalPayload(atx).toString('utf-8');
    expect(payload).toBe(
      'aim_orders_reader|did:opena2a:agent:acme/orders-reader|1.0.0|sha256:abc123|' +
        'sha256:def456|did:opena2a:authority:opena2a.org|4|0.500000|' +
        '2026-05-25T00:00:00Z|2026-06-08T00:00:00Z|1.0',
    );
  });

  it('normalizes RFC 3339 to seconds-precision UTC Z', () => {
    expect(normalizeRfc3339('2026-06-08T00:00:00.123Z')).toBe('2026-06-08T00:00:00Z');
    expect(normalizeRfc3339('2026-06-08T02:00:00+02:00')).toBe('2026-06-08T00:00:00Z');
  });
});
