import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import {
  LocalAtxVerifier,
  canonicalPayload,
  canonicalPayloadV11,
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

// ---------------------------------------------------------------------------
// ATX v1.1 (JCS / RFC 8785). The verifier signs JCS(TBS), so capabilities,
// scanSummary, issuerChain, and publisher are integrity-protected.
// ---------------------------------------------------------------------------

// The credential that projects to the jcs-vectors baseline vector. Its canonical
// bytes are pinned across all four implementations.
const V11_BASELINE: Omit<Atx, 'signatures'> = {
  atcVersion: '1.1',
  agentId: 'agent_conformance_test_001',
  agentDid: 'did:opena2a:agent:agent_conformance_test_001',
  publisher: 'opena2a-conformance',
  publisherDid: 'did:opena2a:publisher:opena2a-conformance',
  version: '1.0.0',
  contentHash: '0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff',
  buildAttestation: 'https://slsa.dev/provenance/v1#opena2a-conformance',
  issuerDid: 'did:opena2a:authority:opena2a.org',
  issuerChain: ['did:opena2a:authority:opena2a.org-root', 'did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
  trustScore: 87.5,
  issuedAt: '2026-05-23T00:00:00Z',
  expiresAt: '2099-12-31T23:59:59Z',
  capabilities: ['read:public', 'write:owned'],
  behavioralProfile: { checksum: 'sha256:ghi789', generatedAt: '2026-05-19T00:00:00Z', observationDays: 14 },
  scanSummary: {
    hma: 'passed',
    criticalFindings: 0,
    highFindings: 0,
    secretless: 'clean',
    cryptoServe: 'no-weak-crypto',
    oasbLevel: 'L1',
  },
};

// Pinned in atx-conformance/jcs-vectors/vectors/01-baseline.json. The broker MUST
// reproduce these exact bytes or it will reject credentials the registry signs.
const V11_BASELINE_CANONICAL_HEX =
  '7b226167656e74446964223a226469643a6f70656e6132613a6167656e743a6167656e745f636f6e666f726d616e63655f746573745f303031222c226167656e744964223a226167656e745f636f6e666f726d616e63655f746573745f303031222c2261746356657273696f6e223a22312e31222c226265686176696f72616c50726f66696c65223a7b22636865636b73756d223a227368613235363a676869373839222c2267656e6572617465644174223a22323032362d30352d31395430303a30303a30305a222c226f62736572766174696f6e44617973223a31347d2c226275696c644174746573746174696f6e223a2268747470733a2f2f736c73612e6465762f70726f76656e616e63652f7631236f70656e6132612d636f6e666f726d616e6365222c226361706162696c6974696573223a5b22726561643a7075626c6963222c2277726974653a6f776e6564225d2c22636f6e74656e7448617368223a2230303030313131313232323233333333343434343535353536363636373737373838383839393939616161616262626263636363646464646565656566666666222c22657870697265734174223a22323039392d31322d33315432333a35393a35395a222c226973737565644174223a22323032362d30352d32335430303a30303a30305a222c22697373756572436861696e223a5b226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f72672d726f6f74222c226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267225d2c22697373756572446964223a226469643a6f70656e6132613a617574686f726974793a6f70656e6132612e6f7267222c227075626c6973686572223a226f70656e6132612d636f6e666f726d616e6365222c227075626c6973686572446964223a226469643a6f70656e6132613a7075626c69736865723a6f70656e6132612d636f6e666f726d616e6365222c227363616e53756d6d617279223a7b22637269746963616c46696e64696e6773223a302c2263727970746f5365727665223a226e6f2d7765616b2d63727970746f222c226869676846696e64696e6773223a302c22686d61223a22706173736564222c226f6173624c6576656c223a224c31222c227365637265746c657373223a22636c65616e227d2c2274727573744c6576656c223a342c22747275737453636f7265223a2238372e353030303030222c2276657273696f6e223a22312e302e30227d';

/** Sign a v1.1 ATX over its JCS(TBS) with a fresh key; mutate after signing for tamper tests. */
function makeSignedV11Atx(mutate?: (a: Atx) => void): { atx: Atx; pubHex: string } {
  const { privateKey, pubHex } = makeKeypair();
  const atx: Atx = { ...V11_BASELINE, signatures: [] };
  const sig = crypto.sign(null, canonicalPayloadV11(atx), privateKey);
  atx.signatures = [{ keyId: 'test#ed25519', algorithm: 'Ed25519', value: sig.toString('base64') }];
  if (mutate) mutate(atx);
  return { atx, pubHex };
}

describe('ATX v1.1 (JCS)', () => {
  it('reproduces the pinned jcs-vectors baseline canonical bytes', () => {
    const atx: Atx = { ...V11_BASELINE, signatures: [] };
    expect(canonicalPayloadV11(atx).toString('hex')).toBe(V11_BASELINE_CANONICAL_HEX);
  });

  it('accepts a valid v1.1 credential and marks capabilities as signed', () => {
    const { atx, pubHex } = makeSignedV11Atx();
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(true);
    expect(r.context?.signedCapabilities).toBe(true);
    expect(r.context?.capabilities).toEqual(['read:public', 'write:owned']);
  });

  it('marks v1.0 capabilities as unsigned', () => {
    const { atx, pubHex } = makeSignedAtx();
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(true);
    expect(r.context?.signedCapabilities).toBe(false);
  });

  it('rejects a v1.1 credential whose capabilities were escalated after signing', () => {
    const { atx, pubHex } = makeSignedV11Atx((a) => {
      a.capabilities = ['read:public', 'write:owned', 'admin:all'];
    });
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('SIGNATURE_INVALID');
  });

  it('rejects tampering of other now-signed fields (scanSummary, issuerChain, publisher)', () => {
    const mutations: Array<(a: Atx) => void> = [
      (a) => { a.scanSummary = { ...a.scanSummary, oasbLevel: 'L3' }; },
      (a) => { a.issuerChain = ['did:opena2a:authority:opena2a.org', 'did:opena2a:authority:opena2a.org-root']; },
      (a) => { a.publisher = 'evil-corp'; },
    ];
    for (const mutate of mutations) {
      const { atx, pubHex } = makeSignedV11Atx(mutate);
      const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
      expect(r.valid).toBe(false);
      expect(r.rejectCategory).toBe('SIGNATURE_INVALID');
    }
  });

  it('fails closed on a 1.1 -> 1.0 downgrade', () => {
    const { atx, pubHex } = makeSignedV11Atx((a) => { a.atcVersion = '1.0'; });
    const r = new LocalAtxVerifier(makeTrustAnchors(pubHex)).verify(atx);
    expect(r.valid).toBe(false);
  });
});
