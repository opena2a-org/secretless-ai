/**
 * Post-quantum broker assertion minting (AAP-SPEC §8.2/§9.3/§9.4/§9.5, RFC 9964).
 *
 * The byte-parity tests reproduce the AAP spec repo's published fixtures
 * (agent-authorization-protocol examples/tokens/cgt-v1.mldsa65.jwt and
 * cgt-v1.hybrid.general.json) from the published test-key seeds and fixed
 * inputs, and compare sha256 digests — proving the reference broker, the spec
 * generator (dilithium-py), and the conformance generator (@noble/post-quantum)
 * mint identical bytes under FIPS 204 deterministic signing.
 */

import { createHash, createPublicKey, createPrivateKey, verify as cryptoVerify } from 'crypto';
import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import {
  type BrokerSigningKey,
  brokerPublicAkpJwk,
  generateBrokerPqcSigningKey,
  mintBrokerAssertion,
  mintBrokerAssertionMlDsa65,
  mintHybridBrokerAssertion,
} from './assertion';
import type { ResourceBinding } from './types';

// --- the spec repo's published fixture inputs (TEST values, never production) ----

// broker-key-1 Ed25519 seed (agent-authorization-protocol examples/tokens/test-keys.json).
const ED_SEED_HEX = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
// broker-pqc-1 ML-DSA-65 seed (the FIPS 204 xi input / RFC 9964 AKP priv form).
const PQC_SEED_HEX = '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f';
const PKCS8_ED25519_PREFIX = '302e020100300506032b657004220420';

// 2026-06-01T12:00:00Z — the spec generator's fixed clock.
const IAT = 1780315200;
const JTI_CGT = '9f8e7d6c5b4a39281706f5e4d3c2b1a0';
const JTI_CGT_PQ = 'b1c2d3e4f5a60718293a4b5c6d7e8f90';

// sha256 of the published fixture bytes (examples/tokens/cgt-v1.mldsa65.jwt,
// trimmed) and of the hybrid container's signed segments
// (payload + "." + entry0.protected + "." + entry0.signature + ...).
const COMPACT_PQ_SHA256 = '9c57544f3fc7309710acd2cc9078d2669f7e79b3ab2babe9fd1965291bc95900';
const HYBRID_SHA256 = '365ac0793d9196f4c03eadf210fb0c1de47a2273ee55c9f986a15610f27163a7';

const ctx = {
  agentDid: 'did:opena2a:agent:acme/orders-reader',
  issuerChain: ['did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
} as ResolutionContext;

const binding: ResourceBinding = {
  audience: 'https://api.orders.internal',
  scope: 'orders.read',
  trustClass: 'orders:read',
  ttlSeconds: 300,
} as ResourceBinding;

function specEdKey(): BrokerSigningKey {
  return {
    kid: 'broker-key-1',
    issuer: 'https://broker.acme.example',
    privateKey: createPrivateKey({
      key: Buffer.from(PKCS8_ED25519_PREFIX + ED_SEED_HEX, 'hex'),
      format: 'der',
      type: 'pkcs8',
    }),
  };
}

function specPqcKey() {
  return generateBrokerPqcSigningKey(
    'https://broker.acme.example',
    'broker-pqc-1',
    Buffer.from(PQC_SEED_HEX, 'hex'),
  );
}

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const b64json = (segment: string) =>
  JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;

describe('broker assertion — ML-DSA-65 suite (AAP §9.3 PQ-interop lane)', () => {
  it('mints a compact ML-DSA-65 JWT that verifies and matches the published fixture bytes', () => {
    const token = mintBrokerAssertionMlDsa65(ctx, binding, specPqcKey(), IAT, JTI_CGT_PQ, {
      deterministic: true,
    });
    const [h, p, s] = token.split('.');
    expect(b64json(h)).toEqual({ alg: 'ML-DSA-65', typ: 'JWT', kid: 'broker-pqc-1' });
    expect(b64json(p)).toMatchObject({ trust_class: 'orders:read', jti: JTI_CGT_PQ });
    expect(
      ml_dsa65.verify(Buffer.from(s, 'base64url'), Buffer.from(`${h}.${p}`), specPqcKey().publicKey),
    ).toBe(true);
    // Byte parity with the spec repo's dilithium-py generator.
    expect(sha256(token)).toBe(COMPACT_PQ_SHA256);
  });

  it('hedged signing (the production default) still verifies but is non-deterministic', () => {
    const a = mintBrokerAssertionMlDsa65(ctx, binding, specPqcKey(), IAT, JTI_CGT_PQ);
    const b = mintBrokerAssertionMlDsa65(ctx, binding, specPqcKey(), IAT, JTI_CGT_PQ);
    const [h, p, s] = a.split('.');
    expect(
      ml_dsa65.verify(Buffer.from(s, 'base64url'), Buffer.from(`${h}.${p}`), specPqcKey().publicKey),
    ).toBe(true);
    expect(a).not.toBe(b);
  });

  it('refuses to mint without trustClass, like the EdDSA path', () => {
    const bad = { ...binding, trustClass: undefined } as unknown as ResourceBinding;
    expect(() => mintBrokerAssertionMlDsa65(ctx, bad, specPqcKey(), IAT, JTI_CGT_PQ)).toThrow(
      /trustClass/,
    );
  });

  it('exports the public half as an RFC 9964 AKP JWK (no priv member)', () => {
    const jwk = brokerPublicAkpJwk(specPqcKey());
    expect(jwk).toEqual({
      kty: 'AKP',
      pub: Buffer.from(specPqcKey().publicKey).toString('base64url'),
      kid: 'broker-pqc-1',
      use: 'sig',
      alg: 'ML-DSA-65',
    });
    expect(jwk).not.toHaveProperty('priv');
    expect(Buffer.from(String(jwk.pub), 'base64url')).toHaveLength(1952);
  });
});

describe('broker assertion — hybrid Ed25519 + ML-DSA-65 (AAP §9.4)', () => {
  it('mints a General JSON token whose every entry verifies, matching the published fixture bytes', () => {
    const token = mintHybridBrokerAssertion(ctx, binding, specEdKey(), specPqcKey(), IAT, JTI_CGT, {
      deterministic: true,
    });
    expect(token.signatures).toHaveLength(2);
    const [ed, pq] = token.signatures;
    expect(b64json(ed.protected)).toEqual({ alg: 'EdDSA', kid: 'broker-key-1' });
    expect(b64json(pq.protected)).toEqual({ alg: 'ML-DSA-65', kid: 'broker-pqc-1' });

    // Both suite families verify over the same payload — the §8.2 hybrid rule.
    const edPub = createPublicKey(specEdKey().privateKey);
    expect(
      cryptoVerify(
        null,
        Buffer.from(`${ed.protected}.${token.payload}`),
        edPub,
        Buffer.from(ed.signature, 'base64url'),
      ),
    ).toBe(true);
    expect(
      ml_dsa65.verify(
        Buffer.from(pq.signature, 'base64url'),
        Buffer.from(`${pq.protected}.${token.payload}`),
        specPqcKey().publicKey,
      ),
    ).toBe(true);

    // Byte parity with the spec repo's published hybrid fixture.
    const concat = `${token.payload}.${token.signatures
      .map((e) => `${e.protected}.${e.signature}`)
      .join('.')}`;
    expect(sha256(concat)).toBe(HYBRID_SHA256);

    // The payload is byte-identical to the compact EdDSA form's payload segment:
    // one claim set, two serializations (AAP §9.1 serialization is canonicalization).
    const compact = mintBrokerAssertion(ctx, binding, specEdKey(), IAT, JTI_CGT);
    expect(token.payload).toBe(compact.split('.')[1]);
  });

  it('rejects key pairs from different issuers', () => {
    const foreign = { ...specPqcKey(), issuer: 'https://other.example' };
    expect(() => mintHybridBrokerAssertion(ctx, binding, specEdKey(), foreign, IAT, JTI_CGT)).toThrow(
      /same issuer/,
    );
  });
});
