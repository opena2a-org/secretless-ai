/**
 * Post-quantum broker assertion minting (AAP-SPEC §8.2/§9.3/§9.4/§9.5, RFC 9964).
 *
 * These tests mint from the AAP conformance suite's published test keys and
 * fixture inputs and check that every signature verifies. Byte parity with the
 * suite's fixtures, for these two paths and the compact EdDSA one, is asserted
 * in ./assertion.conformance.test.ts against the vendored copies; this file
 * carries no digest of its own.
 */

import { createPublicKey, verify as cryptoVerify } from 'crypto';
import { describe, expect, it } from 'vitest';
import {
  brokerPublicAkpJwk,
  mintBrokerAssertion,
  mintBrokerAssertionMlDsa65,
  mintHybridBrokerAssertion,
} from './assertion';
import {
  CGT_BINDING as binding,
  CGT_CONTEXT as ctx,
  CGT_IAT as IAT,
  CGT_JTI as JTI_CGT,
  CGT_PQ_JTI as JTI_CGT_PQ,
  publishedEdKey as specEdKey,
  publishedPqcKey as specPqcKey,
} from './conformance-vectors.test-support';
import type { ResourceBinding } from './types';

// @noble/post-quantum is ESM-only and this file compiles as CommonJS, so it
// loads through require(esm), as ./assertion.ts does.
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js') as typeof import(
  '@noble/post-quantum/ml-dsa.js',
  { with: { 'resolution-mode': 'import' } }
);

const b64json = (segment: string) =>
  JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;

describe('broker assertion — ML-DSA-65 suite (AAP §9.3 PQ-interop lane)', () => {
  it('mints a compact ML-DSA-65 JWT that verifies under the published key', () => {
    const token = mintBrokerAssertionMlDsa65(ctx, binding, specPqcKey(), IAT, JTI_CGT_PQ, {
      deterministic: true,
    });
    const [h, p, s] = token.split('.');
    expect(b64json(h)).toEqual({ alg: 'ML-DSA-65', typ: 'JWT', kid: 'broker-pqc-1' });
    expect(b64json(p)).toMatchObject({ trust_class: 'orders:read', jti: JTI_CGT_PQ });
    expect(
      ml_dsa65.verify(Buffer.from(s, 'base64url'), Buffer.from(`${h}.${p}`), specPqcKey().publicKey),
    ).toBe(true);
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
  it('mints a General JSON token whose every entry verifies', () => {
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
