/**
 * Broker assertion minting — the broker as its own identity provider (AAP Broker Profile §11).
 *
 * In AAP token-model terms (AAP-SPEC.md), the assertion minted here IS a Capability Grant Token
 * (CGT) / Delegation Assertion (DA): a short-lived, scoped authorization derived from the verified
 * ATX (which the Agent Identity Token references) and used as the RFC 8693 subject token.
 *
 * For Assume and Exchange, the broker mints a short-lived assertion whose claims derive
 * from the *verified* ATX, signed with the broker's own signing key. The downstream
 * (STS for Assume, authorization server for Exchange) is configured once to trust the
 * broker's IdP via its published public key — the broker holds no standing secret to any
 * backend, only this one rotating key.
 *
 * The assertion is a compact EdDSA JWT. The SAME assertion a broker mints for its own
 * agents is what a peer broker will verify for a foreign agent in v2 federation — which
 * is why the claims carry the ATX issuer chain and trust level, not just a subject.
 *
 * Post-quantum profile (AAP-SPEC §8.2/§9.4/§9.5, RFC 9964): the broker can also mint
 * a compact ML-DSA-65 assertion (the PQ-interop lane) and a hybrid Ed25519 + ML-DSA-65
 * assertion as JWS General JSON Serialization — one signature entry per suite over the
 * same payload; a hybrid token verifies only if every declared entry verifies and both
 * suite families are present. Serialization-profile decision:
 * agent-authorization-protocol decisions/2026-07-16-mldsa65-serialization-profile.md.
 */

import * as crypto from 'crypto';
import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import type { ResourceBinding } from './types';

// @noble/post-quantum is ESM-only; this package compiles to CommonJS, so the
// module loads via require(esm) — supported since Node 20.19 (the package
// engines floor). Lazy + memoized: classical EdDSA minting never touches it.
type MlDsaModule = typeof import('@noble/post-quantum/ml-dsa.js', {
  with: { 'resolution-mode': 'import' },
});
let mlDsaModule: MlDsaModule | undefined;
function mlDsa65(): MlDsaModule['ml_dsa65'] {
  if (!mlDsaModule) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      mlDsaModule = require('@noble/post-quantum/ml-dsa.js') as MlDsaModule;
    } catch (err) {
      throw new Error(
        'ML-DSA-65 minting needs Node >= 20.19 (require() of the ESM-only ' +
          `@noble/post-quantum). Underlying error: ${(err as Error).message}`,
      );
    }
  }
  return mlDsaModule.ml_dsa65;
}

/**
 * The broker's IdP signing key. In production this is the existing short-lived delegated
 * signing key (30-day default) and it ROTATES; only the public half is published on the
 * operator's own domain. Here it is an Ed25519 key pair the broker holds in memory.
 */
export interface BrokerSigningKey {
  /** Key id published in the broker's discovery document; lands in the JWT header `kid`. */
  kid: string;
  /** Ed25519 private key (Node KeyObject). */
  privateKey: crypto.KeyObject;
  /** Issuer identifier for the broker IdP (e.g. the operator's broker URL). */
  issuer: string;
}

/** Generate a fresh Ed25519 broker signing key (rotation produces a new one). */
export function generateBrokerSigningKey(issuer: string, kid: string): BrokerSigningKey {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  return { kid, privateKey, issuer };
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

/**
 * Mint a broker assertion (compact EdDSA JWT) from a verified-ATX context and a binding.
 *
 * Claims are derived ONLY from the verified ATX and the local binding — never from
 * agent-supplied input. `nowSeconds` and `jti` are injectable for deterministic tests
 * and fixture generation (AAP-SPEC §9.7); the defaults are the production behavior.
 */
export function mintBrokerAssertion(
  ctx: ResolutionContext,
  binding: ResourceBinding,
  key: BrokerSigningKey,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  jti: string = crypto.randomBytes(16).toString('hex'),
): string {
  const header = { alg: 'EdDSA', typ: 'JWT', kid: key.kid };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(
    JSON.stringify(buildAssertionClaims(ctx, binding, key.issuer, nowSeconds, jti)),
  )}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), key.privateKey);
  return `${signingInput}.${base64url(signature)}`;
}

/**
 * The pinned CGT/DA claim set (AAP-SPEC §4.2) — member order is normative for
 * the signed bytes, so every mint path derives it from this one builder.
 */
function buildAssertionClaims(
  ctx: ResolutionContext,
  binding: ResourceBinding,
  issuer: string,
  nowSeconds: number,
  jti: string,
): Record<string, unknown> {
  // trust_class is the abstract ATX capability from the matched policy clause
  // (AAP-SPEC §4.2), injected by the grant resolver. Refuse to mint without it:
  // a scope-shaped trust_class fails the pinned claim schema, and silently
  // minting a non-conformant token is worse than failing loudly here.
  if (!binding.trustClass) {
    throw new Error(
      'broker assertion minting: binding.trustClass is required (AAP-SPEC §4.2); ' +
        'the grant resolver injects it from the matched policy clause',
    );
  }
  return {
    iss: issuer,
    sub: ctx.agentDid,
    aud: binding.audience,
    scope: binding.scope,
    // Federation attributes carried for v2 cross-broker verification (AAP §7, §11).
    trust_class: binding.trustClass,
    issuer_chain: ctx.issuerChain,
    trust_level: ctx.trustLevel,
    iat: nowSeconds,
    exp: nowSeconds + binding.ttlSeconds,
    jti,
  };
}

/** Export the public half as a JWK for the broker's discovery document (operator's domain). */
export function brokerPublicJwk(key: BrokerSigningKey): Record<string, unknown> {
  const pub = crypto.createPublicKey(key.privateKey);
  const jwk = pub.export({ format: 'jwk' }) as Record<string, unknown>;
  return { ...jwk, kid: key.kid, use: 'sig', alg: 'EdDSA' };
}

// --- post-quantum suite (ML-DSA-65, RFC 9964) -----------------------------------

/**
 * The broker's ML-DSA-65 signing key (FIPS 204). Same lifecycle as the Ed25519
 * key: rotates, only the public half (an RFC 9964 AKP JWK) is published.
 */
export interface BrokerPqcSigningKey {
  /** Key id published in the broker's discovery document; lands in the header `kid`. */
  kid: string;
  /** ML-DSA-65 secret key bytes (FIPS 204 expanded form). */
  secretKey: Uint8Array;
  /** ML-DSA-65 public key bytes (1952 bytes, FIPS 204 §5.3). */
  publicKey: Uint8Array;
  /** Issuer identifier for the broker IdP; MUST match the Ed25519 key's issuer. */
  issuer: string;
}

/**
 * Generate a fresh ML-DSA-65 broker signing key. `seed` (the 32-byte FIPS 204
 * xi input — the same seed form RFC 9964 pins for the AKP `priv` parameter) is
 * injectable for deterministic tests and fixture generation; the default is a
 * fresh random seed.
 */
export function generateBrokerPqcSigningKey(
  issuer: string,
  kid: string,
  seed: Uint8Array = crypto.randomBytes(32),
): BrokerPqcSigningKey {
  const { secretKey, publicKey } = mlDsa65().keygen(seed);
  return { kid, secretKey, publicKey, issuer };
}

/** Signing options shared by the PQ mint paths. */
export interface PqcMintOptions {
  /**
   * Use the FIPS 204 deterministic signing variant. Fixture generation REQUIRES
   * it (AAP-SPEC §9.7: fixed keys + fixed claims = fixed bytes); production
   * minting defaults to hedged signing, which FIPS 204 prefers for side-channel
   * resilience. Verification is identical either way.
   */
  deterministic?: boolean;
}

function signMlDsa65(key: BrokerPqcSigningKey, message: Buffer, opts?: PqcMintOptions): Buffer {
  // Empty context string and pure ML-DSA (no pre-hash), as RFC 9964 requires.
  return Buffer.from(
    mlDsa65().sign(message, key.secretKey, opts?.deterministic ? { extraEntropy: false } : {}),
  );
}

/**
 * Mint a compact ML-DSA-65 assertion — the PQ-interop lane of AAP-SPEC §9.3,
 * for counterparties that advertise RFC 9964 support. Same pinned claim set
 * and JWS Signing Input as the EdDSA form; only the suite differs.
 */
export function mintBrokerAssertionMlDsa65(
  ctx: ResolutionContext,
  binding: ResourceBinding,
  key: BrokerPqcSigningKey,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  jti: string = crypto.randomBytes(16).toString('hex'),
  opts?: PqcMintOptions,
): string {
  const header = { alg: 'ML-DSA-65', typ: 'JWT', kid: key.kid };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(
    JSON.stringify(buildAssertionClaims(ctx, binding, key.issuer, nowSeconds, jti)),
  )}`;
  const signature = signMlDsa65(key, Buffer.from(signingInput), opts);
  return `${signingInput}.${base64url(signature)}`;
}

/** JWS General JSON Serialization (RFC 7515 §7.2.1) — AAP-SPEC §9.4. */
export interface JwsGeneralJson {
  payload: string;
  signatures: { protected: string; signature: string }[];
}

/**
 * Mint a hybrid Ed25519 + ML-DSA-65 assertion (AAP-SPEC §8.2/§9.4): JWS General
 * JSON Serialization with one signature entry per suite over the same payload,
 * each protected header exactly {alg, kid}. This is the RECOMMENDED form
 * wherever both ends implement AAP; a conformant verifier accepts it only if
 * every declared entry verifies and both suite families are present.
 */
export function mintHybridBrokerAssertion(
  ctx: ResolutionContext,
  binding: ResourceBinding,
  edKey: BrokerSigningKey,
  pqcKey: BrokerPqcSigningKey,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  jti: string = crypto.randomBytes(16).toString('hex'),
  opts?: PqcMintOptions,
): JwsGeneralJson {
  if (edKey.issuer !== pqcKey.issuer) {
    throw new Error(
      'mintHybridBrokerAssertion: the Ed25519 and ML-DSA-65 keys must belong to ' +
        `the same issuer (got "${edKey.issuer}" and "${pqcKey.issuer}")`,
    );
  }
  const payload = base64url(
    JSON.stringify(buildAssertionClaims(ctx, binding, edKey.issuer, nowSeconds, jti)),
  );
  const edProtected = base64url(JSON.stringify({ alg: 'EdDSA', kid: edKey.kid }));
  const pqProtected = base64url(JSON.stringify({ alg: 'ML-DSA-65', kid: pqcKey.kid }));
  return {
    payload,
    signatures: [
      {
        protected: edProtected,
        signature: base64url(
          crypto.sign(null, Buffer.from(`${edProtected}.${payload}`), edKey.privateKey),
        ),
      },
      {
        protected: pqProtected,
        signature: base64url(signMlDsa65(pqcKey, Buffer.from(`${pqProtected}.${payload}`), opts)),
      },
    ],
  };
}

/**
 * Export the ML-DSA-65 public half as an RFC 9964 AKP JWK for the broker's
 * discovery document. `alg` is REQUIRED on AKP keys; the private `priv`
 * member (the 32-byte seed) is never exported.
 */
export function brokerPublicAkpJwk(key: BrokerPqcSigningKey): Record<string, unknown> {
  return {
    kty: 'AKP',
    pub: base64url(Buffer.from(key.publicKey)),
    kid: key.kid,
    use: 'sig',
    alg: 'ML-DSA-65',
  };
}
