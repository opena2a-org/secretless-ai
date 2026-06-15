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
 */

import * as crypto from 'crypto';
import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import type { ResourceBinding } from './types';

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
 * agent-supplied input. `nowSeconds` is injectable for deterministic tests.
 */
export function mintBrokerAssertion(
  ctx: ResolutionContext,
  binding: ResourceBinding,
  key: BrokerSigningKey,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): string {
  const header = { alg: 'EdDSA', typ: 'JWT', kid: key.kid };
  const claims = {
    iss: key.issuer,
    sub: ctx.agentDid,
    aud: binding.audience,
    scope: binding.scope,
    // Federation attributes carried for v2 cross-broker verification (AAP §7, §11).
    trust_class: binding.scope,
    issuer_chain: ctx.issuerChain,
    trust_level: ctx.trustLevel,
    iat: nowSeconds,
    exp: nowSeconds + binding.ttlSeconds,
    jti: crypto.randomBytes(16).toString('hex'),
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), key.privateKey);
  return `${signingInput}.${base64url(signature)}`;
}

/** Export the public half as a JWK for the broker's discovery document (operator's domain). */
export function brokerPublicJwk(key: BrokerSigningKey): Record<string, unknown> {
  const pub = crypto.createPublicKey(key.privateKey);
  const jwk = pub.export({ format: 'jwk' }) as Record<string, unknown>;
  return { ...jwk, kid: key.kid, use: 'sig', alg: 'EdDSA' };
}
