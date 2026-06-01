/**
 * ATX (Agent Trust eXtension) verification — the subject-claim check the broker
 * runs before resolving any grant. AAP §6 step 2.
 *
 * The ATX is the signed, portable credential defined by ATP/ATX that states what an
 * agent *is*. AAP does not redefine it; this verifier mirrors the OpenA2A reference
 * verifier (`atx-conformance/verifiers/python/verify.py`, itself a port of
 * `opena2a-registry/pkg/atcverify/verify.go canonicalPayload()`) VERBATIM so a broker
 * accepts exactly the credentials the conformance suite accepts.
 *
 * (ATX is the current name for the credential formerly called ATC; fixtures still use
 * the `atcVersion` field and the canonical form hardcodes "1.0" — both replicated here.)
 *
 * Scope: Ed25519 is verified fully. ML-DSA-65 presence is recorded but verification is
 * delegated — Node's stdlib has no ML-DSA, exactly as the Python reference verifier
 * skips it. Production wires the post-quantum half + the live trusted-issuer/CRL anchors
 * to AIM's verification path (see AtxVerifier / RegistryAtxVerifier seam below).
 *
 * SECURITY — signature coverage (matches the upstream canonical form, see canonicalPayload):
 * The ATX/ATC canonical signing string covers identity, issuer, trustLevel, trustScore,
 * contentHash, buildAttestation, and the validity window. It does NOT cover `capabilities`,
 * `scanSummary.oasbLevel`, `issuerChain`, or `jurisdiction`. A holder of ANY validly-signed
 * ATX can therefore edit those fields without invalidating the Ed25519 signature. Because
 * the broker authorizes on `capabilities` (the trust-class gate) and `oasbLevel`, a
 * production verifier MUST source those authorization attributes from the issuing
 * Registry/AIM for the verified `agentId` — NOT trust them from the presented credential
 * blob. The LocalAtxVerifier is faithful to the wire format for conformance; it is not a
 * sufficient authorization oracle on its own. Tracked as an ATX-spec hardening item
 * (bind the trust-class set into the canonical payload or a signed content hash).
 */

import * as crypto from 'crypto';

/** The hardcoded schema version in the canonical signing string (Go quirk, replicated). */
export const SUPPORTED_ATX_VERSION = '1.0';

/** A signature reference on an ATX. */
export interface AtxSignature {
  keyId?: string;
  algorithm: 'Ed25519' | 'ML-DSA-65' | string;
  /** base64-encoded signature value. */
  value: string;
}

/** The ATX credential (subset used for verification + context derivation). */
export interface Atx {
  atcVersion?: string;
  agentId: string;
  agentDid: string;
  version: string;
  contentHash: string;
  buildAttestation?: string;
  issuerDid: string;
  issuerChain?: string[];
  trustLevel: number;
  trustScore: number;
  issuedAt: string;
  expiresAt: string;
  capabilities?: string[];
  scanSummary?: { oasbLevel?: string; [k: string]: unknown };
  /** Optional, optional-to-ignore jurisdiction claim (AAP §9). */
  jurisdiction?: string[];
  revoked?: boolean;
  signatures: AtxSignature[];
}

/** A public key the verifier trusts, keyed by algorithm. */
export interface AtxPublicKey {
  algorithm: 'Ed25519' | 'ML-DSA-65' | string;
  /** hex-encoded raw public key (32 bytes for Ed25519). */
  publicKeyHex: string;
}

/** Trust anchors the verifier evaluates against (in production: fetched from AIM/Registry). */
export interface AtxTrustAnchors {
  trustedIssuers: string[];
  publicKeys: AtxPublicKey[];
  /** Cached, federated CRL. Revocation rides entirely on the ATX + CRL (AAP §6). */
  crl?: { entries: Array<{ agentId: string; reason?: string }> };
  /** Clock source (injectable for tests). Defaults to wall clock. */
  now?: () => Date;
}

export type RejectCategory =
  | 'UNSUPPORTED_VERSION'
  | 'EXPIRED'
  | 'REVOKED'
  | 'UNTRUSTED_ISSUER'
  | 'SIGNATURE_INVALID'
  | 'MALFORMED';

/** Context the broker derives from a *verified* ATX. Contains no backend information. */
export interface ResolutionContext {
  agentId: string;
  agentDid: string;
  issuerDid: string;
  issuerChain: string[];
  trustLevel: number;
  trustScore: number;
  capabilities: string[];
  oasbLevel?: string;
  jurisdiction?: string[];
}

export interface AtxVerificationResult {
  valid: boolean;
  /** Present when valid: the context the broker resolves against. */
  context?: ResolutionContext;
  /** Present when invalid. */
  rejectCategory?: RejectCategory;
  reason?: string;
  /** Whether an ML-DSA-65 signature was present (and therefore delegated, not skipped silently). */
  mldsaPresent?: boolean;
}

/** The verification interface. Lets the broker swap a local verifier for an AIM-backed one. */
export interface AtxVerifier {
  verify(atx: Atx): AtxVerificationResult;
}

/**
 * Local ATX verifier. Cryptographically real (Ed25519) and interoperable with the
 * conformance fixtures; trust anchors are injected. The production counterpart
 * (`RegistryAtxVerifier`, a seam for a later pass) fetches `trustedIssuers`,
 * `publicKeys`, and the `crl` from AIM's verification endpoint and adds ML-DSA-65.
 */
export class LocalAtxVerifier implements AtxVerifier {
  constructor(private readonly anchors: AtxTrustAnchors) {}

  verify(atx: Atx): AtxVerificationResult {
    const now = (this.anchors.now ?? (() => new Date()))();

    // Step 1: schema version.
    if (atx.atcVersion !== SUPPORTED_ATX_VERSION) {
      return reject('UNSUPPORTED_VERSION', `unsupported atxVersion ${String(atx.atcVersion)}`);
    }

    // Step 2: expiry.
    const expires = new Date(atx.expiresAt);
    if (Number.isNaN(expires.getTime())) {
      return reject('MALFORMED', 'expiresAt is not a valid timestamp');
    }
    if (now.getTime() > expires.getTime()) {
      return reject('EXPIRED', `expired at ${normalizeRfc3339(atx.expiresAt)}`);
    }

    // Step 3: revocation (ATX field + federated CRL).
    if (atx.revoked) {
      return reject('REVOKED', 'credential revoked field is true');
    }
    for (const entry of this.anchors.crl?.entries ?? []) {
      if (entry.agentId === atx.agentId) {
        return reject('REVOKED', `agent appears on CRL: ${entry.reason ?? ''}`);
      }
    }

    // Step 4: issuer trust.
    if (!this.anchors.trustedIssuers.includes(atx.issuerDid)) {
      return reject('UNTRUSTED_ISSUER', `issuer DID ${atx.issuerDid} is not trusted`);
    }

    // Step 5: signature verification (Ed25519 fully; ML-DSA-65 presence recorded).
    const payload = canonicalPayload(atx);
    const edKeys = this.anchors.publicKeys
      .filter((k) => k.algorithm === 'Ed25519')
      .map((k) => ed25519FromRawHex(k.publicKeyHex))
      .filter((k): k is crypto.KeyObject => k !== null);

    let edVerified = false;
    let mldsaPresent = false;

    for (const sig of atx.signatures ?? []) {
      if (sig.algorithm === 'Ed25519') {
        let sigBytes: Buffer;
        try {
          sigBytes = Buffer.from(sig.value, 'base64');
        } catch {
          return reject('SIGNATURE_INVALID', `signature ${sig.keyId ?? ''} has invalid base64`);
        }
        const ok = edKeys.some((key) => {
          try {
            return crypto.verify(null, payload, key, sigBytes);
          } catch {
            return false;
          }
        });
        if (!ok) {
          return reject('SIGNATURE_INVALID', `Ed25519 signature ${sig.keyId ?? ''} did not verify`);
        }
        edVerified = true;
      } else if (sig.algorithm === 'ML-DSA-65') {
        // Presence recorded; PQC verification delegated (see module docstring). Not silently skipped.
        mldsaPresent = true;
      }
    }

    if (!edVerified) {
      return reject('SIGNATURE_INVALID', 'no Ed25519 signature verified');
    }

    return {
      valid: true,
      mldsaPresent,
      context: {
        agentId: atx.agentId,
        agentDid: atx.agentDid,
        issuerDid: atx.issuerDid,
        issuerChain: atx.issuerChain ?? [atx.issuerDid],
        trustLevel: atx.trustLevel,
        trustScore: atx.trustScore,
        capabilities: atx.capabilities ?? [],
        oasbLevel: atx.scanSummary?.oasbLevel,
        jurisdiction: atx.jurisdiction,
      },
    };
  }
}

function reject(rejectCategory: RejectCategory, reason: string): AtxVerificationResult {
  return { valid: false, rejectCategory, reason };
}

/**
 * Mirror of `opena2a-registry/pkg/atcverify/verify.go canonicalPayload()`:
 *   fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%.6f|%s|%s|%s", ...)
 * with atxVersion hardcoded to "1.0".
 */
export function canonicalPayload(atx: Atx): Buffer {
  const fields = [
    atx.agentId,
    atx.agentDid,
    atx.version,
    atx.contentHash,
    atx.buildAttestation ?? '',
    atx.issuerDid,
    String(Math.trunc(atx.trustLevel)),
    Number(atx.trustScore).toFixed(6),
    normalizeRfc3339(atx.issuedAt),
    normalizeRfc3339(atx.expiresAt),
    SUPPORTED_ATX_VERSION,
  ];
  return Buffer.from(fields.join('|'), 'utf-8');
}

/** Normalize an RFC 3339 timestamp to UTC "YYYY-MM-DDTHH:MM:SSZ" (Go time.RFC3339 for UTC). */
export function normalizeRfc3339(s: string): string {
  const dt = new Date(s);
  if (Number.isNaN(dt.getTime())) {
    throw new Error(`invalid RFC 3339 timestamp: ${s}`);
  }
  return dt.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Build a Node KeyObject from a raw 32-byte Ed25519 public key (hex). */
function ed25519FromRawHex(hex: string): crypto.KeyObject | null {
  const raw = Buffer.from(hex, 'hex');
  if (raw.length !== 32) return null;
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return null;
  }
}
