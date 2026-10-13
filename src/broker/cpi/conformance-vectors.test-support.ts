import { createHash, createPrivateKey } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import {
  type BrokerPqcSigningKey,
  type BrokerSigningKey,
  generateBrokerPqcSigningKey,
} from './assertion';
import type { ResourceBinding } from './types';

/**
 * The AAP conformance suite's vectors as vendored under ./vendor/aap-conformance
 * at the commit PIN.json names, the suite's published test keys, and the inputs
 * its CGT fixtures were generated from. Shared by the broker assertion tests.
 *
 * Excluded from the build (tsconfig: `*.test-support.ts`) and from the test
 * glob (`*.test.ts`), so it ships in neither.
 */

export const VENDOR_DIR = path.join(__dirname, 'vendor', 'aap-conformance');

/** How a vendored file is stored: the upstream bytes, or those bytes with each token member replaced by a placeholder. */
export type StoredForm = 'verbatim' | 'token-withheld';

export interface PinnedFile {
  /** Path in the suite repository, and under VENDOR_DIR. */
  path: string;
  /** sha256 of the suite's file at the pinned commit. */
  sha256: string;
  stored: StoredForm;
}

export interface ConformancePin {
  source: string;
  commit: string;
  license: string;
  files: PinnedFile[];
}

export function readPin(): ConformancePin {
  return JSON.parse(fs.readFileSync(path.join(VENDOR_DIR, 'PIN.json'), 'utf8')) as ConformancePin;
}

export function pinnedFile(file: string): PinnedFile {
  const entry = readPin().files.find((f) => f.path === file);
  if (!entry) throw new Error(`PIN.json does not list ${file}`);
  return entry;
}

export function readVendored(file: string): Buffer {
  return fs.readFileSync(path.join(VENDOR_DIR, file));
}

export const sha256Hex = (bytes: Buffer | string): string =>
  createHash('sha256').update(bytes).digest('hex');

const PLACEHOLDER_OPEN = '{{minted:';
export const placeholder = (member: string): string => `${PLACEHOLDER_OPEN}${member}}}`;

/**
 * The suite's file as it would read with `minted` in place of the withheld
 * token members: the stored copy with each `{{minted:<member>}}` placeholder
 * replaced by the value given for that member. Every placeholder in the file
 * has to be supplied, and each supplied member has to occur exactly once, so a
 * copy that was vendored with its token still in it fails here by name.
 */
export function rebuildUpstream(file: string, minted: Record<string, string>): string {
  let text = readVendored(file).toString('utf8');
  for (const [member, value] of Object.entries(minted)) {
    const parts = text.split(placeholder(member));
    if (parts.length !== 2) {
      throw new Error(
        `${file}: expected the placeholder ${placeholder(member)} once, found it ${parts.length - 1} times`,
      );
    }
    text = parts.join(value);
  }
  if (text.includes(PLACEHOLDER_OPEN)) {
    throw new Error(`${file}: a ${PLACEHOLDER_OPEN}...}} placeholder was left without a minted value`);
  }
  return text;
}

// --- the suite's published test keys (TEST values, never production) -------------

interface PublishedKey {
  kid: string;
  ed25519SeedHex?: string;
  mlDsa65SeedHex?: string;
  publicJwk: Record<string, unknown>;
}

function publishedKey(kid: string): PublishedKey {
  const doc = JSON.parse(readVendored('vectors/test-keys.json').toString('utf8')) as {
    keys: PublishedKey[];
  };
  const key = doc.keys.find((k) => k.kid === kid);
  if (!key) throw new Error(`vectors/test-keys.json has no key ${kid}`);
  return key;
}

function publishedSeed(kid: string, field: 'ed25519SeedHex' | 'mlDsa65SeedHex'): Buffer {
  const hex = publishedKey(kid)[field];
  if (!hex) throw new Error(`vectors/test-keys.json: ${kid} has no ${field}`);
  return Buffer.from(hex, 'hex');
}

export const publishedPublicJwk = (kid: string): Record<string, unknown> => publishedKey(kid).publicJwk;

export const BROKER_ISSUER = 'https://broker.acme.example';
export const ED_KID = 'broker-key-1';
export const PQC_KID = 'broker-pqc-1';

// The PKCS #8 wrapper of a raw 32-byte Ed25519 seed (RFC 8410).
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** broker-key-1, the suite's Ed25519 broker test key. */
export function publishedEdKey(): BrokerSigningKey {
  return {
    kid: ED_KID,
    issuer: BROKER_ISSUER,
    privateKey: createPrivateKey({
      key: Buffer.concat([PKCS8_ED25519_PREFIX, publishedSeed(ED_KID, 'ed25519SeedHex')]),
      format: 'der',
      type: 'pkcs8',
    }),
  };
}

/** broker-pqc-1, the suite's ML-DSA-65 broker test key (the seed is the FIPS 204 xi input). */
export function publishedPqcKey(): BrokerPqcSigningKey {
  return generateBrokerPqcSigningKey(BROKER_ISSUER, PQC_KID, publishedSeed(PQC_KID, 'mlDsa65SeedHex'));
}

// --- the inputs the suite's CGT fixtures were generated from ----------------------

export const CGT_CONTEXT: ResolutionContext = {
  agentId: 'aim_orders_reader',
  agentDid: 'did:opena2a:agent:acme/orders-reader',
  issuerDid: 'did:opena2a:authority:opena2a.org',
  issuerChain: ['did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
  trustScore: 0.95,
  capabilities: ['orders:read'],
  oasbLevel: 'L2',
  signedCapabilities: true,
};

export const CGT_BINDING: ResourceBinding = {
  mode: 'exchange',
  providerId: 'orders-idp',
  scope: 'orders.read',
  audience: 'https://api.orders.internal',
  ttlSeconds: 300,
  trustClass: 'orders:read',
};

// 2026-06-01T12:00:00Z, the fixed clock of the suite's generator.
export const CGT_IAT = 1780315200;
/** jti of the compact EdDSA and the hybrid CGT, which share one claim set. */
export const CGT_JTI = '9f8e7d6c5b4a39281706f5e4d3c2b1a0';
/** jti of the compact ML-DSA-65 CGT. */
export const CGT_PQ_JTI = 'b1c2d3e4f5a60718293a4b5c6d7e8f90';
