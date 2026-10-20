/**
 * Grant file — the operator's configuration that turns on `POST /grant`.
 *
 * One JSON file carries the four things the grant flow decides with. None of them travels
 * with the agent:
 *
 *   trust      the ATX issuers this broker accepts, the keys their credentials verify
 *              against, and the agents whose credentials are revoked
 *   assertion  the identity the broker signs its own assertions under
 *   providers  the identity providers a grant can be resolved through
 *   bindings   which grant maps to which resource, and what an agent must present for it
 *
 * WHAT THIS LOADER DECIDES, AND WHAT IT DOES NOT. `bindings` is handed to
 * `new GrantPolicy(...)` exactly as parsed. That constructor is the one place a binding is
 * accepted or refused, and nothing here reads inside a binding: a second accept-set would
 * drift from the first, and a constraint added to one of them later would hold for files and
 * not for callers, or the reverse. What is checked here is what no other code checks: the
 * raw text (a repeated member name), the envelope (a section this build does not read), and
 * the three sections whose consumers take what they are given. `LocalAtxVerifier` validates
 * nothing about its anchors, so a misspelled `crl` would be a revocation list that is never
 * consulted, and a key it cannot use is dropped without a word.
 *
 * Everything is read once, at start. A change to the file (a new binding, a revoked agent, a
 * removed issuer) takes effect when the broker is restarted.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type {
  AtxPublicKey,
  AtxTrustAnchors,
  AtxVerifier,
} from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import { GrantPolicy } from './grant-policy';
import { MapProviderRegistry } from './cpi/registry';
import { ExchangeProvider } from './cpi/exchange';
import { HttpsTokenExchangeTransport } from './cpi/http-transport';
import { brokerPublicJwk, type BrokerSigningKey } from './cpi/assertion';
import type { ProviderRegistry } from './cpi/types';
import { parseJsonRefusingDuplicates } from './strict-json';
import { nearestMatch } from '../near-miss';

/** Where the broker keeps its assertion signing key when the grant file names no `keyFile`. */
export const DEFAULT_ASSERTION_KEY_FILE = path.join(
  os.homedir(),
  '.secretless-ai',
  'broker-assertion.key',
);

/** Everything a grant resolver is built from, loaded from one grant file. */
export interface GrantConfig {
  /** The file this was loaded from. */
  file: string;
  /** Verifies a presented ATX against the file's `trust` section. */
  verifier: AtxVerifier;
  /** The file's `bindings`, as accepted by `GrantPolicy`. */
  policy: GrantPolicy;
  /** The file's `providers`, each signing with the broker's assertion key. */
  providers: ProviderRegistry;
  bindingCount: number;
  providerCount: number;
  /** The private key the broker signs assertions with. Never leaves the broker. */
  assertionKeyFile: string;
  /** The public half as a JWK, for the operator to register with each identity provider. */
  assertionPublicKeyFile: string;
  /** True when this load created the key, so no identity provider can trust it yet. */
  assertionKeyCreated: boolean;
}

const ENVELOPE_KEYS = new Set(['version', 'trust', 'assertion', 'providers', 'bindings']);
const TRUST_KEYS = new Set(['trustedIssuers', 'publicKeys', 'crl']);
const PUBLIC_KEY_KEYS = new Set(['algorithm', 'publicKeyHex', 'keyId']);
const CRL_KEYS = new Set(['entries']);
const CRL_ENTRY_KEYS = new Set(['agentId', 'reason']);
const ASSERTION_KEYS = new Set(['issuer', 'keyId', 'keyFile']);
const PROVIDER_KEYS = new Set(['mode', 'tokenEndpoint']);

/** The CPI modes the protocol names and this build has no provider for. */
const UNIMPLEMENTED_PROVIDER_MODES = new Set(['retrieve', 'assume']);

/** DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows it. */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Load a grant file, or throw naming what in it this build cannot apply.
 *
 * Nothing is written until the whole file has been accepted: the assertion key is created
 * last, so a refused file leaves no key behind.
 */
export async function loadGrantConfig(file: string): Promise<GrantConfig> {
  if (!fs.existsSync(file)) {
    throw new Error(
      `Grant file ${file} does not exist. The broker was not started: a grant file that was ` +
      `named and cannot be read is not the same as none, and starting without it would leave ` +
      `/grant off while the command line says it is on.`,
    );
  }

  // Resolved before the file is read and reported on its own, because a module that will not
  // load is an installation fault and not a fault in the operator's file.
  let LocalAtxVerifier: new (anchors: AtxTrustAnchors) => AtxVerifier;
  try {
    ({ LocalAtxVerifier } = await import('@opena2a/atx-verify'));
  } catch (err) {
    throw installationFault(file, err instanceof Error ? err.message : String(err));
  }

  try {
    const parsed = await parseJsonRefusingDuplicates(fs.readFileSync(file, 'utf-8'));
    if (!parsed.ok) {
      if (parsed.reason === 'scanner-unavailable') throw installationFault(file, parsed.detail);
      if (parsed.reason === 'duplicate-member') {
        throw new Error(
          `it has a duplicate member "${parsed.member}". A member name that collides with ` +
          `another member of the same object is refused rather than resolved: JSON.parse keeps ` +
          `the last one, so one of the two sections or predicates would be dropped while the ` +
          `file still loads. Names are compared after JSON escape decoding and case folding, ` +
          `so a case variant or an escaped spelling collides too. Remove the duplicate and ` +
          `keep the one you meant.`,
        );
      }
      throw new Error(
        `it is not a single well-formed JSON value. Check the file for truncation, a trailing ` +
        `comma, or content after the closing brace.`,
      );
    }

    const root = parsed.value;
    if (!isRecord(root)) {
      throw new Error(
        `it must be a JSON object with the sections ${sectionList()}, not ${describe(root)}.`,
      );
    }
    for (const key of Object.keys(root)) {
      if (ENVELOPE_KEYS.has(key)) continue;
      const near = nearestMatch(key, [...ENVELOPE_KEYS]);
      throw new Error(
        `it has an unknown top-level key "${key}"${near ? ` (did you mean "${near}"?)` : ''}. ` +
        `A grant file may carry: ${[...ENVELOPE_KEYS].join(', ')}. A section under a key this ` +
        `build does not read would never be loaded, and nothing downstream could tell that ` +
        `from a file that never declared it.`,
      );
    }
    if (root.version !== undefined && root.version !== 1) {
      throw new Error(
        `version must be 1 or absent, not ${describe(root.version)}. This build reads version ` +
        `1, and a file written for another version is refused rather than read as this one.`,
      );
    }

    const anchors = readTrust(root.trust);
    const assertion = readAssertion(root.assertion, path.dirname(path.resolve(file)));
    const endpoints = readProviders(root.providers);
    if (!Array.isArray(root.bindings)) {
      throw new Error(
        `bindings must be an array of grant bindings, not ${describe(root.bindings)}. An empty ` +
        `array is accepted and denies every grant.`,
      );
    }
    // The one write path to the bindings. See the file header.
    const policy = new GrantPolicy(root.bindings);

    // Only now, with the whole file accepted, is anything written.
    const key = loadOrCreateAssertionKey(assertion.keyFile);
    const signingKey: BrokerSigningKey = {
      kid: assertion.keyId,
      issuer: assertion.issuer,
      privateKey: key.privateKey,
    };
    const publicKeyFile = `${assertion.keyFile}.pub.json`;
    writePublicJwk(publicKeyFile, signingKey);

    const transport = new HttpsTokenExchangeTransport();
    const providers = new MapProviderRegistry();
    for (const [id, tokenEndpoint] of endpoints) {
      providers.register(id, new ExchangeProvider({ tokenEndpoint }, signingKey, transport));
    }

    return {
      file,
      verifier: new LocalAtxVerifier(anchors),
      policy,
      providers,
      bindingCount: policy.size,
      providerCount: endpoints.size,
      assertionKeyFile: assertion.keyFile,
      assertionPublicKeyFile: publicKeyFile,
      assertionKeyCreated: key.created,
    };
  } catch (err) {
    if (err instanceof InstallationFault) throw err;
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to load grants from ${file}: ${message}`);
  }
}

/** A fault in the installation, kept apart from a fault in the operator's file. */
class InstallationFault extends Error {}

function installationFault(file: string, detail: string): InstallationFault {
  return new InstallationFault(
    `Cannot load grants from ${file}: @opena2a/atx-verify, which verifies agent credentials ` +
    `and scans the file for duplicate members, could not be loaded, so the broker was not ` +
    `started. This is an installation fault, not a fault in your grant file. Do not edit or ` +
    `delete the file to clear it.\n` +
    `  Verify: node -e "import('@opena2a/atx-verify').then(() => console.log('ok'))"\n` +
    `  Fix:    npm install\n` +
    `          and check that node -v prints 20.19.0 or later\n` +
    `  Cause:  ${detail}`,
  );
}

function sectionList(): string {
  return [...ENVELOPE_KEYS].filter((k) => k !== 'version').join(', ');
}

/** The `trust` section, rebuilt as the anchors the ATX verifier checks against. */
function readTrust(raw: unknown): AtxTrustAnchors {
  if (!isRecord(raw)) {
    throw new Error(
      `trust must be an object naming the ATX issuers this broker accepts (trustedIssuers, ` +
      `publicKeys, and optionally crl), not ${describe(raw)}. Without it no credential can ` +
      `be verified.`,
    );
  }
  refuseUnknownKeys('trust', raw, TRUST_KEYS);

  const issuers = raw.trustedIssuers;
  if (!Array.isArray(issuers) || issuers.length === 0 || !issuers.every(isNonEmptyString)) {
    throw new Error(
      `trust.trustedIssuers must be a non-empty array of issuer DIDs, e.g. ` +
      `["did:opena2a:authority:opena2a.org"]. A list that names no issuer trusts none, so ` +
      `every credential would be denied.`,
    );
  }

  const keys = raw.publicKeys;
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error(
      `trust.publicKeys must be a non-empty array of the issuers' public keys. With no key ` +
      `no signature can verify, so every credential would be denied.`,
    );
  }
  const publicKeys = keys.map((k, i) => readPublicKey(`trust.publicKeys[${i}]`, k));

  // A key with no controller verifies a credential from ANY trusted issuer. With one issuer
  // that is the only reading there is. With several, one issuer's key would sign credentials
  // carrying another issuer's DID, and the audit record and the broker assertion would both
  // name an issuer that never signed.
  if (issuers.length > 1) {
    publicKeys.forEach((k, i) => {
      if (k.keyId?.includes('#')) return;
      throw new Error(
        `trust.publicKeys[${i}]: keyId is required when trust.trustedIssuers names more than ` +
        `one issuer. Write it as the issuer's DID, "#", and a key name, e.g. ` +
        `"${issuers[0]}#key-1". A key bound to no issuer verifies a credential issued under ` +
        `any of them, so one trusted issuer could sign as another.`,
      );
    });
  }

  const anchors: AtxTrustAnchors = { trustedIssuers: [...issuers], publicKeys };
  if (raw.crl !== undefined) anchors.crl = readCrl(raw.crl);
  return anchors;
}

function readPublicKey(label: string, raw: unknown): AtxPublicKey {
  if (!isRecord(raw)) {
    throw new Error(`${label} must be an object with algorithm and publicKeyHex, not ${describe(raw)}`);
  }
  refuseUnknownKeys(label, raw, PUBLIC_KEY_KEYS);

  if (raw.algorithm !== 'Ed25519') {
    throw new Error(
      `${label}: algorithm must be "Ed25519", not ${describe(raw.algorithm)}. Ed25519 is the ` +
      `signature this build verifies on an ATX; a key of another algorithm would be listed ` +
      `as trusted and never used.`,
    );
  }
  const hex = raw.publicKeyHex;
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex) || !isEd25519PublicKey(hex)) {
    throw new Error(
      `${label}: publicKeyHex must be the issuer's 32-byte Ed25519 public key written as 64 ` +
      `hexadecimal characters. The verifier drops a key of any other shape without a word, ` +
      `and every credential that key should verify is then denied.`,
    );
  }
  const key: AtxPublicKey = { algorithm: 'Ed25519', publicKeyHex: hex };
  if (raw.keyId !== undefined) {
    if (!isNonEmptyString(raw.keyId)) {
      throw new Error(
        `${label}: keyId must be a non-empty string, not ${describe(raw.keyId)}. Omit it for ` +
        `a key bound to no particular issuer.`,
      );
    }
    key.keyId = raw.keyId;
  }
  return key;
}

/** True when the verifier can build a key from `hex`, checked the way the verifier builds it. */
function isEd25519PublicKey(hex: string): boolean {
  try {
    crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex, 'hex')]),
      format: 'der',
      type: 'spki',
    });
    return true;
  } catch {
    return false;
  }
}

function readCrl(raw: unknown): NonNullable<AtxTrustAnchors['crl']> {
  if (!isRecord(raw)) {
    throw new Error(`trust.crl must be an object with an "entries" array, not ${describe(raw)}`);
  }
  refuseUnknownKeys('trust.crl', raw, CRL_KEYS);
  if (!Array.isArray(raw.entries)) {
    throw new Error(
      `trust.crl.entries must be an array of revoked agents, not ${describe(raw.entries)}. ` +
      `Omit crl to revoke no one.`,
    );
  }
  return {
    entries: raw.entries.map((entry, i) => {
      const label = `trust.crl.entries[${i}]`;
      if (!isRecord(entry)) {
        throw new Error(`${label} must be an object with an agentId, not ${describe(entry)}`);
      }
      refuseUnknownKeys(label, entry, CRL_ENTRY_KEYS);
      if (!isNonEmptyString(entry.agentId)) {
        throw new Error(
          `${label}: agentId must be the revoked agent's id as a non-empty string, not ` +
          `${describe(entry.agentId)}. An entry the verifier cannot match revokes no one.`,
        );
      }
      if (entry.reason !== undefined && typeof entry.reason !== 'string') {
        throw new Error(`${label}: reason must be a string, not ${describe(entry.reason)}`);
      }
      return entry.reason === undefined
        ? { agentId: entry.agentId }
        : { agentId: entry.agentId, reason: entry.reason };
    }),
  };
}

/** The `assertion` section, with `keyFile` resolved against the grant file's directory. */
function readAssertion(
  raw: unknown,
  baseDir: string,
): { issuer: string; keyId: string; keyFile: string } {
  if (!isRecord(raw)) {
    throw new Error(
      `assertion must be an object naming the identity the broker signs under (issuer, ` +
      `keyId, and optionally keyFile), not ${describe(raw)}.`,
    );
  }
  refuseUnknownKeys('assertion', raw, ASSERTION_KEYS);
  if (!isNonEmptyString(raw.issuer)) {
    throw new Error(
      `assertion.issuer must be a non-empty string, e.g. "https://broker.example.com". It is ` +
      `the "iss" claim of every assertion the broker signs, and the name each identity ` +
      `provider knows the broker by.`,
    );
  }
  if (!isNonEmptyString(raw.keyId)) {
    throw new Error(
      `assertion.keyId must be a non-empty string, e.g. "broker-key-1". It is the "kid" of ` +
      `every assertion the broker signs, and of the public key you register with each ` +
      `identity provider.`,
    );
  }
  let keyFile = DEFAULT_ASSERTION_KEY_FILE;
  if (raw.keyFile !== undefined) {
    if (!isNonEmptyString(raw.keyFile)) {
      throw new Error(
        `assertion.keyFile must be a path, not ${describe(raw.keyFile)}. Omit it to keep the ` +
        `key at ${DEFAULT_ASSERTION_KEY_FILE}.`,
      );
    }
    keyFile = path.resolve(baseDir, raw.keyFile);
  }
  return { issuer: raw.issuer, keyId: raw.keyId, keyFile };
}

/** The `providers` section as provider id -> token endpoint. Builds nothing yet. */
function readProviders(raw: unknown): Map<string, string> {
  if (!isRecord(raw)) {
    throw new Error(
      `providers must be an object mapping a provider id to its configuration, e.g. ` +
      `{ "orders-idp": { "mode": "exchange", "tokenEndpoint": "https://idp.example.com/token" } }, ` +
      `not ${describe(raw)}. An empty object is accepted when there are no bindings.`,
    );
  }
  const endpoints = new Map<string, string>();
  for (const [id, value] of Object.entries(raw)) {
    const label = `providers[${JSON.stringify(id)}]`;
    if (id === '') {
      throw new Error(`providers has an empty provider id. A binding names its provider by this id.`);
    }
    if (!isRecord(value)) {
      throw new Error(`${label} must be an object with mode and tokenEndpoint, not ${describe(value)}`);
    }
    refuseUnknownKeys(label, value, PROVIDER_KEYS);

    if (typeof value.mode === 'string' && UNIMPLEMENTED_PROVIDER_MODES.has(value.mode)) {
      throw new Error(
        `${label}: mode "${value.mode}" has no provider in this build. Only "exchange" does. A ` +
        `grant bound to this provider would be denied on every request, so it is refused here.`,
      );
    }
    if (value.mode !== 'exchange') {
      throw new Error(`${label}: mode must be "exchange", not ${describe(value.mode)}.`);
    }
    endpoints.set(id, readTokenEndpoint(label, value.tokenEndpoint));
  }
  return endpoints;
}

function readTokenEndpoint(label: string, raw: unknown): string {
  if (!isNonEmptyString(raw)) {
    throw new Error(
      `${label}: tokenEndpoint must be the URL of the provider's OAuth token endpoint, not ` +
      `${describe(raw)}.`,
    );
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${label}: tokenEndpoint is not a URL.`);
  }
  if (url.username !== '' || url.password !== '') {
    throw new Error(
      `${label}: tokenEndpoint must not carry a user name or password. The broker would not ` +
      `send them, and a grant file is not a place to keep one.`,
    );
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error(
      `${label}: tokenEndpoint must be an https URL. The broker sends its signed assertion ` +
      `there and receives the scoped token back, and over plain http both cross the network ` +
      `readable. http is accepted for a loopback address only (localhost, 127.0.0.1, [::1]).`,
    );
  }
  return raw;
}

/**
 * Read the assertion signing key, creating it on first use.
 *
 * The key is created with an exclusive open, so a key that already exists is never
 * overwritten. It is always read back from disk, so a key this function created and a key
 * the operator supplied take the same checks.
 */
function loadOrCreateAssertionKey(keyFile: string): { privateKey: crypto.KeyObject; created: boolean } {
  let created = false;
  if (!fs.existsSync(keyFile)) {
    fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    try {
      fs.writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
        mode: 0o600,
        flag: 'wx',
      });
      created = true;
    } catch (err) {
      // It appeared between the check and the open: sign with the key that is there.
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    }
  }

  // Permission bits mean something else on Windows, where the file inherits its directory's
  // access list.
  if (process.platform !== 'win32') {
    const mode = fs.statSync(keyFile).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(
        `assertion key ${keyFile} can be read or written by other users (mode ` +
        `${mode.toString(8)}). Whoever reads it can sign assertions as this broker, and each ` +
        `identity provider that trusts the broker would exchange them for tokens.\n` +
        `  Verify: ls -l ${keyFile}\n` +
        `  Fix:    chmod 600 ${keyFile}`,
      );
    }
  }

  let privateKey: crypto.KeyObject;
  try {
    privateKey = crypto.createPrivateKey(fs.readFileSync(keyFile, 'utf-8'));
  } catch (err) {
    throw new Error(
      `assertion key ${keyFile} cannot be read as a private key: ${(err as Error).message}. ` +
      `It must be an Ed25519 private key in PEM (PKCS #8). Remove the file to have the broker ` +
      `create a new key, then register the new public key with each identity provider.`,
    );
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error(
      `assertion key ${keyFile} holds a key of type "${privateKey.asymmetricKeyType}". The ` +
      `broker signs its assertions with Ed25519 (EdDSA), so the key must be an Ed25519 ` +
      `private key in PEM (PKCS #8).`,
    );
  }
  return { privateKey, created };
}

/**
 * Write the assertion key's public half as a JWK, for the operator to register.
 *
 * Derived from the private key on every load and rewritten when it differs, so the file
 * cannot fall behind a rotated key or a changed `keyId`.
 */
function writePublicJwk(file: string, key: BrokerSigningKey): void {
  const content = `${JSON.stringify(brokerPublicJwk(key), null, 2)}\n`;
  try {
    if (fs.readFileSync(file, 'utf-8') === content) return;
  } catch {
    // Absent or unreadable: write it.
  }
  fs.writeFileSync(file, content, { mode: 0o644 });
}

/** Refuse an object carrying a key this build does not read. */
function refuseUnknownKeys(what: string, value: Record<string, unknown>, known: Set<string>): void {
  for (const key of Object.keys(value)) {
    if (known.has(key)) continue;
    const near = nearestMatch(key, [...known]);
    throw new Error(
      `${what}: unknown field "${key}"${near ? ` (did you mean "${near}"?)` : ''}. It may ` +
      `carry: ${[...known].join(', ')}. A field this build does not read is refused rather ` +
      `than ignored, because ignoring "${key}" would drop whatever it was meant to configure ` +
      `and load the file as though it had never been written.`,
    );
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v !== '';
}

/** Describe a rejected value in an error without printing an object's contents. */
function describe(v: unknown): string {
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  if (typeof v === 'string') return `"${v}"`;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return Array.isArray(v) ? 'an array' : 'an object';
}
