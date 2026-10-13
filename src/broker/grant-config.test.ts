/**
 * The grant file loader: what it accepts, what it refuses, and what it writes.
 *
 * `daemon-grant.test.ts` covers a loaded file serving a grant through a started broker. This
 * file covers the loader on its own, one refusal per shape that would otherwise load as
 * something the operator did not write.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { loadGrantConfig } from './grant-config';
import type { Atx, ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };

// @opena2a/atx-verify is ESM-only and this file compiles as CommonJS, so its values load
// through require(esm), as in aap-conformance.test.ts.
const { canonicalPayloadV11 } = require('@opena2a/atx-verify') as typeof import(
  '@opena2a/atx-verify',
  { with: { 'resolution-mode': 'import' } }
);

const ISSUER = 'did:opena2a:authority:issuer.test';
const OTHER_ISSUER = 'did:opena2a:authority:other.test';

interface IssuerKey {
  privateKey: crypto.KeyObject;
  pubHex: string;
}

function makeIssuerKey(): IssuerKey {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  return { privateKey, pubHex: Buffer.from(jwk.x, 'base64url').toString('hex') };
}

function signedAtx(key: IssuerKey, overrides: Partial<Atx> = {}): Atx {
  const atx: Atx = {
    atcVersion: '1.1',
    agentId: 'aim_orders_reader',
    agentDid: 'did:opena2a:agent:acme/orders-reader',
    version: '1.0.0',
    contentHash: 'sha256:abc123',
    buildAttestation: 'sha256:def456',
    issuerDid: ISSUER,
    issuerChain: [ISSUER],
    trustLevel: 4,
    trustScore: 0.95,
    issuedAt: new Date(Date.now() - 3_600_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    capabilities: ['orders:read'],
    scanSummary: { oasbLevel: 'L2' },
    signatures: [],
    ...overrides,
  };
  const sig = crypto.sign(null, canonicalPayloadV11(atx), key.privateKey);
  atx.signatures = [{ keyId: 'test#ed25519', algorithm: 'Ed25519', value: sig.toString('base64') }];
  return atx;
}

describe('loadGrantConfig', () => {
  let dir: string;
  let issuerKey: IssuerKey;

  /** A grant file this build accepts. Each test changes the one thing it is about. */
  function validContent(): Record<string, any> {
    return {
      version: 1,
      trust: {
        trustedIssuers: [ISSUER],
        publicKeys: [{ algorithm: 'Ed25519', publicKeyHex: issuerKey.pubHex }],
      },
      assertion: { issuer: 'https://broker.example.test', keyId: 'broker-key-1', keyFile: 'assertion.key' },
      providers: {
        'orders-idp': { mode: 'exchange', tokenEndpoint: 'https://idp.example.test/oauth2/v1/token' },
      },
      bindings: [
        {
          grant: 'grant://orders-db',
          match: { trustClass: 'orders:read', minTrustLevel: 3, oasbLevel: '>=L2' },
          resolve: {
            mode: 'exchange',
            providerId: 'orders-idp',
            scope: 'orders.read',
            audience: 'https://api.orders.example.test',
            ttlSeconds: 300,
          },
        },
      ],
    };
  }

  function write(content: unknown): string {
    const file = path.join(dir, 'grants.json');
    fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    return file;
  }

  /** Load `content` changed by `edit`, expecting a refusal; returns its message. */
  async function refusal(edit: (content: Record<string, any>) => void): Promise<string> {
    const content = validContent();
    edit(content);
    try {
      await loadGrantConfig(write(content));
    } catch (err) {
      return (err as Error).message;
    }
    throw new Error('the grant file was loaded');
  }

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grant-config-'));
    issuerKey = makeIssuerKey();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  describe('a file it accepts', () => {
    it('builds a verifier, a policy and a provider registry from the file', async () => {
      const file = write(validContent());

      const config = await loadGrantConfig(file);

      expect(config.file).toBe(file);
      expect(config.bindingCount).toBe(1);
      expect(config.providerCount).toBe(1);

      const verified = config.verifier.verify(signedAtx(issuerKey));
      expect(verified.valid).toBe(true);
      expect(config.verifier.verify(signedAtx(makeIssuerKey())).valid).toBe(false);

      const evaluation = config.policy.evaluate('orders-db', verified.context as ResolutionContext);
      expect(evaluation.allowed).toBe(true);
      expect(config.policy.evaluate('payments-db', verified.context as ResolutionContext).allowed).toBe(false);

      expect(config.providers.get('orders-idp')?.modes).toEqual(['exchange']);
      expect(config.providers.get('payments-idp')).toBeUndefined();
    });

    it('loads the grant file the broker guide tells an operator to write', async () => {
      const guide = fs.readFileSync(
        path.resolve(__dirname, '..', '..', 'docs', 'use-cases', 'run-broker.md'),
        'utf-8',
      );
      const section = guide.slice(guide.indexOf('## Grants: run an operation'));
      const example = /```json\n([\s\S]*?)\n```/.exec(section);
      if (!example) throw new Error('the Grants section of the broker guide has no JSON example');
      const content = JSON.parse(example[1]);
      // The guide prints a placeholder where the issuer's key goes, and keeps the signing key
      // at its default path under the home directory.
      expect(content.trust.publicKeys[0].publicKeyHex).toMatch(/^<.*>$/);
      content.trust.publicKeys[0].publicKeyHex = issuerKey.pubHex;
      content.assertion.keyFile = 'assertion.key';

      const config = await loadGrantConfig(write(content));

      expect(config.bindingCount).toBe(1);
      expect(config.providerCount).toBe(1);
      expect(config.providers.get(content.bindings[0].resolve.providerId)).toBeDefined();
    });

    it('accepts a file with no version, no bindings and no providers', async () => {
      const content = validContent();
      delete content.version;
      content.bindings = [];
      content.providers = {};

      const config = await loadGrantConfig(write(content));

      expect(config.bindingCount).toBe(0);
      expect(config.providerCount).toBe(0);
    });

    it('gives the verifier the revocation list, so a listed agent no longer verifies', async () => {
      const content = validContent();
      content.trust.crl = { entries: [{ agentId: 'aim_orders_reader', reason: 'key compromise' }] };

      const config = await loadGrantConfig(write(content));

      const result = config.verifier.verify(signedAtx(issuerKey));
      expect(result.valid).toBe(false);
      expect(result.rejectCategory).toBe('REVOKED');
      expect(config.verifier.verify(signedAtx(issuerKey, { agentId: 'aim_other' })).valid).toBe(true);
    });

    it('accepts an http token endpoint on a loopback address', async () => {
      for (const endpoint of ['http://127.0.0.1:8080/token', 'http://localhost:8080/token', 'http://[::1]:8080/token']) {
        const content = validContent();
        content.providers['orders-idp'].tokenEndpoint = endpoint;
        expect((await loadGrantConfig(write(content))).providerCount).toBe(1);
      }
    });

    it('accepts several issuers when every key is bound to one of them', async () => {
      const other = makeIssuerKey();
      const content = validContent();
      content.trust.trustedIssuers = [ISSUER, OTHER_ISSUER];
      content.trust.publicKeys = [
        { algorithm: 'Ed25519', publicKeyHex: issuerKey.pubHex, keyId: `${ISSUER}#key-1` },
        { algorithm: 'Ed25519', publicKeyHex: other.pubHex, keyId: `${OTHER_ISSUER}#key-1` },
      ];

      const config = await loadGrantConfig(write(content));

      expect(config.verifier.verify(signedAtx(issuerKey)).valid).toBe(true);
      // The other issuer's key does not verify a credential issued under this issuer's DID.
      expect(config.verifier.verify(signedAtx(other)).valid).toBe(false);
      expect(
        config.verifier.verify(signedAtx(other, { issuerDid: OTHER_ISSUER, issuerChain: [OTHER_ISSUER] })).valid,
      ).toBe(true);
    });
  });

  describe('the file itself', () => {
    it('refuses a file that does not exist, naming it', async () => {
      const missing = path.join(dir, 'absent.json');
      await expect(loadGrantConfig(missing)).rejects.toThrow(`Grant file ${missing} does not exist`);
    });

    it('refuses text that is not JSON', async () => {
      const file = write('{ "trust": ');
      await expect(loadGrantConfig(file)).rejects.toThrow(
        `Failed to load grants from ${file}: it is not a single well-formed JSON value`,
      );
    });

    it('refuses a repeated section rather than keeping the last one', async () => {
      // JSON.stringify cannot write this: the second "bindings" is the one JSON.parse keeps.
      const text = JSON.stringify(validContent()).replace(/\}$/, ',"bindings":[]}');
      expect(JSON.parse(text).bindings).toEqual([]);

      await expect(loadGrantConfig(write(text))).rejects.toThrow('duplicate member "bindings"');
    });

    it('refuses a repeated predicate inside a binding, at any depth', async () => {
      const text = JSON.stringify(validContent()).replace(
        '"minTrustLevel":3',
        '"minTrustLevel":3,"minTrustLevel":0',
      );
      expect(text).toContain('"minTrustLevel":3,"minTrustLevel":0');

      await expect(loadGrantConfig(write(text))).rejects.toThrow(/duplicate member "mintrustlevel"/i);
    });

    it('refuses a top-level array', async () => {
      await expect(loadGrantConfig(write([validContent()]))).rejects.toThrow(
        'it must be a JSON object with the sections trust, assertion, providers, bindings, not an array',
      );
    });

    it('refuses a section under a key it does not read, suggesting the one meant', async () => {
      const message = await refusal((c) => {
        c.provider = c.providers;
        delete c.providers;
      });
      expect(message).toContain('unknown top-level key "provider" (did you mean "providers"?)');
    });

    it('refuses a version it does not read', async () => {
      expect(await refusal((c) => { c.version = 2; })).toContain('version must be 1 or absent, not 2');
    });

    it.each(['trust', 'assertion', 'providers', 'bindings'])('refuses a file with no %s section', async (section) => {
      const message = await refusal((c) => { delete c[section]; });
      expect(message).toContain(`${section} must be`);
      expect(message).toContain('not undefined');
    });
  });

  describe('bindings', () => {
    it('are accepted or refused by GrantPolicy: a misspelled predicate is refused', async () => {
      const message = await refusal((c) => {
        c.bindings[0].match = { trustClass: 'orders:read', oasbLevl: '>=L2' };
      });
      expect(message).toContain('Grant binding "grant://orders-db": match: unknown field "oasbLevl" (did you mean "oasbLevel"?)');
    });

    it('are accepted or refused by GrantPolicy: a floor it cannot rank is refused', async () => {
      const message = await refusal((c) => { c.bindings[0].match.oasbLevel = '>=L4'; });
      expect(message).toContain('names a level this build cannot rank');
    });

    it('are accepted or refused by GrantPolicy: two bindings for one grant are refused', async () => {
      const message = await refusal((c) => { c.bindings.push(c.bindings[0]); });
      expect(message).toContain('duplicate binding');
    });

    it('must be an array', async () => {
      const message = await refusal((c) => { c.bindings = { 'grant://orders-db': c.bindings[0] }; });
      expect(message).toContain('bindings must be an array of grant bindings, not an object');
    });
  });

  describe('trust', () => {
    it('refuses an empty issuer list', async () => {
      expect(await refusal((c) => { c.trust.trustedIssuers = []; })).toContain(
        'trust.trustedIssuers must be a non-empty array of issuer DIDs',
      );
    });

    it('refuses an empty key list', async () => {
      expect(await refusal((c) => { c.trust.publicKeys = []; })).toContain(
        'trust.publicKeys must be a non-empty array',
      );
    });

    it('refuses a misspelled revocation list rather than revoking no one', async () => {
      const message = await refusal((c) => {
        c.trust.clr = { entries: [{ agentId: 'aim_orders_reader' }] };
      });
      expect(message).toContain('trust: unknown field "clr" (did you mean "crl"?)');
    });

    it('refuses a revocation entry whose agent id is under a misspelled key', async () => {
      const message = await refusal((c) => {
        c.trust.crl = { entries: [{ agentID: 'aim_orders_reader' }] };
      });
      expect(message).toContain('trust.crl.entries[0]: unknown field "agentID" (did you mean "agentId"?)');
    });

    it('refuses a revocation entry with no agent id', async () => {
      const message = await refusal((c) => { c.trust.crl = { entries: [{ reason: 'left' }] }; });
      expect(message).toContain('trust.crl.entries[0]: agentId must be the revoked agent\'s id');
    });

    it('refuses a revocation list that is not under "entries"', async () => {
      const message = await refusal((c) => { c.trust.crl = [{ agentId: 'aim_orders_reader' }]; });
      expect(message).toContain('trust.crl must be an object with an "entries" array, not an array');
    });

    it('refuses a public key the verifier would drop', async () => {
      const message = await refusal((c) => {
        c.trust.publicKeys[0].publicKeyHex = issuerKey.pubHex.slice(0, 62);
      });
      expect(message).toContain('trust.publicKeys[0]: publicKeyHex must be the issuer\'s 32-byte Ed25519 public key');
      // The value is not echoed.
      expect(message).not.toContain(issuerKey.pubHex.slice(0, 62));
    });

    it('refuses a key of an algorithm it does not verify', async () => {
      const message = await refusal((c) => { c.trust.publicKeys[0].algorithm = 'ML-DSA-65'; });
      expect(message).toContain('trust.publicKeys[0]: algorithm must be "Ed25519", not "ML-DSA-65"');
    });

    it('refuses a key bound to no issuer when more than one issuer is trusted', async () => {
      const message = await refusal((c) => { c.trust.trustedIssuers = [ISSUER, OTHER_ISSUER]; });
      expect(message).toContain(
        'trust.publicKeys[0]: keyId is required when trust.trustedIssuers names more than one issuer',
      );
    });
  });

  describe('providers', () => {
    it('refuses a provider field it does not read', async () => {
      const message = await refusal((c) => { c.providers['orders-idp'].clientId = 'orders'; });
      expect(message).toContain('providers["orders-idp"]: unknown field "clientId"');
    });

    it.each(['retrieve', 'assume'])('refuses the %s mode, which has no provider in this build', async (mode) => {
      const message = await refusal((c) => { c.providers['orders-idp'].mode = mode; });
      expect(message).toContain(`providers["orders-idp"]: mode "${mode}" has no provider in this build`);
    });

    it('refuses a mode that is not a mode', async () => {
      const message = await refusal((c) => { c.providers['orders-idp'].mode = 'oauth'; });
      expect(message).toContain('providers["orders-idp"]: mode must be "exchange", not "oauth"');
    });

    it('refuses an http token endpoint that is not on a loopback address', async () => {
      const message = await refusal((c) => {
        c.providers['orders-idp'].tokenEndpoint = 'http://idp.example.test/oauth2/v1/token';
      });
      expect(message).toContain('providers["orders-idp"]: tokenEndpoint must be an https URL');
    });

    it('refuses a token endpoint that carries a password', async () => {
      // Built from parts so that no URL with a password in it is written in this file.
      const endpoint = new URL('https://idp.example.test/token');
      endpoint.username = 'client';
      endpoint.password = 'pw';
      const message = await refusal((c) => { c.providers['orders-idp'].tokenEndpoint = endpoint.href; });
      expect(message).toContain('tokenEndpoint must not carry a user name or password');
      expect(message).not.toContain('pw@');
    });

    it('refuses a token endpoint that is not a URL', async () => {
      const message = await refusal((c) => { c.providers['orders-idp'].tokenEndpoint = 'idp.example.test/token'; });
      expect(message).toContain('providers["orders-idp"]: tokenEndpoint is not a URL');
    });

    it('refuses a provider list', async () => {
      const message = await refusal((c) => { c.providers = [c.providers['orders-idp']]; });
      expect(message).toContain('providers must be an object mapping a provider id to its configuration');
    });
  });

  describe('the assertion key', () => {
    it.each(['issuer', 'keyId'])('refuses an assertion section with no %s', async (field) => {
      const message = await refusal((c) => { delete c.assertion[field]; });
      expect(message).toContain(`assertion.${field} must be a non-empty string`);
    });

    it('refuses an assertion field it does not read', async () => {
      const message = await refusal((c) => { c.assertion.kid = 'broker-key-1'; });
      expect(message).toContain('assertion: unknown field "kid"');
    });

    it('creates the key beside the grant file, private to the owner, and publishes the public half', async () => {
      const config = await loadGrantConfig(write(validContent()));

      const keyFile = path.join(dir, 'assertion.key');
      expect(config.assertionKeyFile).toBe(keyFile);
      expect(config.assertionKeyCreated).toBe(true);
      if (process.platform !== 'win32') {
        expect(fs.statSync(keyFile).mode & 0o777).toBe(0o600);
      }
      const privateKey = crypto.createPrivateKey(fs.readFileSync(keyFile, 'utf-8'));
      expect(privateKey.asymmetricKeyType).toBe('ed25519');

      expect(config.assertionPublicKeyFile).toBe(`${keyFile}.pub.json`);
      const jwk = JSON.parse(fs.readFileSync(config.assertionPublicKeyFile, 'utf-8'));
      expect(Object.keys(jwk).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x']);
      expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', kid: 'broker-key-1', use: 'sig', alg: 'EdDSA' });
      expect(jwk.x).toBe((crypto.createPublicKey(privateKey).export({ format: 'jwk' }) as { x: string }).x);
    });

    it('signs with the same key on the next load, so a registered public key stays valid', async () => {
      const file = write(validContent());
      const first = await loadGrantConfig(file);
      const published = fs.readFileSync(first.assertionPublicKeyFile, 'utf-8');

      const second = await loadGrantConfig(file);

      expect(second.assertionKeyCreated).toBe(false);
      expect(fs.readFileSync(second.assertionPublicKeyFile, 'utf-8')).toBe(published);
    });

    it('rewrites the published key when the key id changes', async () => {
      await loadGrantConfig(write(validContent()));
      const content = validContent();
      content.assertion.keyId = 'broker-key-2';

      const config = await loadGrantConfig(write(content));

      expect(JSON.parse(fs.readFileSync(config.assertionPublicKeyFile, 'utf-8')).kid).toBe('broker-key-2');
    });

    it('creates no key for a file it refuses', async () => {
      await refusal((c) => { c.bindings[0].match.oasbLevel = '>=L4'; });

      expect(fs.existsSync(path.join(dir, 'assertion.key'))).toBe(false);
      expect(fs.existsSync(path.join(dir, 'assertion.key.pub.json'))).toBe(false);
    });

    it.skipIf(process.platform === 'win32')('refuses a key other users can read, with the command that fixes it', async () => {
      const file = write(validContent());
      await loadGrantConfig(file);
      const keyFile = path.join(dir, 'assertion.key');
      fs.chmodSync(keyFile, 0o644);

      const message = await loadGrantConfig(file).then(() => '', (err: Error) => err.message);

      expect(message).toContain(`assertion key ${keyFile} can be read or written by other users (mode 644)`);
      expect(message).toContain(`Fix:    chmod 600 ${keyFile}`);
    });

    it('refuses a key that is not Ed25519', async () => {
      const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      fs.writeFileSync(
        path.join(dir, 'assertion.key'),
        privateKey.export({ type: 'pkcs8', format: 'pem' }),
        { mode: 0o600 },
      );

      const message = await refusal(() => {});

      expect(message).toContain('holds a key of type "ec"');
      expect(message).toContain('must be an Ed25519 private key');
    });

    it('refuses a key file that holds no key', async () => {
      fs.writeFileSync(path.join(dir, 'assertion.key'), 'not a key\n', { mode: 0o600 });

      expect(await refusal(() => {})).toContain('cannot be read as a private key');
    });
  });
});
