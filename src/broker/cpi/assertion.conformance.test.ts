/**
 * Byte parity between the broker's mint paths and the AAP conformance suite.
 *
 * The suite's CGT ACCEPT fixtures carry the normative signed bytes of the three
 * forms the broker mints: compact EdDSA, compact ML-DSA-65 and hybrid General
 * JSON. They are vendored under ./vendor/aap-conformance at the commit PIN.json
 * names, with each token member replaced by a placeholder. Each parity test
 * mints from the suite's published test keys, puts the result where the
 * placeholders are and compares the sha256 of the rebuilt file with the pinned
 * sha256 of the suite's file. The digests are equal only when the broker
 * minted the suite's token byte for byte.
 *
 * A parity test that turns red after PIN.json moved means the suite's tokens
 * changed, and the broker's mint or the fixture inputs have to follow.
 */

import * as fs from 'fs';
import * as path from 'path';
import { describe, expect, it } from 'vitest';
import {
  brokerPublicAkpJwk,
  brokerPublicJwk,
  mintBrokerAssertion,
  mintBrokerAssertionMlDsa65,
  mintHybridBrokerAssertion,
} from './assertion';
import {
  CGT_BINDING,
  CGT_CONTEXT,
  CGT_IAT,
  CGT_JTI,
  CGT_PQ_JTI,
  ED_KID,
  PQC_KID,
  VENDOR_DIR,
  pinnedFile,
  publishedEdKey,
  publishedPqcKey,
  publishedPublicJwk,
  readPin,
  readVendored,
  rebuildUpstream,
  sha256Hex,
} from './conformance-vectors.test-support';

const decoded = (segment: string) => Buffer.from(segment, 'base64url').toString('utf8');

/** Every regular file under VENDOR_DIR, as sorted paths relative to it. */
function vendoredFiles(): string[] {
  const out: string[] = [];
  const walk = (rel: string) => {
    for (const entry of fs.readdirSync(path.join(VENDOR_DIR, rel), { withFileTypes: true })) {
      const child = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) walk(child);
      else out.push(child);
    }
  };
  walk('');
  return out.sort();
}

/**
 * Assert that the suite's `file`, rebuilt with `minted` in place of its token
 * members, is the file the pin names. `shape` is what was minted, decoded, for
 * the failure message: the repository holds no copy of the expected token to
 * print beside it.
 */
function expectSuiteBytes(file: string, minted: Record<string, string>, shape: string[]): void {
  const pin = readPin();
  expect(
    sha256Hex(rebuildUpstream(file, minted)),
    [
      `${file}: rebuilt from this mint, the file does not hash to the pinned sha256.`,
      'Either the broker no longer mints the suite token, or the vendored copy was edited.',
      ...shape,
      `Suite file: ${pin.source}/blob/${pin.commit}/${file}`,
    ].join('\n'),
  ).toBe(pinnedFile(file).sha256);
}

describe('vendored AAP conformance vectors', () => {
  it('are pinned to one suite commit with a sha256 for every file', () => {
    const pin = readPin();
    expect(pin.source).toBe('https://github.com/opena2a-standards/aap-conformance');
    expect(pin.commit).toMatch(/^[0-9a-f]{40}$/);
    for (const file of pin.files) {
      expect(file.sha256, file.path).toMatch(/^[0-9a-f]{64}$/);
      expect(['verbatim', 'token-withheld'], file.path).toContain(file.stored);
    }
    // The pin lists exactly the vendored files: none unpinned, none missing.
    expect(vendoredFiles().filter((f) => f !== 'PIN.json' && f !== 'README.md')).toEqual(
      pin.files.map((f) => f.path).sort(),
    );
  });

  it('hold the published test keys byte for byte', () => {
    const verbatim = readPin().files.filter((f) => f.stored === 'verbatim');
    expect(verbatim.map((f) => f.path)).toEqual(['vectors/test-keys.json']);
    for (const file of verbatim) {
      expect(sha256Hex(readVendored(file.path)), file.path).toBe(file.sha256);
    }
  });

  it('carry seeds that derive the published public keys', () => {
    expect(brokerPublicJwk(publishedEdKey())).toEqual(publishedPublicJwk(ED_KID));
    expect(brokerPublicAkpJwk(publishedPqcKey())).toEqual(publishedPublicJwk(PQC_KID));
  });
});

describe('broker mint parity with the AAP conformance suite', () => {
  it('compact EdDSA: mints aap-v1/cgt-compact-valid byte for byte', () => {
    const token = mintBrokerAssertion(CGT_CONTEXT, CGT_BINDING, publishedEdKey(), CGT_IAT, CGT_JTI);
    const [header, claims] = token.split('.');
    expectSuiteBytes('fixtures/cgt-compact-valid.json', { token }, [
      `Minted header: ${decoded(header)}`,
      `Minted claims: ${decoded(claims)}`,
    ]);
  });

  it('compact ML-DSA-65: mints aap-v1/cgt-mldsa65-compact-valid byte for byte', () => {
    const token = mintBrokerAssertionMlDsa65(
      CGT_CONTEXT,
      CGT_BINDING,
      publishedPqcKey(),
      CGT_IAT,
      CGT_PQ_JTI,
      { deterministic: true },
    );
    const [header, claims] = token.split('.');
    expectSuiteBytes('fixtures/cgt-mldsa65-compact-valid.json', { token }, [
      `Minted header: ${decoded(header)}`,
      `Minted claims: ${decoded(claims)}`,
    ]);
  });

  it('hybrid General JSON: mints aap-v1/cgt-hybrid-general-valid byte for byte', () => {
    const token = mintHybridBrokerAssertion(
      CGT_CONTEXT,
      CGT_BINDING,
      publishedEdKey(),
      publishedPqcKey(),
      CGT_IAT,
      CGT_JTI,
      { deterministic: true },
    );
    expect(token.signatures).toHaveLength(2);
    const [ed, pq] = token.signatures;
    expectSuiteBytes(
      'fixtures/cgt-hybrid-general-valid.json',
      {
        payload: token.payload,
        'signatures.0.protected': ed.protected,
        'signatures.0.signature': ed.signature,
        'signatures.1.protected': pq.protected,
        'signatures.1.signature': pq.signature,
      },
      [
        `Minted claims: ${decoded(token.payload)}`,
        `Minted protected headers: ${decoded(ed.protected)} ${decoded(pq.protected)}`,
      ],
    );
  });

  it('is sensitive to one byte: a mint that differs in its last character is not the suite file', () => {
    const token = mintBrokerAssertion(CGT_CONTEXT, CGT_BINDING, publishedEdKey(), CGT_IAT, CGT_JTI);
    const file = 'fixtures/cgt-compact-valid.json';
    expect(sha256Hex(rebuildUpstream(file, { token }))).toBe(pinnedFile(file).sha256);
    const last = token.slice(-1) === 'A' ? 'B' : 'A';
    expect(sha256Hex(rebuildUpstream(file, { token: token.slice(0, -1) + last }))).not.toBe(
      pinnedFile(file).sha256,
    );
  });
});
