# Vendored AAP conformance vectors

Files from the AAP conformance suite,
<https://github.com/opena2a-standards/aap-conformance> (Apache-2.0), at the
commit `PIN.json` names. `PIN.json` records the sha256 of each of the suite's
files at that commit. This is test data: nothing here is compiled into `dist`
or shipped in the npm package.

| File | Stored as |
|---|---|
| `vectors/test-keys.json` | the suite's bytes, unchanged |
| `fixtures/cgt-compact-valid.json` | the suite's bytes with the token withheld |
| `fixtures/cgt-mldsa65-compact-valid.json` | the suite's bytes with the token withheld |
| `fixtures/cgt-hybrid-general-valid.json` | the suite's bytes with the token withheld |

The keys in `vectors/test-keys.json` are the suite's test keys. Their seeds are
published, so they protect nothing and are never used outside fixture
reproduction.

## Why the tokens are withheld

The three fixtures are the tokens the broker's mint paths have to reproduce:
compact EdDSA, compact ML-DSA-65 and hybrid General JSON. In each copy the
string value of every token member is replaced by a `{{minted:<member>}}`
placeholder, and no other byte differs from the suite's file.

`../../assertion.conformance.test.ts` mints each token from the published test
keys, puts it where the placeholders are and compares the sha256 of the
rebuilt file with the pinned sha256. The digests are equal only when the broker
minted the suite's token byte for byte, so the comparison needs no stored copy
of the token, and this directory holds no signed token.

## Moving the pin

1. Set `commit` in `PIN.json` to the suite commit.
2. Copy the four files from that commit. In each fixture replace the string
   value of `token`, or of `tokenGeneral.payload` and of each
   `tokenGeneral.signatures[i].protected` and `.signature`, with its
   placeholder as the copies here show, changing no other byte.
3. Set each `sha256` to the sha256 of the suite's file at that commit. The
   suite's `MANIFEST.sha256` lists them.
4. Run `assertion.conformance.test.ts`. A parity test that fails after only the
   pin moved means the suite's token changed: the broker's mint, or the fixture
   inputs in `../../conformance-vectors.test-support.ts`, has to follow.
