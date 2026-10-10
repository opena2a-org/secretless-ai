/**
 * retracted-claims.mjs: sentences a released version of this package shipped
 * that described a protection the code did not provide, and that the source
 * has since withdrawn.
 *
 * Correcting the source reaches no user until a release ships the correction.
 * Until then every install gets the old text, and a type definition renders
 * it in the editor at the moment the field is used. Each sentence listed here
 * is checked in two places:
 *
 *   - release-artifact-review.mjs fails its `no-retracted-claims` check on a
 *     tarball any file of which carries one, so no release ships it again;
 *   - src/retracted-claims.test.ts fails when the source carries one, or when
 *     the tarball packed from the delivered tree does.
 *
 * Whether the version on the registry still carries a withdrawn sentence is
 * the same review run over the published tarball:
 *
 *   npm pack secretless-ai@latest --ignore-scripts
 *   node scripts/release-artifact-review.mjs --tarball secretless-ai-<version>.tgz
 *
 * `check no-retracted-claims: fail` names each file and line that carries one.
 *
 * Add an entry when a corrected security claim has shipped in a release, and
 * keep it: an entry is the record that the sentence must not come back.
 */

export const RETRACTED_CLAIMS = [
  {
    // The documentation of GrantPolicy's `trustClass`, `minTrustLevel` and
    // `oasbLevel` called each one enforced. The source documents what each
    // predicate depends on instead (src/broker/grant-policy.ts).
    text: 'Enforced in v1.',
    shipped: 'dist/broker/grant-policy.d.ts, three fields, in 0.23.0 and earlier',
  },
];

/**
 * A pattern for `text` that also matches it wrapped across the lines of a
 * comment: between two words, any run of whitespace, `*` or `/` stands for
 * the one space. Case-sensitive, and the first word must start a word.
 */
function claimPattern(text) {
  const words = text
    .trim()
    .split(/\s+/)
    .map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp(`(?<![A-Za-z0-9_])${words.join('[\\s*/]+')}`, 'g');
}

/**
 * Each retracted claim `content` carries, as the claim's text and the
 * 1-based line its first word is on, in line order.
 */
export function retractedClaimsIn(content) {
  const hits = [];
  for (const { text } of RETRACTED_CLAIMS) {
    for (const match of content.matchAll(claimPattern(text))) {
      hits.push({ claim: text, line: content.slice(0, match.index).split('\n').length });
    }
  }
  return hits.sort((a, b) => a.line - b.line);
}
