/**
 * Retrieve mode — AAP §5.1. SEAM, not implemented in v1.
 *
 * The provider holds a secret and returns its value; the broker either proxies the
 * operation itself so the value never leaves the broker, or injects the value into an
 * ephemeral worker. Secret stores, OS keychains, and vault platforms are Retrieve
 * providers. Dynamic secrets fold in here with an ephemeral flag — not a new mode.
 *
 * SCOPE: most Retrieve work is already roadmapped in Secretless features 170–199 and the
 * existing CredentialResolver (../resolver.ts) + backends (../../backends) already retrieve
 * secret values. v1 deliberately does NOT wire a Retrieve CPI provider — the no-standing-
 * secret modes (Assume, Exchange) are preferred (AAP §5.4). When implemented, this provider
 * SHOULD wrap the existing resolver/backends rather than re-fetch secrets.
 */

import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import type { CredentialProvider, CpiMode, ResourceBinding, ScopedCredential } from './types';

export class RetrieveProvider implements CredentialProvider {
  readonly modes: ReadonlyArray<CpiMode> = ['retrieve'];

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async resolve(_ctx: ResolutionContext, _binding: ResourceBinding): Promise<ScopedCredential> {
    throw new Error(
      'Retrieve mode is declared but not implemented in v1 (see Secretless features 170–199). ' +
        'Prefer Assume/Exchange — no standing secret (AAP §5.4).',
    );
  }
}
