/**
 * Assume mode — AAP §5.2. SEAM, not implemented in v1.
 *
 * The provider takes an identity proof and returns short-lived, role-scoped credentials.
 * No standing secret. Cloud STS-style role assumption is Assume.
 *
 * The identity proof is the SAME broker assertion that Exchange mints (./assertion.ts).
 * That is the whole point of building Exchange first: once the assertion core exists, the
 * Assume path against a cloud STS is a second adapter that consumes the identical assertion
 * — no new credential format. When implemented, this provider mints the broker assertion
 * and calls the STS AssumeRole-with-web-identity equivalent, returning a ScopedCredential.
 */

import type { ResolutionContext } from '../atx';
import type { CredentialProvider, CpiMode, ResourceBinding, ScopedCredential } from './types';

export class AssumeProvider implements CredentialProvider {
  readonly modes: ReadonlyArray<CpiMode> = ['assume'];

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async resolve(_ctx: ResolutionContext, _binding: ResourceBinding): Promise<ScopedCredential> {
    throw new Error(
      'Assume mode is declared but not implemented in v1. It consumes the same broker ' +
        'assertion as Exchange (AAP §11); wire a cloud-STS adapter to enable it.',
    );
  }
}
