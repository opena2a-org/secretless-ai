/**
 * Okta provider adapter — the FIRST conformance test for Exchange mode (AAP §13/§14).
 *
 * This is the ONLY file in the broker permitted to name a vendor. AAP Principle 4 says no
 * vendor or product name appears in any protocol structure or in the broker core; vendors
 * are configuration. This adapter confines everything Okta-specific (its token-endpoint
 * convention) to one thin factory. If "Okta" leaks anywhere outside this file, it is a bug.
 *
 * Build to the standard, not to Okta: the adapter only knows how to construct an Okta token
 * endpoint URL. The actual RFC 8693 flow lives in the vendor-free ExchangeProvider, so the
 * Assume path against a cloud STS becomes a second adapter consuming the same broker assertion.
 */

import { ExchangeProvider, type ExchangeProviderConfig, type TokenExchangeTransport } from './exchange';
import { HttpsTokenExchangeTransport } from './http-transport';
import type { BrokerSigningKey } from './assertion';

export interface OktaAdapterOptions {
  /** Okta org base URL, e.g. "https://example.okta.com". */
  orgUrl: string;
  /** Custom authorization server id; omit for the org authorization server. */
  authorizationServerId?: string;
  /** The broker's IdP signing key (Okta is configured once to trust its public half). */
  signingKey: BrokerSigningKey;
  /** Override the wire transport (tests inject a fake). */
  transport?: TokenExchangeTransport;
}

/** Okta token-endpoint convention. The only Okta-specific knowledge in the codebase. */
function oktaTokenEndpoint(orgUrl: string, authorizationServerId?: string): string {
  const base = orgUrl.replace(/\/+$/, '');
  return authorizationServerId
    ? `${base}/oauth2/${authorizationServerId}/v1/token`
    : `${base}/oauth2/v1/token`;
}

/** Construct an Exchange provider backed by Okta. Returned as a generic CredentialProvider. */
export function createOktaExchangeProvider(opts: OktaAdapterOptions): ExchangeProvider {
  const config: ExchangeProviderConfig = {
    tokenEndpoint: oktaTokenEndpoint(opts.orgUrl, opts.authorizationServerId),
  };
  return new ExchangeProvider(
    config,
    opts.signingKey,
    opts.transport ?? new HttpsTokenExchangeTransport(),
  );
}
