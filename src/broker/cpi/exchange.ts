/**
 * Exchange mode — AAP §5.3. A profile of OAuth 2.0 Token Exchange (RFC 8693).
 *
 * The broker mints a broker assertion from the verified ATX (§11), then performs a
 * token exchange against the downstream authorization server to obtain a SCOPED bearer
 * token for the requested resource. The broker holds no standing secret to the backend —
 * only its one rotating signing key.
 *
 * This module is the reusable CORE. It is vendor-free: the token endpoint and the wire
 * transport are injected by a thin provider adapter (see okta-adapter.ts). A vendor name
 * appearing in this file would be a bug against AAP Principle 4.
 */

import type { ResolutionContext } from '../atx';
import type { CredentialProvider, CpiMode, ResourceBinding, ScopedCredential } from './types';
import { mintBrokerAssertion, type BrokerSigningKey } from './assertion';

export const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const SUBJECT_TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';
export const REQUESTED_TOKEN_TYPE_ACCESS = 'urn:ietf:params:oauth:token-type:access_token';

/** A single RFC 8693 token-exchange call. */
export interface TokenExchangeRequest {
  tokenEndpoint: string;
  /** Form-encoded parameters per RFC 8693 §2.1. */
  params: Record<string, string>;
}

/** The downstream authorization server's response (RFC 8693 §2.2.1). */
export interface TokenExchangeResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  issued_token_type?: string;
  scope?: string;
}

/** Pluggable transport so the core never depends on a concrete HTTP client or vendor. */
export interface TokenExchangeTransport {
  exchange(req: TokenExchangeRequest): Promise<TokenExchangeResponse>;
}

export interface ExchangeProviderConfig {
  /** Token endpoint of the downstream authorization server (from the adapter; config only). */
  tokenEndpoint: string;
  /** Subject token type for the minted broker assertion. */
  subjectTokenType?: string;
  /** Requested downstream token type. */
  requestedTokenType?: string;
}

export class ExchangeProvider implements CredentialProvider {
  readonly modes: ReadonlyArray<CpiMode> = ['exchange'];

  constructor(
    private readonly config: ExchangeProviderConfig,
    private readonly signingKey: BrokerSigningKey,
    private readonly transport: TokenExchangeTransport,
  ) {}

  async resolve(ctx: ResolutionContext, binding: ResourceBinding): Promise<ScopedCredential> {
    if (binding.mode !== 'exchange') {
      throw new Error(`ExchangeProvider received non-exchange binding (${binding.mode})`);
    }

    // 1. Mint the broker assertion from verified ATX claims (never from agent input).
    const assertion = mintBrokerAssertion(ctx, binding, this.signingKey);

    // 2. RFC 8693 token exchange for a scoped downstream token.
    const params: Record<string, string> = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: assertion,
      subject_token_type: this.config.subjectTokenType ?? SUBJECT_TOKEN_TYPE_JWT,
      scope: binding.scope,
      audience: binding.audience,
      requested_token_type: this.config.requestedTokenType ?? REQUESTED_TOKEN_TYPE_ACCESS,
    };

    const res = await this.transport.exchange({ tokenEndpoint: this.config.tokenEndpoint, params });
    if (!res || typeof res.access_token !== 'string' || res.access_token.length === 0) {
      throw new Error('token exchange returned no access_token');
    }

    // 3. Return a SCOPED credential. It is confined to the broker (§6.5) — the caller
    //    uses it in an ephemeral worker and returns only the operation result.
    return {
      token: res.access_token,
      tokenType: res.token_type ?? 'Bearer',
      expiresInSeconds: typeof res.expires_in === 'number' ? res.expires_in : binding.ttlSeconds,
    };
  }
}
