/**
 * Credential Provider Interface (CPI) — AAP §5.
 *
 * A backend plugs into the broker by implementing the CPI and declaring which of the
 * three modes it supports. The modes correspond to the only three things a credential
 * authority can do:
 *
 *   - Retrieve : provider holds a secret and returns its value.            (broker secret surface: per-backend)
 *   - Assume   : provider takes an identity proof, returns short-lived,
 *                role-scoped credentials. No standing secret.              (broker secret surface: one signing key)
 *   - Exchange : provider is an OAuth-style authorization server; broker
 *                performs an RFC 8693 token exchange for a scoped token.   (broker secret surface: one signing key)
 *
 * Providers are CONFIGURATION, never protocol. No vendor or product name appears in any
 * type here (AAP Principle 4) — vendor specifics live only in a provider adapter.
 */

import type { ResolutionContext } from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };

export type CpiMode = 'retrieve' | 'assume' | 'exchange';

/**
 * The longest `ttlSeconds` a resource binding may carry: twelve hours.
 *
 * The TTL is added to the issue time to form the broker assertion's `exp`, and it is the life
 * the exchange site reports for the scoped credential when the authorization server states none.
 * A whole number has no upper bound of its own: `1e21` passes `Number.isInteger` and mints an
 * `exp` some thirty trillion years out, which a downstream verifier reads as no expiry at all,
 * the same outcome as the `"exp": null` the lower bound exists to prevent.
 *
 * Twelve hours is the longest assumed-role session the major cloud security-token services issue,
 * and the assertion this TTL governs is the identity proof Assume mode presents to one
 * (./assume.ts). A binding asking for longer asks for a life those services would not grant.
 *
 * The bound is enforced at two sites with one accept-set: where grant policy loads
 * (../grant-policy.ts) and where the assertion is minted (./assertion.ts), so a binding built
 * in code, which never passes the loader, meets the same bound.
 */
export const MAX_GRANT_TTL_SECONDS = 12 * 60 * 60;

/**
 * A resource binding comes from local broker policy (configuration). It maps a grant to
 * a concrete CPI mode, provider, downstream scope, audience, and TTL. It NEVER travels
 * on the wire and is never returned to the agent.
 */
export interface ResourceBinding {
  /** CPI mode used to resolve this grant. */
  mode: CpiMode;
  /** Opaque provider id resolved against the provider registry (e.g. "orders-idp"). */
  providerId: string;
  /** Downstream scope requested (e.g. "orders.read"). */
  scope: string;
  /** Downstream audience / resource (e.g. "https://api.orders.internal"). */
  audience: string;
  /**
   * Lifetime of the minted/scoped credential in seconds: a whole number from 1 to
   * MAX_GRANT_TTL_SECONDS.
   */
  ttlSeconds: number;
  /**
   * Trust class (ATX capability, e.g. "orders:read") the grant was matched under.
   * Injected by the grant resolver from the policy clause's match predicate — never
   * authored in configuration, so a binding does not duplicate its match clause. It is
   * carried into the broker assertion's `trust_class` claim (AAP-SPEC §4.2): the claim
   * is the abstract, portable capability, distinct from the downstream `scope`.
   */
  trustClass?: string;
}

/**
 * A scoped credential produced by a provider. It is CONFINED to the broker/ephemeral
 * worker (AAP §6.5) and MUST NOT be returned to the agent. Only the *result* of the
 * operation performed with it crosses back.
 */
export interface ScopedCredential {
  /** Scoped downstream token. Stays inside the broker. Never serialized to the agent. */
  token: string;
  /** Token type, e.g. "Bearer". */
  tokenType: string;
  /** Seconds until the scoped credential expires: at most the binding's TTL (capCredentialLife). */
  expiresInSeconds: number;
}

/**
 * The life to report for a scoped credential: what its provider stated, held to the binding's TTL.
 *
 * The TTL is the operator's ceiling on the credential's life, so a stated life can shorten it and
 * cannot extend it. A longer one reports the TTL, a negative one reports 0 (already expired), and
 * a value that is not a number (absent, NaN, a string) states no life, so the TTL stands.
 *
 * One rule for the two sites that report a life: where Exchange reads the authorization server's
 * `expires_in` (./exchange.ts), and where the grant resolver takes a credential from whichever
 * provider the registry returned (../grant-resolver.ts). `ttlSeconds` is a binding TTL inside its
 * range; each site passes one that was already checked.
 *
 * This bounds the life the broker reports. It does not shorten the credential the provider issued.
 */
export function capCredentialLife(stated: unknown, ttlSeconds: number): number {
  return typeof stated === 'number' && !Number.isNaN(stated)
    ? Math.max(0, Math.min(stated, ttlSeconds))
    : ttlSeconds;
}

/** A credential provider implements one or more CPI modes. */
export interface CredentialProvider {
  /** Modes this provider supports. */
  readonly modes: ReadonlyArray<CpiMode>;
  /**
   * Resolve a scoped credential for a verified-ATX context against a resource binding.
   * The returned credential is confined to the broker — the caller (ephemeral worker)
   * uses it and returns only the operation result.
   */
  resolve(ctx: ResolutionContext, binding: ResourceBinding): Promise<ScopedCredential>;
}

/** Resolves an opaque provider id to a configured provider. Adapters register here. */
export interface ProviderRegistry {
  get(providerId: string): CredentialProvider | undefined;
}
