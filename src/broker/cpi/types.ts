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
  /** Lifetime of the minted/scoped credential in seconds. */
  ttlSeconds: number;
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
  /** Seconds until the scoped credential expires. */
  expiresInSeconds: number;
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
