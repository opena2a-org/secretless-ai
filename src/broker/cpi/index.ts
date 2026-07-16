/**
 * Credential Provider Interface (CPI) — AAP §5 barrel.
 *
 * v1 implements Exchange; Retrieve and Assume are declared seams.
 */

export type {
  CpiMode,
  ResourceBinding,
  ScopedCredential,
  CredentialProvider,
  ProviderRegistry,
} from './types';

export {
  ExchangeProvider,
  TOKEN_EXCHANGE_GRANT_TYPE,
  SUBJECT_TOKEN_TYPE_JWT,
  REQUESTED_TOKEN_TYPE_ACCESS,
  type ExchangeProviderConfig,
  type TokenExchangeRequest,
  type TokenExchangeResponse,
  type TokenExchangeTransport,
} from './exchange';

export { HttpsTokenExchangeTransport } from './http-transport';
export { createOktaExchangeProvider, type OktaAdapterOptions } from './okta-adapter';
export { MapProviderRegistry } from './registry';
export {
  mintBrokerAssertion,
  generateBrokerSigningKey,
  brokerPublicJwk,
  mintBrokerAssertionMlDsa65,
  mintHybridBrokerAssertion,
  generateBrokerPqcSigningKey,
  brokerPublicAkpJwk,
  type BrokerSigningKey,
  type BrokerPqcSigningKey,
  type PqcMintOptions,
  type JwsGeneralJson,
} from './assertion';

// Declared-but-not-implemented seams (v1).
export { RetrieveProvider } from './retrieve';
export { AssumeProvider } from './assume';
