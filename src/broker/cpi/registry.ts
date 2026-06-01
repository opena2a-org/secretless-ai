/**
 * Provider registry — resolves an opaque provider id (from broker policy) to a configured
 * CredentialProvider. Adapters register themselves here. The wire never carries a provider
 * id or a vendor name; this map lives entirely in broker configuration (AAP Principle 4).
 */

import type { CredentialProvider, ProviderRegistry } from './types';

export class MapProviderRegistry implements ProviderRegistry {
  private readonly providers = new Map<string, CredentialProvider>();

  register(providerId: string, provider: CredentialProvider): this {
    this.providers.set(providerId, provider);
    return this;
  }

  get(providerId: string): CredentialProvider | undefined {
    return this.providers.get(providerId);
  }
}
