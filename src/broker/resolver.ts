/**
 * Credential resolver — looks up secrets from SecretStore and McpVault.
 *
 * The resolver checks the user-managed SecretStore first, then falls back
 * to the MCP vault for MCP-scoped secrets. Returns the raw credential value
 * without exposing storage details to callers.
 */

import { SecretStore } from '../secret-store';
import { McpVault } from '../mcp/vault';

export interface ResolverOptions {
  /** Pre-constructed SecretStore instance (for DI/testing). */
  secretStore?: SecretStore;
  /** Pre-constructed McpVault instance (for DI/testing). */
  mcpVault?: McpVault;
}

export class CredentialResolver {
  private readonly secretStore: SecretStore;
  private readonly mcpVault: McpVault;

  constructor(options?: ResolverOptions) {
    this.secretStore = options?.secretStore ?? new SecretStore();
    this.mcpVault = options?.mcpVault ?? new McpVault();
  }

  /**
   * Resolve a credential by name.
   *
   * Lookup order:
   * 1. SecretStore (user-managed secrets under secret/ prefix)
   * 2. McpVault (MCP-scoped secrets, searched across all clients/servers)
   * 3. Environment variable fallback
   *
   * @param credentialName - Name of the credential to resolve
   * @returns The credential value, or undefined if not found
   */
  async resolve(credentialName: string): Promise<string | undefined> {
    // 1. Check SecretStore first
    const storeValue = await this.secretStore.getSecret(credentialName);
    if (storeValue !== undefined) {
      return storeValue;
    }

    // 2. Check MCP vault (search across all client/server combos)
    const mcpValue = await this.searchMcpVault(credentialName);
    if (mcpValue !== undefined) {
      return mcpValue;
    }

    // 3. Environment variable fallback
    const envValue = process.env[credentialName];
    if (envValue !== undefined) {
      return envValue;
    }

    return undefined;
  }

  /**
   * Check if a credential exists without returning its value.
   */
  async exists(credentialName: string): Promise<boolean> {
    const value = await this.resolve(credentialName);
    return value !== undefined;
  }

  /**
   * Search the MCP vault for a credential across all client/server entries.
   * Returns the first match found.
   */
  private async searchMcpVault(credentialName: string): Promise<string | undefined> {
    try {
      const entries = await this.mcpVault.listEntries();
      for (const entry of entries) {
        const secrets = await this.mcpVault.getServerSecrets(entry.client, entry.server);
        if (credentialName in secrets) {
          return secrets[credentialName];
        }
      }
    } catch {
      // MCP vault may not be configured — that is fine
    }
    return undefined;
  }
}
