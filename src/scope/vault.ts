/**
 * HashiCorp Vault scope discovery via capabilities-self API.
 *
 * Uses POST /v1/sys/capabilities-self to discover what the current Vault token
 * can do on various paths. This requires only a valid token -- no additional
 * policies or permissions are needed.
 *
 * Zero SDK dependency -- raw fetch calls to the Vault HTTP API.
 */

import type { ScopeProvider } from './types';

/** Vault paths relevant to credential and secret management. */
const VAULT_PROBE_PATHS = [
  'secret/data/*',
  'secret/metadata/*',
  'auth/token/lookup-self',
  'auth/token/renew-self',
  'sys/mounts',
  'sys/policies/acl',
  'sys/health',
  'sys/seal-status',
  'auth/userpass/*',
  'auth/ldap/*',
  'auth/oidc/*',
  'pki/issue/*',
  'transit/encrypt/*',
  'transit/decrypt/*',
  'database/creds/*',
];

const REQUEST_TIMEOUT_MS = 10_000;

interface CapabilitiesSelfResponse {
  capabilities?: Record<string, string[]>;
  data?: Record<string, string[]>;
}

/**
 * Vault scope discovery provider.
 *
 * Reads VAULT_ADDR and VAULT_TOKEN from environment variables (standard Vault
 * convention). Discovers the token's capabilities on predefined paths.
 */
export class VaultScopeProvider implements ScopeProvider {
  readonly name = 'vault';

  private addr: string;
  private token: string;

  constructor(addr?: string, token?: string) {
    this.addr = addr ?? process.env.VAULT_ADDR ?? '';
    this.token = token ?? process.env.VAULT_TOKEN ?? '';
  }

  async discover(): Promise<string[]> {
    if (!this.addr) {
      throw new Error('VAULT_ADDR not set');
    }
    if (!this.token) {
      throw new Error('VAULT_TOKEN not set');
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const url = `${this.addr.replace(/\/$/, '')}/v1/sys/capabilities-self`;

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'X-Vault-Token': this.token,
          'Content-Type': 'application/json',
          'User-Agent': 'secretless-ai-scope/1.0',
        },
        body: JSON.stringify({ paths: VAULT_PROBE_PATHS }),
        signal: controller.signal,
      });

      if (response.status === 403) {
        throw new Error('Vault token lacks permission to check capabilities');
      }

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(`Vault capabilities-self failed (HTTP ${response.status}): ${text}`);
      }

      const body = await response.json() as CapabilitiesSelfResponse;
      return capabilitiesToPermissions(body);
    } finally {
      clearTimeout(timeout);
    }
  }

  async healthCheck(): Promise<boolean> {
    if (!this.addr || !this.token) return false;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      try {
        const url = `${this.addr.replace(/\/$/, '')}/v1/sys/health`;
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            'User-Agent': 'secretless-ai-scope/1.0',
          },
          signal: controller.signal,
        });

        // Vault returns 200 for healthy, 429 for standby, 472 for DR secondary,
        // 473 for performance standby, 501 for not initialized, 503 for sealed
        return response.status === 200 || response.status === 429 ||
               response.status === 472 || response.status === 473;
      } finally {
        clearTimeout(timeout);
      }
    } catch {
      return false;
    }
  }
}

/**
 * Convert Vault capabilities-self response into a flat list of permission strings.
 * Format: "path:capability" (e.g., "secret/data/*:read", "sys/mounts:list")
 */
function capabilitiesToPermissions(response: CapabilitiesSelfResponse): string[] {
  const capabilities = response.data ?? response.capabilities ?? {};
  const permissions: string[] = [];

  for (const [path, caps] of Object.entries(capabilities)) {
    if (!Array.isArray(caps)) continue;

    for (const cap of caps) {
      // Skip "deny" capabilities -- they indicate lack of access
      if (cap === 'deny') continue;
      permissions.push(`${path}:${cap}`);
    }
  }

  return permissions.sort();
}
