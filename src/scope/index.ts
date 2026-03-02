/**
 * Credential scope discovery orchestrator.
 *
 * Auto-detects the provider from the credential format and runs
 * provider-specific scope discovery, comparing results against stored baselines.
 */

export type { ScopeBaseline, ScopeCheckResult, ScopeProvider } from './types';
export { GCPScopeProvider, parseServiceAccountKey, createSignedJwt } from './gcp';
export { VaultScopeProvider } from './vault';
export {
  saveBaseline, loadBaseline, listBaselines,
  compareToBaseline, resetBaseline,
} from './baselines';

import type { ScopeCheckResult, ScopeProvider } from './types';
import { GCPScopeProvider } from './gcp';
import { VaultScopeProvider } from './vault';
import { saveBaseline, compareToBaseline } from './baselines';

/**
 * Detect the scope provider from a credential's format.
 *
 * - JSON with `type: "service_account"` -> GCP
 * - Starts with `hvs.` or `s.` -> Vault
 * - Starts with `AKIA` -> AWS (not yet implemented)
 */
export function detectProvider(credential: string): string | null {
  const trimmed = credential.trim();

  // GCP service account key JSON
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.type === 'service_account') return 'gcp';
    } catch {
      // Not valid JSON
    }
  }

  // Vault token
  if (trimmed.startsWith('hvs.') || trimmed.startsWith('s.')) {
    return 'vault';
  }

  // AWS access key (future)
  if (/^AKIA[0-9A-Z]{16}$/.test(trimmed)) {
    return 'aws';
  }

  return null;
}

/**
 * Create a ScopeProvider instance for a given provider name and credential.
 */
export function createScopeProvider(provider: string, credential: string): ScopeProvider {
  switch (provider) {
    case 'gcp':
      return new GCPScopeProvider(credential);
    case 'vault':
      // credential IS the vault token -- use it for scope inspection
      // VAULT_ADDR still comes from env (the server address doesn't change)
      return new VaultScopeProvider(undefined, credential);
    default:
      throw new Error(`Unsupported scope provider: "${provider}"`);
  }
}

/**
 * Run scope discovery on a credential.
 *
 * 1. Auto-detects the provider from the credential format
 * 2. Runs provider-specific discovery to get current permissions
 * 3. Compares against the stored baseline
 * 4. Returns a ScopeCheckResult with expansion/contraction details
 *
 * If `saveAsBaseline` is true (default), the current permissions are saved
 * as the new baseline.
 */
export async function discoverScope(
  credentialName: string,
  credentialValue: string,
  options?: { saveAsBaseline?: boolean },
): Promise<ScopeCheckResult> {
  const shouldSave = options?.saveAsBaseline ?? true;

  const providerName = detectProvider(credentialValue);
  if (!providerName) {
    throw new Error(
      'Unable to detect credential provider. Supported formats: ' +
      'GCP service account key (JSON), Vault token (hvs./s. prefix)',
    );
  }

  if (providerName === 'aws') {
    throw new Error(
      'AWS scope discovery is not yet implemented. ' +
      'Use the opena2a CLI DRIFT-002 check for AWS key liveness verification.',
    );
  }

  const provider = createScopeProvider(providerName, credentialValue);
  const currentPermissions = await provider.discover(credentialValue);

  const result = compareToBaseline(credentialName, providerName, currentPermissions);

  if (shouldSave) {
    saveBaseline({
      credentialName,
      provider: providerName,
      permissions: currentPermissions,
      checkedAt: result.checkedAt,
    });
  }

  return result;
}
