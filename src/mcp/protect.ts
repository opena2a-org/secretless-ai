/**
 * MCP protection orchestrator — discover → classify → encrypt → rewrite.
 *
 * Ties together all MCP protection modules into a single function that
 * scans all MCP client configs, identifies plaintext secrets, encrypts
 * them into the vault, and rewrites configs to use the secretless-mcp wrapper.
 */

import * as path from 'path';
import { discoverMcpConfigs } from './discover';
import { classifyEnvVars } from './classify';
import { McpVault } from './vault';
import { rewriteConfig } from './rewrite';
import { screenMcpEnvVars } from '../nanomind';
import type { SelectableBackendType } from '../backends/config';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InjectionWarning {
  client: string;
  server: string;
  key: string;
  injectionType: string;
  severity: string;
}

export interface ProtectOptions {
  /** Override home directory (for testing) */
  homeDir?: string;
  /** Override data directory for vault + backups (default: ~/.secretless-ai) */
  dataDir?: string;
  /** Absolute path to the secretless-mcp wrapper */
  wrapperPath: string;
  /** Backend type for secret storage. Defaults to config file or 'local'. */
  backendType?: SelectableBackendType;
}

export interface ProtectedServer {
  client: string;
  server: string;
  secretKeys: string[];
}

export interface ProtectResult {
  clientsScanned: number;
  secretsFound: number;
  serversProtected: number;
  servers: ProtectedServer[];
  alreadyProtected: number;
  /** Prompt injection warnings found in MCP env var values (requires @nanomind/guard) */
  injectionWarnings: InjectionWarning[];
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

/**
 * Main orchestrator: discover → classify → encrypt → rewrite.
 *
 * 1. Discovers all MCP config files across supported clients.
 * 2. For each server entry, classifies env vars into secrets vs non-secrets.
 * 3. Stores secrets in the encrypted vault.
 * 4. Rewrites config files to use the secretless-mcp wrapper.
 *
 * @param options - Configuration for the protection run.
 * @returns Summary of what was scanned and protected.
 */
export async function protectMcp(options: ProtectOptions): Promise<ProtectResult> {
  const home = options.homeDir;
  if (home && !path.isAbsolute(home)) {
    throw new Error(`homeDir must be an absolute path, got: "${home}"`);
  }
  const dataDir = options.dataDir ?? path.join(
    home ?? (process.env.HOME ?? process.env.USERPROFILE ?? '/tmp'),
    '.secretless-ai',
  );

  const vaultDir = path.join(dataDir, 'mcp-vault');
  const backupDir = path.join(dataDir, 'mcp-backups');

  // Derive a deterministic vault key from homeDir when provided (testing),
  // otherwise let LocalBackend use its default machine-based key.
  const vaultKey = home
    ? `${home}-secretless-mcp-${process.env.USER ?? 'default'}`
    : undefined;

  const vault = new McpVault({
    storeDir: vaultDir,
    ...(vaultKey ? { key: vaultKey } : {}),
    ...(options.backendType ? { backendType: options.backendType } : {}),
  });

  // 1. Discover all MCP configs
  const configs = discoverMcpConfigs(home);

  const result: ProtectResult = {
    clientsScanned: configs.length,
    secretsFound: 0,
    serversProtected: 0,
    servers: [],
    alreadyProtected: 0,
    injectionWarnings: [],
  };

  // 2. For each config: classify, encrypt, rewrite
  for (const config of configs) {
    const serverSecrets: Record<string, Record<string, string>> = {};

    for (const server of config.servers) {
      // Skip servers already wrapped by secretless-mcp
      if (server.alreadyProtected) {
        result.alreadyProtected++;
        continue;
      }

      // Classify env vars into secrets and non-secrets
      const classified = classifyEnvVars(server.env);

      // Screen non-secret env vars for prompt injection (if @nanomind/guard available)
      const injectionFindings = screenMcpEnvVars(classified.nonSecrets);
      for (const finding of injectionFindings) {
        result.injectionWarnings.push({
          client: config.client,
          server: server.name,
          key: finding.key,
          injectionType: finding.result.patterns[0]?.type ?? 'unknown',
          severity: finding.result.patterns[0]?.severity ?? 'medium',
        });
      }

      const secretCount = Object.keys(classified.secrets).length;

      if (secretCount === 0) continue;

      // Store secrets in encrypted vault
      await vault.storeServerSecrets(config.client, server.name, classified.secrets);
      serverSecrets[server.name] = classified.secrets;

      result.secretsFound += secretCount;
      result.servers.push({
        client: config.client,
        server: server.name,
        secretKeys: Object.keys(classified.secrets),
      });
    }

    // Rewrite config file if any servers had secrets
    if (Object.keys(serverSecrets).length > 0) {
      const rewriteResult = rewriteConfig(
        config.filePath,
        config.client,
        serverSecrets,
        options.wrapperPath,
        backupDir,
        options.backendType,
      );
      result.serversProtected += rewriteResult.serversRewritten;
    }
  }

  return result;
}
