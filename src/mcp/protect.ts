/**
 * MCP protection orchestrator — discover → classify → encrypt → rewrite.
 *
 * Ties together all MCP protection modules into a single function that
 * scans all MCP client configs, identifies plaintext secrets, encrypts
 * them into the vault, and rewrites configs to use the secretless-mcp wrapper.
 */

import * as path from 'path';
import { discoverMcpConfigsDetailed, rewrittenByProtectMcp } from './discover';
import type { McpConfigFile, McpServerEntry, UncheckedMcpServer, UnparsedMcpConfig } from './discover';
import { classifyEnvVars } from './classify';
import { McpVault } from './vault';
import { rewriteServerMaps, type ServerMapSecrets } from './rewrite';
import { screenMcpEnvVars } from '../nanomind';
import { prepareBinArgv, MCP_WRAPPER } from '../argv';
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
  /** Override project directory (for testing). Defaults to process.cwd(). */
  projectDir?: string;
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

/** A config that was read, with the server entries in it that had a part that could not be. */
export interface UncheckedMcpConfig {
  client: string;
  filePath: string;
  /** The path from the project directory, for a config found there. Absent for a config in the home directory. */
  projectPath?: string;
  /** For the server map of one project in ~/.claude.json: the key it is under (see McpConfigFile). */
  projectKey?: string;
  servers: UncheckedMcpServer[];
}

/** Where a server map is: its file, and the project it is kept for in ~/.claude.json. */
export interface McpServerMapLocation {
  filePath: string;
  /** The path from the project directory, for a config found there. Absent for a config in the home directory. */
  projectPath?: string;
  /** For the server map of one project in ~/.claude.json: the key it is under (see McpConfigFile). */
  projectKey?: string;
}

/**
 * A server with secrets that protect-mcp left as it is, because a protected
 * server in another server map reads its secrets by the same client and
 * server name. Secrets are stored under that name, so storing this server's
 * would hand them to the other server.
 */
export interface SharedNameMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
  /** The server map holding the protected server that reads its secrets by this name. */
  protectedIn: McpServerMapLocation;
}

/** A project-level config protect-mcp leaves as it is (see rewrittenByProtectMcp). */
export interface ProjectLevelMcpConfig {
  client: string;
  filePath: string;
  /** The path from the project directory. */
  projectPath: string;
}

export interface ProtectResult {
  clientsScanned: number;
  secretsFound: number;
  serversProtected: number;
  servers: ProtectedServer[];
  alreadyProtected: number;
  /** Prompt injection warnings found in MCP env var values (requires @nanomind/guard) */
  injectionWarnings: InjectionWarning[];
  /** Config files that exist but could not be read or parsed: nothing in them was checked or protected. */
  unparsed: UnparsedMcpConfig[];
  /** Server entries with a part that could not be read: a secret in that part was not found or protected. */
  unchecked: UncheckedMcpConfig[];
  /** Servers with secrets left as they are, in plaintext, because their name is a protected server's (see SharedNameMcpServer). */
  sharedName: SharedNameMcpServer[];
  /**
   * Project-level configs left as they are, parsed or not: nothing in them was
   * checked or protected. `mcp-status` lists their servers.
   */
  projectLevel: ProjectLevelMcpConfig[];
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

/**
 * Main orchestrator: discover → classify → encrypt → rewrite.
 *
 * 1. Discovers all MCP config files across supported clients. A project-level
 *    config other than .mcp.json is returned in `projectLevel`, unchanged.
 * 2. For each server entry, classifies env vars into secrets vs non-secrets.
 * 3. Stores secrets in the encrypted vault, under the client and server name.
 *    A server whose name is a protected server's in another server map is
 *    returned in `sharedName`, unchanged.
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

  // 1. Discover all MCP configs. A project-level config other than .mcp.json
  // is left as it is and returned by name (see rewrittenByProtectMcp).
  const discovered = discoverMcpConfigsDetailed(home, options.projectDir);
  const configs = discovered.configs.filter(rewrittenByProtectMcp);
  const unparsed = discovered.unparsed.filter(rewrittenByProtectMcp);
  const projectLevel: ProjectLevelMcpConfig[] = [];
  for (const { client, filePath, projectPath } of [...discovered.configs, ...discovered.unparsed]) {
    if (projectPath !== undefined && !rewrittenByProtectMcp({ projectPath })) {
      projectLevel.push({ client, filePath, projectPath });
    }
  }

  const result: ProtectResult = {
    clientsScanned: configs.length,
    secretsFound: 0,
    serversProtected: 0,
    servers: [],
    alreadyProtected: 0,
    injectionWarnings: [],
    unparsed,
    unchecked: configs
      .filter((config) => config.unchecked.length > 0)
      .map((config) => ({ client: config.client, ...mapLocation(config), servers: config.unchecked })),
    sharedName: [],
    projectLevel,
  };

  // Secrets are stored under the client and server name, and a protected
  // server's wrapper reads them back by that name. So a name belongs to the
  // server map holding a protected server that reads by it, protected before
  // this run or during it, and a server with secrets in another map that
  // would be stored under it is left as it is (see SharedNameMcpServer).
  const nameHolders = new Map<string, McpConfigFile>();
  for (const config of configs) {
    for (const server of config.servers) {
      const name = server.alreadyProtected ? protectedVaultName(config.client, server) : undefined;
      if (name !== undefined && !nameHolders.has(name)) nameHolders.set(name, config);
    }
  }

  // 2. For each config: classify, encrypt, rewrite. The server maps of one
  // file, the top level and each project of ~/.claude.json, are rewritten
  // together, so the file's backup is the file as it was before any of them.
  for (const [filePath, fileConfigs] of configsByFile(configs)) {
    const maps: ServerMapSecrets[] = [];

    for (const config of fileConfigs) {
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

        const name = `${config.client}/${server.name}`;
        const holder = nameHolders.get(name);
        if (holder !== undefined) {
          result.sharedName.push({
            client: config.client,
            ...mapLocation(config),
            server: server.name,
            protectedIn: mapLocation(holder),
          });
          continue;
        }
        nameHolders.set(name, config);

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

      if (Object.keys(serverSecrets).length > 0) {
        maps.push({ ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }), serverSecrets });
      }
    }

    // Rewrite config file if any servers had secrets
    if (maps.length > 0) {
      const rewriteResult = rewriteServerMaps(
        filePath,
        fileConfigs[0].client,
        maps,
        options.wrapperPath,
        backupDir,
        options.backendType,
      );
      result.serversProtected += rewriteResult.serversRewritten;
    }
  }

  return result;
}

/**
 * The client and server name a protected server's wrapper reads its secrets
 * by: its `--client` and `--server` values, read from its args as the wrapper
 * reads them, or the config's client and the server's name where one is not
 * given.
 */
function protectedVaultName(client: string, server: McpServerEntry): string {
  const args = prepareBinArgv(MCP_WRAPPER, server.args).args;
  let vaultClient = client;
  let vaultServer = server.name;
  for (let i = 0; i < args.length && args[i] !== '--'; i++) {
    const flag = args[i];
    // Every wrapper flag takes a value, and the wrapper reads the token after it as that value.
    if (MCP_WRAPPER.flags[flag] !== true || args[i + 1] === undefined) continue;
    const value = args[++i];
    if (flag === '--client') vaultClient = value;
    if (flag === '--server') vaultServer = value;
  }
  return `${vaultClient}/${vaultServer}`;
}

/** The configs of each file, in the order the files were found. */
function configsByFile(configs: readonly McpConfigFile[]): Map<string, McpConfigFile[]> {
  const byFile = new Map<string, McpConfigFile[]>();
  for (const config of configs) {
    const fileConfigs = byFile.get(config.filePath);
    if (fileConfigs) fileConfigs.push(config);
    else byFile.set(config.filePath, [config]);
  }
  return byFile;
}

/** Where a config's server map is, without the fields that are absent. */
function mapLocation(config: McpServerMapLocation): McpServerMapLocation {
  return {
    filePath: config.filePath,
    ...(config.projectPath === undefined ? {} : { projectPath: config.projectPath }),
    ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }),
  };
}
