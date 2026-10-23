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
import { resolveBackendType } from '../backends/config';
import type { SelectableBackendType } from '../backends/config';
import { effectiveBackendName } from '../backends/factory';
import { listedName, quotedName } from '../secret-value';

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

/**
 * A server that already runs through the wrapper, with secrets in plaintext
 * in its env that protect-mcp left there, because moving them into the store
 * is not safe (see unmovedReason and storedValueReason).
 */
export interface UnmovedMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
  /** Why the secrets were left, e.g. "another protected server reads its secrets by the same name, cursor/github". */
  reason: string;
}

/** A project-level config protect-mcp leaves as it is (see rewrittenByProtectMcp). */
export interface ProjectLevelMcpConfig {
  client: string;
  filePath: string;
  /** The path from the project directory. */
  projectPath: string;
}

export interface ProtectResult {
  /**
   * The number of MCP clients with a config that was checked for secrets (not
   * one in `unparsed` or `projectLevel`). A client with several configs, or
   * with several server maps in one file (~/.claude.json), counts once.
   */
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
  /** Servers that run through the wrapper with secrets left in plaintext in their env (see UnmovedMcpServer). */
  unmoved: UnmovedMcpServer[];
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
 *    returned in `sharedName`, unchanged. A server that already runs through
 *    the wrapper has its secrets stored under the name its wrapper reads by,
 *    or, where that is not safe, is returned in `unmoved`, unchanged.
 * 4. Rewrites config files to use the secretless-mcp wrapper. A server that
 *    already runs through it keeps its command and args, and the secrets
 *    stored for it are removed from its env.
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
    clientsScanned: new Set(configs.map((config) => config.client)).size,
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
    unmoved: [],
    projectLevel,
  };

  // Secrets are stored under the client and server name, and a protected
  // server's wrapper reads them back by that name. So a name belongs to the
  // server map holding a protected server that reads by it, protected before
  // this run or during it, and a server with secrets in another map that
  // would be stored under it is left as it is (see SharedNameMcpServer).
  // `readers` counts the protected servers that read by each name in every
  // config this run parsed, the project-level ones it leaves as they are
  // included: a secret stored under a name is handed to every one of them.
  const nameHolders = new Map<string, McpConfigFile>();
  const readers = new Map<string, number>();
  for (const config of discovered.configs) {
    for (const server of config.servers) {
      if (!server.alreadyProtected) continue;
      const name = protectedVaultName(config.client, server);
      if (rewrittenByProtectMcp(config) && !nameHolders.has(name)) nameHolders.set(name, config);
      readers.set(name, (readers.get(name) ?? 0) + 1);
    }
  }
  const stores: WrapperStores = {
    run: resolveBackendType(options.backendType),
    configured: resolveBackendType(),
    keyed: vaultKey !== undefined,
  };

  // 2. For each config: classify, encrypt, rewrite. The server maps of one
  // file, the top level and each project of ~/.claude.json, are rewritten
  // together, so the file's backup is the file as it was before any of them.
  for (const [filePath, fileConfigs] of configsByFile(configs)) {
    const maps: ServerMapSecrets[] = [];

    for (const config of fileConfigs) {
      const serverSecrets: Record<string, Record<string, string>> = {};
      const storedEnvKeys: Record<string, string[]> = {};

      for (const server of config.servers) {
        // Classify env vars into secrets and non-secrets
        const classified = classifyEnvVars(server.env);
        const secretKeys = Object.keys(classified.secrets);

        // A server already wrapped by secretless-mcp reads its secrets from
        // the store, and the wrapper does not take a value out of the file.
        // A secret in its env is stored under the name its wrapper reads by
        // and removed from its env, where that is safe.
        if (server.alreadyProtected) {
          if (secretKeys.length === 0) {
            result.alreadyProtected++;
            continue;
          }
          const readerCount = readers.get(protectedVaultName(config.client, server)) ?? 0;
          const reason = unmovedReason(config.client, server, readerCount, stores);
          if (reason !== undefined) {
            result.unmoved.push({ client: config.client, ...mapLocation(config), server: server.name, reason });
            continue;
          }
          const reads = readsBy(config.client, server);
          // The wrapper gives the server a value stored under an env name in
          // place of the one in its env, so storing another value under that
          // name would change the credential the server is given.
          const stored = await vault.getServerSecrets(reads.client, reads.server);
          const differing = secretKeys.filter((key) =>
            Object.prototype.hasOwnProperty.call(stored, key) && stored[key] !== classified.secrets[key]);
          if (differing.length > 0) {
            result.unmoved.push({ client: config.client, ...mapLocation(config), server: server.name, reason: storedValueReason(differing, reads) });
            continue;
          }
          await vault.storeServerSecrets(reads.client, reads.server, classified.secrets);
          storedEnvKeys[server.name] = secretKeys;
          result.secretsFound += secretKeys.length;
          result.servers.push({ client: config.client, server: server.name, secretKeys });
          continue;
        }

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

      if (Object.keys(serverSecrets).length > 0 || Object.keys(storedEnvKeys).length > 0) {
        maps.push({ ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }), serverSecrets, storedEnvKeys });
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
 * The wrapper flags given in a protected server's args, each with the value
 * the wrapper reads for it: the args are read as the wrapper reads them, up
 * to `--`, and a flag given twice has its last value.
 */
function wrapperFlags(server: McpServerEntry): Map<string, string> {
  const args = prepareBinArgv(MCP_WRAPPER, server.args).args;
  const flags = new Map<string, string>();
  for (let i = 0; i < args.length && args[i] !== '--'; i++) {
    const flag = args[i];
    // Every wrapper flag takes a value, and the wrapper reads the token after it as that value.
    if (MCP_WRAPPER.flags[flag] !== true || args[i + 1] === undefined) continue;
    flags.set(flag, args[++i]);
  }
  return flags;
}

/**
 * The client and server name a protected server's wrapper reads its secrets
 * by: its `--client` and `--server` values, read from its args as the wrapper
 * reads them, or the config's client and the server's name where one is not
 * given.
 */
function readsBy(client: string, server: McpServerEntry): { client: string; server: string } {
  const flags = wrapperFlags(server);
  return { client: flags.get('--client') ?? client, server: flags.get('--server') ?? server.name };
}

/** The name readsBy gives, as `client/server`. */
function protectedVaultName(client: string, server: McpServerEntry): string {
  const reads = readsBy(client, server);
  return `${reads.client}/${reads.server}`;
}

/**
 * The backend this run stores secrets in, the configured one a wrapper given
 * no --backend reads from, and whether this run's vault has a key. Only a run
 * given a home directory gives it one, and without one `local` is the
 * platform keychain while no backend is configured (see effectiveBackendName).
 */
interface WrapperStores {
  run: SelectableBackendType;
  configured: SelectableBackendType;
  keyed: boolean;
}

/**
 * Why the secrets in the env of a server that runs through the wrapper are
 * left there, or undefined when they are stored. A secret stored under a name
 * is handed to every protected server that reads by it, so it is stored only
 * when this server is the one server that does (`readerCount` counts them).
 * It is stored only where its wrapper reads it, as far as this run can tell:
 * the args name no --vault-dir or --vault-key, and give no --backend other
 * than the backend this run stores in, or, giving none, the configured
 * backend is that backend; and for `local`, which the wrapper reads from the
 * encrypted file, this run's vault is that file.
 */
function unmovedReason(
  client: string,
  server: McpServerEntry,
  readerCount: number,
  stores: WrapperStores,
): string | undefined {
  if (readerCount > 1) {
    return `another protected server reads its secrets by the same name, ${listedName(protectedVaultName(client, server))}`;
  }
  const flags = wrapperFlags(server);
  if (flags.has('--vault-dir') || flags.has('--vault-key')) {
    return 'its args choose the store its wrapper reads from with --vault-dir or --vault-key';
  }
  const backend = flags.get('--backend');
  if (backend === undefined && stores.configured !== stores.run) {
    return `its wrapper reads from the configured backend, ${stores.configured}, and this run stores in ${stores.run}`;
  }
  if (backend !== undefined && backend !== stores.run) {
    return `its --backend argument is ${quotedName(backend)}, and this run stores in ${stores.run}`;
  }
  // The wrapper gives its store a key, so for `local` it builds the encrypted
  // file, where this run's vault, built without one, can be the platform keychain.
  if (stores.run === 'local' && !stores.keyed) {
    const runStore = effectiveBackendName('local');
    if (runStore !== 'local') {
      return `its wrapper reads from the local encrypted file, and this run stores in ${runStore}`;
    }
  }
  return undefined;
}

/**
 * Why the secrets in the env of a server that runs through the wrapper are
 * left there when the env names in `envKeys` are stored with other values
 * under the name its wrapper reads by.
 */
function storedValueReason(envKeys: string[], reads: { client: string; server: string }): string {
  const names = envKeys.map(listedName).join(', ');
  const pair = listedName(`${reads.client}/${reads.server}`);
  return envKeys.length === 1
    ? `${names} is stored under ${pair} with another value, which its wrapper gives the server in place of the one in its env`
    : `${names} are stored under ${pair} with other values, which its wrapper gives the server in place of the ones in its env`;
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
