/**
 * MCP protection orchestrator — discover → classify → encrypt → rewrite.
 *
 * Ties together all MCP protection modules into a single function that
 * scans all MCP client configs, identifies plaintext secrets, encrypts
 * them into the vault, and rewrites configs to use the secretless-mcp wrapper.
 */

import * as fs from 'fs';
import * as path from 'path';
import { discoverMcpConfigsDetailed, rewrittenByProtectMcp, serverMapKey } from './discover';
import type { McpConfigFile, McpServerEntry, UncheckedMcpServer, UnparsedMcpConfig } from './discover';
import { classifyEnvVars } from './classify';
import { McpVault, boundEntryName, commandDigest, isBindingId, mcpNameProblem, newBindingId } from './vault';
import type { McpBinding } from './vault';
import { readConfigBackup, rewriteServerMaps, type ServerMapSecrets } from './rewrite';
import { packageVersionAbove } from './wrapper-version';
import { screenMcpEnvVars } from '../nanomind';
import { readWrapperArgv, withWrapperBinding, wrapperFlag } from '../argv';
import { resolveBackendType } from '../backends/config';
import type { SelectableBackendType } from '../backends/config';
import { effectiveBackendName } from '../backends/factory';
import { listedName, quotedName } from '../secret-value';
import { escapeForDisplay } from '../display-safe';

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
 * server in another server map, in any config it reads, a project-level one
 * it leaves as it is included, reads its secrets by the same client and
 * server name. Secrets are stored under that name, so storing this server's
 * would hand them to the other server.
 */
export interface SharedNameMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
  /** The server map holding the protected server that reads its secrets by this name. */
  protectedIn: McpServerMapLocation;
  /**
   * When the secrets stored under the name are bound to a config entry (see
   * McpBinding) that is not a protected server this run read: that entry,
   * whose file is protectedIn's.
   */
  boundTo?: McpBoundEntry;
}

/** The config entry a binding names: its server name as written, its file and its ~/.claude.json project key. */
export interface McpBoundEntry {
  server: string;
  file: string;
  projectKey?: string;
}

/**
 * A server that runs through the wrapper, bound this run to the secrets
 * stored under the name its wrapper reads by: protected by an earlier version
 * and bound in place, or bound in place of a server no longer in its config.
 */
export interface BoundMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
  /** For a binding taken over from a server no longer in its config: that server's entry. */
  tookOver?: McpBoundEntry;
}

/**
 * A bound server in a home config whose command or arguments changed since
 * it was bound, bound again this run to the command it has now.
 */
export interface ReboundMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
}

/**
 * A server that runs through the wrapper and is not bound to the secrets
 * stored under the name its wrapper reads by, so the wrapper does not start
 * it. The reason says why and what to change.
 */
export interface UnboundMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
  /** Why it is not bound, e.g. "the secrets stored under cursor/github are bound to server "github" in ...". Names only. */
  reason: string;
}

/**
 * A server that runs through the wrapper carrying the binding of another
 * config entry, a copy of that entry: the wrapper gives it that entry's
 * secrets when its command is that entry's. protect-mcp writes nothing for it.
 */
export interface CopiedBindingMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
  /** The entry the binding names. */
  boundTo: McpBoundEntry;
  /** protect-mcp replaced that home binding with a new id (see replaceBinding): this entry no longer starts. */
  replaced?: true;
  /** Why protect-mcp could not replace that home binding: this entry still receives its secrets. */
  replaceError?: string;
}

/**
 * A server with secrets that protect-mcp left as it is: secrets are stored
 * under the server's name, and the store refuses that name (see
 * mcpNameProblem).
 */
export interface RefusedNameMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
  /** Why the store refuses the name, e.g. "the store refuses its name, since it is empty". */
  reason: string;
}

/**
 * A server with secrets in plaintext in its env that protect-mcp left there,
 * because moving them into the store is not safe: one that already runs
 * through the wrapper (see unmovedReason and storedValueReason), or one whose
 * secrets would be stored under a name that holds stored secrets other than
 * its own, or, for a project-level config, any stored secret (see
 * unwrappedStoredReason and projectStoredReason).
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
  /** Servers with secrets left as they are, in plaintext, because the store refuses their name (see RefusedNameMcpServer). */
  refusedName: RefusedNameMcpServer[];
  /** Servers with secrets left in plaintext in their env, because moving them into the store is not safe (see UnmovedMcpServer). */
  unmoved: UnmovedMcpServer[];
  /** Servers that run through the wrapper and were bound this run (see BoundMcpServer). */
  bound: BoundMcpServer[];
  /** Bound servers in home configs whose command changed, bound again this run (see ReboundMcpServer). */
  rebound: ReboundMcpServer[];
  /** Servers that run through the wrapper and are not bound, so the wrapper does not start them (see UnboundMcpServer). */
  unbound: UnboundMcpServer[];
  /** Servers carrying the binding of another config entry (see CopiedBindingMcpServer). */
  copies: CopiedBindingMcpServer[];
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
 *    A server whose name is a protected server's in another server map, in
 *    any config found, is returned in `sharedName`, unchanged, one whose name
 *    the vault refuses in `refusedName`, and one whose name holds stored
 *    secrets other than its own, or, for a project-level config, any stored
 *    secret, in `unmoved`. A server that already runs through the wrapper
 *    has its secrets stored under the name its wrapper reads by, or, where
 *    that is not safe, is returned in `unmoved`, unchanged.
 * 4. Rewrites config files to use the secretless-mcp wrapper. A server that
 *    already runs through it keeps its command and args, and the secrets
 *    stored for it are removed from its env. A file with a server that ran
 *    through the wrapper before this run keeps the backup an earlier run
 *    wrote (see RewriteOptions.keepBackup).
 *
 * Every pair whose secrets this run stores is bound to the entry they came
 * from (see McpBinding): the binding is stored before the secrets, and its
 * id is written into the entry's wrapper args. A server that already runs
 * through the wrapper is bound in place when the pair's secrets are shown to
 * be its own (see bindWrapped), returned in `bound` or `rebound`, and
 * otherwise in `unbound` or `copies`, with why.
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
  // otherwise give none, as the wrapper gives none when its args name no
  // --vault-dir or --vault-key: both then build one store for one backend,
  // and for `local` it is the platform keychain while no backend is
  // configured, where there is one, and otherwise LocalBackend's encrypted
  // file under its default machine-based key.
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
    refusedName: [],
    unmoved: [],
    bound: [],
    rebound: [],
    unbound: [],
    copies: [],
    projectLevel,
  };

  // Secrets are stored under the client and server name, and a protected
  // server's wrapper reads them back by that name. So a name belongs to the
  // server map holding a protected server that reads by it, protected before
  // this run or during it, and a server with secrets in another map that
  // would be stored under it is left as it is (see SharedNameMcpServer).
  // `readers` holds, for each name, the config of each protected server that
  // reads by it in every config this run parsed, the project-level ones it
  // leaves as they are included: a secret stored under a name is handed to
  // every one of them.
  const nameHolders = new Map<string, McpConfigFile>();
  const readers = new Map<string, McpConfigFile[]>();
  for (const config of discovered.configs) {
    for (const server of config.servers) {
      if (!server.alreadyProtected) continue;
      const name = protectedVaultName(config.client, server);
      if (rewrittenByProtectMcp(config) && !nameHolders.has(name)) nameHolders.set(name, config);
      const readerConfigs = readers.get(name);
      if (readerConfigs) readerConfigs.push(config);
      else readers.set(name, [config]);
    }
  }
  const stores: WrapperStores = {
    run: resolveBackendType(options.backendType),
    configured: resolveBackendType(),
    keyed: vaultKey !== undefined,
  };

  // The servers that run through the wrapper, by the name they read by, in
  // the configs this run rewrites: a pair's secrets are bound to one entry,
  // so a pair read by more than one of them is bound to none (see
  // bindWrapped). One in a project-level config this run leaves as it is can
  // never be bound, so it is not counted.
  const rewrittenReaders = new Map<string, Array<{ config: McpConfigFile; server: McpServerEntry }>>();
  for (const config of configs) {
    for (const server of config.servers) {
      if (!server.alreadyProtected) continue;
      const name = protectedVaultName(config.client, server);
      const entries = rewrittenReaders.get(name);
      if (entries) entries.push({ config, server });
      else rewrittenReaders.set(name, [{ config, server }]);
    }
  }
  const binder: Binder = {
    vault,
    discovered,
    rewrittenReaders,
    stores,
    backupDir,
    bindings: new Map(),
    boundBy: packageVersionAbove(__dirname) ?? 'unknown',
    wrapperPath: options.wrapperPath,
    backendType: options.backendType,
  };

  // 2. For each config: classify, encrypt, rewrite. The server maps of one
  // file, the top level and each project of ~/.claude.json, are rewritten
  // together, so the file's backup is the file as it was before any of them.
  for (const [filePath, fileConfigs] of configsByFile(configs)) {
    const maps: ServerMapSecrets[] = [];

    for (const config of fileConfigs) {
      const serverSecrets: Record<string, Record<string, string>> = {};
      const storedEnvKeys: Record<string, string[]> = {};
      // The binding id written into each server's wrapper args this run.
      const bindings: Record<string, string> = {};

      for (const server of config.servers) {
        // Classify env vars into secrets and non-secrets
        const classified = classifyEnvVars(server.env);
        const secretKeys = Object.keys(classified.secrets);

        // A server already wrapped by secretless-mcp reads its secrets from
        // the store, and the wrapper does not take a value out of the file.
        // A secret in its env is stored under the name its wrapper reads by
        // and removed from its env, where that is safe. First, whether the
        // pair it reads is bound to it: the wrapper gives the pair's secrets
        // to that entry only.
        if (server.alreadyProtected) {
          const location = { client: config.client, ...mapLocation(config), server: server.name };
          const reads = wrapperReads(config.client, server);
          // Whether a secret in its env may be stored, and why not.
          let storeReason: string | undefined;
          if (secretKeys.length > 0) {
            const readerCount = readers.get(protectedVaultName(config.client, server))?.length ?? 0;
            storeReason = unmovedReason(config.client, server, readerCount, stores);
            if (storeReason === undefined) {
              // A value from a project-level config is stored only under a name
              // that holds no stored secret, so it neither adds to nor replaces
              // the secrets stored under that name.
              const stored = await vault.getServerSecrets(reads.client, reads.server);
              storeReason = projectStoredReason(config, stored, reads);
              // The wrapper gives the server a value stored under an env name in
              // place of the one in its env, so storing another value under that
              // name would change the credential the server is given.
              const differing = secretKeys.filter((key) =>
                Object.prototype.hasOwnProperty.call(stored, key) && stored[key] !== classified.secrets[key]);
              if (storeReason === undefined && differing.length > 0) storeReason = storedValueReason(differing, reads);
            }
          }

          // The binding is stored before any secret (see applyBinding), and
          // whether or not a secret in its env is stored.
          const plan = await bindWrapped(binder, config, server, secretKeys.length > 0 && storeReason === undefined);
          if (plan.kind === 'left') result.unbound.push({ ...location, reason: plan.reason });
          if (plan.kind === 'copy') result.copies.push({ ...location, boundTo: boundEntry(plan.binding) });
          if (plan.kind === 'replace') {
            const why = await replaceBinding(binder, plan, reads);
            result.copies.push({ ...location, boundTo: boundEntry(plan.binding), ...(why === undefined ? { replaced: true } : { replaceError: why }) });
          }
          const bound = await applyBinding(binder, plan, config, server, bindings, result);
          if (!bound && (plan.kind === 'bind' || plan.kind === 'rebind')) {
            result.unbound.push({ ...location, reason: bindingNotStoredReason(binder.lastError) });
          }

          if (secretKeys.length === 0) {
            result.alreadyProtected++;
            continue;
          }
          if (storeReason !== undefined) {
            result.unmoved.push({ ...location, reason: storeReason });
            continue;
          }
          // The secrets stored under the name are given only to the entry
          // bound to it, so a secret is stored only from that entry.
          if (!bound) {
            const reason = plan.kind === 'left' || plan.kind === 'copy' || plan.kind === 'replace'
              ? (plan.binding === undefined
                ? `this server is not bound to ${pairName(reads)}`
                : `the secrets stored under ${pairName(reads)} are bound to ${boundEntryName(plan.binding)}`)
              : bindingNotStoredReason(binder.lastError);
            result.unmoved.push({ ...location, reason });
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

        // The vault refuses such a name by throwing, which ended the run (#513).
        const problem = mcpNameProblem(server.name);
        if (problem !== undefined) {
          result.refusedName.push({
            client: config.client,
            ...mapLocation(config),
            server: server.name,
            reason: `the store refuses its name, since ${problem}`,
          });
          continue;
        }

        // A protected server in any config this run parsed that reads by this
        // name, a project-level one it leaves as it is included, is handed
        // every secret stored under it.
        const name = `${config.client}/${server.name}`;
        const holder = nameHolders.get(name) ?? readers.get(name)?.[0];
        if (holder !== undefined) {
          result.sharedName.push({
            client: config.client,
            ...mapLocation(config),
            server: server.name,
            protectedIn: mapLocation(holder),
          });
          continue;
        }
        // Once wrapped, the server is given every secret stored under its
        // name, and storing replaces a value stored under the same env name,
        // so its secrets are stored only under a name that holds none, or
        // only its own (see unwrappedStoredReason), and a value from a
        // project-level config only under one that holds none (see
        // projectStoredReason).
        const reads = { client: config.client, server: server.name };
        const stored = await vault.getServerSecrets(reads.client, reads.server);
        const storedReason = projectStoredReason(config, stored, reads) ?? unwrappedStoredReason(stored, classified.secrets, reads);
        if (storedReason !== undefined) {
          result.unmoved.push({ client: config.client, ...mapLocation(config), server: server.name, reason: storedReason });
          continue;
        }
        // A name whose secrets are bound to another entry is that entry's,
        // unless that entry is no longer in its config and this server is in
        // a config of the same scope (see orphanedBinding). A binding that
        // names this entry is its own: it is bound again in place.
        const found = await bindingOf(binder, reads);
        const existing = found !== undefined && isBoundEntry(found, config, server.name) ? undefined : found;
        if (existing !== undefined && !(orphanedBinding(binder, existing) && scopeOf(config) === existing.scope)) {
          result.sharedName.push({
            client: config.client,
            ...mapLocation(config),
            server: server.name,
            protectedIn: { filePath: existing.file, ...(existing.projectKey === undefined ? {} : { projectKey: existing.projectKey }) },
            boundTo: boundEntry(existing),
          });
          continue;
        }

        // The binding is stored before the secrets: a store that refuses it
        // leaves no secret stored without one.
        const id = newBindingId();
        try {
          await storeBindingOf(binder, reads, newBinding(binder, config, server.name, id, commandDigest(server.command, server.args)));
        } catch (err) {
          result.unmoved.push({ client: config.client, ...mapLocation(config), server: server.name, reason: bindingNotStoredReason(err) });
          continue;
        }
        nameHolders.set(name, config);
        if (existing !== undefined) {
          result.bound.push({ client: config.client, ...mapLocation(config), server: server.name, tookOver: boundEntry(existing) });
        }

        // Store secrets in encrypted vault
        await vault.storeServerSecrets(config.client, server.name, classified.secrets);
        serverSecrets[server.name] = classified.secrets;
        bindings[server.name] = id;

        result.secretsFound += secretCount;
        result.servers.push({
          client: config.client,
          server: server.name,
          secretKeys: Object.keys(classified.secrets),
        });
      }

      if (Object.keys(serverSecrets).length > 0 || Object.keys(storedEnvKeys).length > 0 || Object.keys(bindings).length > 0) {
        maps.push({ ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }), serverSecrets, storedEnvKeys, bindings });
      }
    }

    // Rewrite config file if any servers had secrets. A file in which a
    // server already runs through the wrapper keeps the backup an earlier run
    // wrote, where there is one: the file as it was before protect-mcp
    // changed it, which mcp-unprotect restores (#513).
    if (maps.length > 0) {
      const rewrittenBefore = fileConfigs.some((config) => config.servers.some((server) => server.alreadyProtected));
      const rewriteResult = rewriteServerMaps(
        filePath,
        fileConfigs[0].client,
        maps,
        options.wrapperPath,
        backupDir,
        options.backendType,
        { keepBackup: rewrittenBefore },
      );
      result.serversProtected += rewriteResult.serversRewritten;
    }
  }

  return result;
}

/**
 * The wrapper flags given in a protected server's args, each with the value
 * the wrapper reads for it: the args are read as the wrapper reads them, up
 * to `--`, and a flag given twice has its last value (see readWrapperArgv).
 */
function wrapperFlags(server: McpServerEntry): Map<string, string> {
  const read = readWrapperArgv(server.args);
  return new Map([...read.values].map(([flag, values]) => [flag, values[values.length - 1]]));
}

/**
 * The client and server name a protected server's wrapper reads its secrets
 * by: its `--client` and `--server` values, read from its args as the wrapper
 * reads them, or the config's client and the server's name where one is not
 * given.
 */
export function wrapperReads(client: string, server: McpServerEntry): { client: string; server: string } {
  const flags = wrapperFlags(server);
  return { client: flags.get('--client') ?? client, server: flags.get('--server') ?? server.name };
}

/** The name wrapperReads gives, as `client/server`. */
function protectedVaultName(client: string, server: McpServerEntry): string {
  const reads = wrapperReads(client, server);
  return `${reads.client}/${reads.server}`;
}

/**
 * The backend this run stores secrets in, the configured one a wrapper given
 * no --backend reads from, and whether this run's vault has a key. Only a run
 * given a home directory, as a test is, gives it one, so its `local` is the
 * encrypted file, and a test starts the wrapper with that key (--vault-key).
 * Without one, this run and a wrapper whose args name no --vault-dir or
 * --vault-key build one store for one backend (see storeName).
 */
interface WrapperStores {
  run: SelectableBackendType;
  configured: SelectableBackendType;
  keyed: boolean;
}

/**
 * The store a vault built for the backend `type` is, by the name of the
 * backend: `local` with a key is the encrypted file, and without one it is
 * what effectiveBackendName names, the platform keychain while no backend is
 * configured, where there is one. That keychain is the one `keychain` builds,
 * so `keychain` has its name where `local` upgrades to it. Two backends with
 * the same name here build one store. Names are compared, not stores built:
 * building the 1password backend runs `op account get`, which can open a
 * dialog (see isOnePasswordAvailable).
 */
function storeName(type: string, keyed: boolean): string {
  if (type === 'local') return keyed ? 'local' : effectiveBackendName('local');
  if (type === 'keychain') {
    const upgrade = effectiveBackendName('local');
    return upgrade === 'local' ? 'keychain' : upgrade;
  }
  return type;
}

/**
 * Why the secrets in the env of a server that runs through the wrapper are
 * left there, or undefined when they are stored. They are stored under the
 * name its wrapper reads by, so the vault has to take that name. A secret
 * stored under a name is handed to every protected server that reads by it,
 * so it is stored only when this server is the one server that does
 * (`readerCount` counts them). It is stored only where its wrapper reads it,
 * as far as this run can tell: the args name no --vault-dir or --vault-key,
 * and the backend its wrapper reads from, its --backend argument or the
 * configured backend when it gives none, builds the store this run stores in
 * (see storeName). A reason names the store this run stores in by its
 * storeName.
 */
function unmovedReason(
  client: string,
  server: McpServerEntry,
  readerCount: number,
  stores: WrapperStores,
): string | undefined {
  const refused = refusedNameReason(wrapperReads(client, server));
  if (refused !== undefined) return refused;
  if (readerCount > 1) {
    return `another protected server reads its secrets by the same name, ${listedName(protectedVaultName(client, server))}`;
  }
  return storeMismatchReason(server, stores);
}

/**
 * Why the store a protected server's wrapper reads from is not, as far as
 * this run can tell, the one this run stores in, or undefined when it is (see
 * unmovedReason). Neither a secret nor a binding is stored for a wrapper that
 * reads another store.
 */
function storeMismatchReason(server: McpServerEntry, stores: WrapperStores): string | undefined {
  const flags = wrapperFlags(server);
  if (flags.has('--vault-dir') || flags.has('--vault-key')) {
    return 'its args choose the store its wrapper reads from with --vault-dir or --vault-key';
  }
  const backend = flags.get('--backend');
  const runStore = storeName(stores.run, stores.keyed);
  const wrapperStore = storeName(backend ?? stores.configured, stores.keyed);
  if (wrapperStore === runStore) return undefined;
  return backend === undefined
    ? `its wrapper reads from the configured backend, ${wrapperStore}, and this run stores in ${runStore}`
    : `its --backend argument is ${quotedName(backend)}, and this run stores in ${runStore}`;
}

// ---------------------------------------------------------------------------
// Binding (see McpBinding)
// ---------------------------------------------------------------------------

/** What binding a server needs from this run: its store, what discovery found, and the bindings read so far. */
interface Binder {
  vault: McpVault;
  discovered: { configs: McpConfigFile[]; unparsed: UnparsedMcpConfig[] };
  /** The servers that run through the wrapper in the configs this run rewrites, by the name they read by. */
  rewrittenReaders: Map<string, Array<{ config: McpConfigFile; server: McpServerEntry }>>;
  stores: WrapperStores;
  backupDir: string;
  /** The binding of each pair read this run, by `client/server`, as this run leaves it. */
  bindings: Map<string, McpBinding | undefined>;
  /** The secretless-ai version this run is, for McpBinding.boundBy. */
  boundBy: string;
  /** Why the store refused the binding applyBinding last stored. */
  lastError?: unknown;
  /** The wrapper path and backend this run writes into a config it rewrites. */
  wrapperPath: string;
  backendType?: string;
}

/** What this run does for the binding of a server that runs through the wrapper (see bindWrapped). */
type BindingPlan =
  /** The pair is bound to this entry and its command: nothing is written. */
  | { kind: 'bound' }
  /** The pair is bound to this entry, in a home config, and its command changed: the binding takes its command now. */
  | { kind: 'rebind'; binding: McpBinding; digest: string }
  /** This entry is bound in place: a new binding, and its id in the entry's args. */
  | { kind: 'bind'; id: string; digest: string; tookOver?: McpBinding }
  /** This entry is not bound, with why. `binding` is the pair's binding, when one is stored. */
  | { kind: 'left'; reason: string; binding?: McpBinding }
  /** This entry carries the binding of the entry it names, at another place: a copy. Nothing is written. */
  | { kind: 'copy'; binding: McpBinding }
  /**
   * A copy of an entry bound in a home config, which is in its file: the
   * binding is replaced, and the copy is not written (see replaceBinding).
   */
  | { kind: 'replace'; binding: McpBinding; owner: { config: McpConfigFile; server: McpServerEntry } };

/**
 * Whether the pair a server that runs through the wrapper reads is bound to
 * it, and what this run does about that. Bound to this entry (its id, place
 * and command): nothing; its command changed, in a home config: bound again,
 * where a project-level entry is left. Bound to another entry: left, or, for
 * an entry carrying its id, reported as a copy, and the binding replaced where
 * that entry is bound in a home config and is in its file; when that entry is
 * no longer in its config, the one entry of its scope that reads the pair
 * takes it over.
 * No binding stored: bound in place when this is the one entry of the configs
 * this run rewrites that reads the pair, in a home config, or in the
 * project's .mcp.json when this run stores its secrets into an empty pair or
 * protect-mcp's backup of the file holds every secret stored under the pair.
 * `storesSecrets`: whether its env holds a secret this run may store.
 */
async function bindWrapped(
  binder: Binder,
  config: McpConfigFile,
  server: McpServerEntry,
  storesSecrets: boolean,
): Promise<BindingPlan> {
  const reads = wrapperReads(config.client, server);
  const notStored = refusedNameReason(reads) ?? storeMismatchReason(server, binder.stores);
  if (notStored !== undefined) return { kind: 'left', reason: notStored };
  const read = readWrapperArgv(server.args);
  if (read.child === undefined) return { kind: 'left', reason: 'its args give its wrapper no command to start after --' };
  const digest = commandDigest(read.child.command, read.child.args);
  const entryId = wrapperFlag(read, '--binding');
  const binding = await bindingOf(binder, reads);

  if (binding !== undefined) {
    const carriesId = isBindingId(entryId) && entryId === binding.id;
    const here = isBoundEntry(binding, config, server.name);
    if (carriesId && here) {
      if (binding.commandDigest === digest) return { kind: 'bound' };
      if (scopeOf(config) === 'home') return { kind: 'rebind', binding, digest };
      return { kind: 'left', reason: changedProjectCommandReason(), binding };
    }
    if (!here && orphanedBinding(binder, binding) && scopeOf(config) === binding.scope && soleReader(binder, reads)) {
      return placed(config, server, { kind: 'bind', id: newBindingId(), digest, tookOver: binding });
    }
    if (carriesId) return replacePlan(binder, binding) ?? { kind: 'copy', binding };
    if (here) return { kind: 'left', reason: otherIdReason(reads), binding };
    return { kind: 'left', reason: boundElsewhereReason(reads, binding), binding };
  }

  const others = (binder.rewrittenReaders.get(`${reads.client}/${reads.server}`) ?? []).filter((r) => r.server !== server);
  if (others.length > 0) return { kind: 'left', reason: otherReadersReason(reads, others) };
  if (scopeOf(config) === 'project') {
    // A project-level config comes with the repository it is in, so its
    // entry is bound only to secrets shown to be its own: ones this run
    // stores from its env, or ones protect-mcp's backup of the file holds.
    const stored = await binder.vault.getServerSecrets(reads.client, reads.server);
    const storesFromEnv = storesSecrets && Object.keys(stored).length === 0;
    if (!storesFromEnv && !backupHoldsSecrets(binder.backupDir, config.filePath, server.name, stored)) {
      return { kind: 'left', reason: notInBackupReason(reads) };
    }
  }
  return placed(config, server, { kind: 'bind', id: newBindingId(), digest });
}

/**
 * A plan that writes an id into an entry's args, when the args take it in
 * place (see withWrapperBinding), and otherwise one that leaves the entry.
 */
function placed(config: McpConfigFile, server: McpServerEntry, plan: Extract<BindingPlan, { kind: 'bind' }>): BindingPlan {
  const args = rawServerArgs(config, server.name);
  if (args === undefined || withWrapperBinding(args, plan.id) === undefined) {
    return { kind: 'left', reason: 'its args do not take a --binding before the -- that ends its wrapper\'s own args' };
  }
  return plan;
}

/** A server's args as the file holds them, when every one is a string. */
function rawServerArgs(config: McpConfigFile, serverName: string): string[] | undefined {
  let container: unknown = config.raw;
  if (config.projectKey !== undefined) {
    const projects = config.raw['projects'];
    container = projects && typeof projects === 'object' && Object.prototype.hasOwnProperty.call(projects, config.projectKey)
      ? (projects as Record<string, unknown>)[config.projectKey]
      : undefined;
  }
  if (!container || typeof container !== 'object' || Array.isArray(container)) return undefined;
  const key = serverMapKey(container as Record<string, unknown>);
  const servers = key === undefined ? undefined : (container as Record<string, unknown>)[key];
  if (!servers || typeof servers !== 'object' || !Object.prototype.hasOwnProperty.call(servers, serverName)) return undefined;
  const entry = (servers as Record<string, unknown>)[serverName];
  const args = entry && typeof entry === 'object' ? (entry as Record<string, unknown>)['args'] : undefined;
  return Array.isArray(args) && args.every((a): a is string => typeof a === 'string') ? args : undefined;
}

/**
 * Carry out a plan for a server that runs through the wrapper: store its
 * binding (bind, rebind) and note the id to write into its args (bind).
 * Returns whether the server is bound to its pair after it: false for a plan
 * that leaves it, and when the store refused the binding, with why in
 * binder.lastError.
 */
async function applyBinding(
  binder: Binder,
  plan: BindingPlan,
  config: McpConfigFile,
  server: McpServerEntry,
  bindings: Record<string, string>,
  result: ProtectResult,
): Promise<boolean> {
  if (plan.kind === 'bound') return true;
  if (plan.kind === 'left' || plan.kind === 'copy' || plan.kind === 'replace') return false;
  const reads = wrapperReads(config.client, server);
  const location = { client: config.client, ...mapLocation(config), server: server.name };
  try {
    if (plan.kind === 'rebind') {
      await storeBindingOf(binder, reads, {
        ...plan.binding,
        commandDigest: plan.digest,
        boundAt: new Date().toISOString(),
        boundBy: binder.boundBy,
      });
      result.rebound.push(location);
      return true;
    }
    await storeBindingOf(binder, reads, newBinding(binder, config, server.name, plan.id, plan.digest));
  } catch (err) {
    binder.lastError = err;
    return false;
  }
  bindings[server.name] = plan.id;
  result.bound.push({ ...location, ...(plan.tookOver === undefined ? {} : { tookOver: boundEntry(plan.tookOver) }) });
  return true;
}

/**
 * For a copy of an entry bound in a home config: the plan that replaces the
 * binding, where that entry is in its file as this run read it and its args
 * take an id in place. A project binding is left as it is: its copy is
 * reported, and the wrapper refuses it from a directory where it is visible.
 */
function replacePlan(binder: Binder, binding: McpBinding): BindingPlan | undefined {
  if (binding.scope !== 'home') return undefined;
  for (const config of binder.discovered.configs) {
    if (config.projectKey !== binding.projectKey || !sameFile(config.filePath, binding.file)) continue;
    const server = config.servers.find((s) => s.name === binding.server);
    if (server === undefined) continue;
    const args = rawServerArgs(config, server.name);
    if (args === undefined || withWrapperBinding(args, binding.id) === undefined) return undefined;
    return { kind: 'replace', binding, owner: { config, server } };
  }
  return undefined;
}

/**
 * Replace a home binding a copy of its entry carries: a new id is stored for
 * the pair, with the same entry and command, before it is written into the
 * bound entry's args, so the copy, which keeps the old id, no longer starts.
 * A store that refuses the new binding leaves the entry as it is; a file that
 * cannot be written gets the old binding stored back. Returns why it was not
 * replaced, or undefined.
 */
async function replaceBinding(
  binder: Binder,
  plan: Extract<BindingPlan, { kind: 'replace' }>,
  reads: { client: string; server: string },
): Promise<string | undefined> {
  const id = newBindingId();
  try {
    await storeBindingOf(binder, reads, { ...plan.binding, id, boundAt: new Date().toISOString(), boundBy: binder.boundBy });
  } catch (err) {
    return `the store refused the new binding (${firstLine(err)})`;
  }
  const { config, server } = plan.owner;
  try {
    rewriteServerMaps(
      config.filePath,
      config.client,
      [{ ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }), serverSecrets: {}, bindings: { [server.name]: id } }],
      binder.wrapperPath,
      binder.backupDir,
      binder.backendType,
      { keepBackup: true },
    );
  } catch (err) {
    try {
      await storeBindingOf(binder, reads, plan.binding);
    } catch {
      // The line this returns says the entry was not written.
    }
    return `${listedName(config.filePath)} could not be written (${firstLine(err)})`;
  }
  // Later in this run, the bound entry is read as its file now holds it.
  server.args = withWrapperBinding(server.args, id) ?? server.args;
  return undefined;
}

/** The first line of an error's message, as a line may show it. */
function firstLine(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return escapeForDisplay(message.split('\n')[0]);
}

/** A new binding of the pair a server reads, to that server's entry in `config`. */
function newBinding(binder: Binder, config: McpConfigFile, serverName: string, id: string, digest: string): McpBinding {
  return {
    schema: 1,
    id,
    scope: scopeOf(config),
    file: path.resolve(config.filePath),
    ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }),
    client: config.client,
    server: serverName,
    commandDigest: digest,
    boundAt: new Date().toISOString(),
    boundBy: binder.boundBy,
  };
}

/** The binding stored for a pair, read once per run and kept as this run stores it. */
async function bindingOf(binder: Binder, reads: { client: string; server: string }): Promise<McpBinding | undefined> {
  const name = `${reads.client}/${reads.server}`;
  if (!binder.bindings.has(name)) binder.bindings.set(name, await binder.vault.getBinding(reads.client, reads.server));
  return binder.bindings.get(name);
}

async function storeBindingOf(binder: Binder, reads: { client: string; server: string }, binding: McpBinding): Promise<void> {
  await binder.vault.storeBinding(reads.client, reads.server, binding);
  binder.bindings.set(`${reads.client}/${reads.server}`, binding);
}

/** 'home' for a config in the home directory, 'project' for one in the project directory. */
function scopeOf(config: { projectPath?: string }): 'home' | 'project' {
  return config.projectPath === undefined ? 'home' : 'project';
}

/** The entry a binding names. */
function boundEntry(binding: McpBinding): McpBoundEntry {
  return {
    server: binding.server,
    file: binding.file,
    ...(binding.projectKey === undefined ? {} : { projectKey: binding.projectKey }),
  };
}

/** Whether a binding names this server entry: its file, its ~/.claude.json project key and its name. */
export function isBoundEntry(binding: McpBinding, config: McpServerMapLocation, serverName: string): boolean {
  return binding.server === serverName && binding.projectKey === config.projectKey && sameFile(binding.file, config.filePath);
}

/** Whether two paths reach one file. */
function sameFile(a: string, b: string): boolean {
  if (path.resolve(a) === path.resolve(b)) return true;
  try {
    return fs.realpathSync(a) === fs.realpathSync(b);
  } catch {
    return false;
  }
}

/** Whether one server in the configs this run rewrites runs through the wrapper reading this pair. */
function soleReader(binder: Binder, reads: { client: string; server: string }): boolean {
  return (binder.rewrittenReaders.get(`${reads.client}/${reads.server}`) ?? []).length === 1;
}

/**
 * Whether the entry a binding names is no longer in its config: its file is
 * one this run read, and the server map there holds no server of that name.
 * A file this run did not read, one in another project directory or one that
 * could not be parsed, may still hold it.
 */
function orphanedBinding(binder: Binder, binding: McpBinding): boolean {
  const inFile = (config: { filePath: string; projectKey?: string }) => sameFile(config.filePath, binding.file);
  if (binder.discovered.unparsed.some((u) => inFile(u) && (u.projectKey === undefined || u.projectKey === binding.projectKey))) {
    return false;
  }
  const fileConfigs = binder.discovered.configs.filter(inFile);
  if (fileConfigs.length === 0) return false;
  const map = fileConfigs.find((config) => config.projectKey === binding.projectKey);
  if (map === undefined) return true;
  return !map.servers.some((s) => s.name === binding.server) && !map.unchecked.some((s) => s.name === binding.server);
}

/**
 * Whether protect-mcp's backup of a config file, the file as it was before
 * protect-mcp first changed it, holds a server of this name whose env holds
 * every secret in `stored` with the same value.
 */
function backupHoldsSecrets(backupDir: string, filePath: string, serverName: string, stored: Record<string, string>): boolean {
  const content = readConfigBackup(filePath, backupDir);
  if (content === undefined) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return false;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
  const key = serverMapKey(parsed as Record<string, unknown>);
  const servers = key === undefined ? undefined : (parsed as Record<string, unknown>)[key];
  if (!servers || typeof servers !== 'object' || !Object.prototype.hasOwnProperty.call(servers, serverName)) return false;
  const entry = (servers as Record<string, unknown>)[serverName];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const env = (entry as Record<string, unknown>)['env'];
  const has = (name: string) =>
    !!env && typeof env === 'object' && Object.prototype.hasOwnProperty.call(env, name) && (env as Record<string, unknown>)[name] === stored[name];
  return Object.keys(stored).every(has);
}

/** `<client>/<server>`, as today's lists write a pair. */
function pairName(reads: { client: string; server: string }): string {
  return listedName(`${reads.client}/${reads.server}`);
}

/** The end of a reason whose fix is to store the server's secrets from its env again. */
const STORE_AGAIN = 'put the server\'s values in its env, and run `npx secretless-ai protect-mcp`.';

function changedProjectCommandReason(): string {
  return 'its command or arguments changed since it was bound, and a project-level entry is bound again only when protect-mcp stores its values. '
    + `If you made the change, ${STORE_AGAIN}`;
}

function otherReadersReason(
  reads: { client: string; server: string },
  others: Array<{ config: McpConfigFile; server: McpServerEntry }>,
): string {
  const entries = others.map(({ config, server }) =>
    boundEntryName({ server: server.name, file: config.filePath, ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }) }));
  return `${pairName(reads)} is also read by ${entries.join('; ')}, and the secrets stored under a name are bound to one entry only. `
    + 'Keep one of these entries, remove the others, and run `npx secretless-ai protect-mcp`; to run another as well, add it again under a new name with its values.';
}

function notInBackupReason(reads: { client: string; server: string }): string {
  return `the secrets stored under ${pairName(reads)} are not in protect-mcp's backup of this file, and a project-level entry is bound only to values protect-mcp stores from its file. `
    + `If this entry is yours, ${STORE_AGAIN}`;
}

function boundElsewhereReason(reads: { client: string; server: string }, binding: McpBinding): string {
  const gone = fs.existsSync(binding.file) ? '' : ` ${listedName(binding.file)} no longer exists.`;
  return `the secrets stored under ${pairName(reads)} are bound to ${boundEntryName(binding)}. `
    + `To run this server as well, add it again under a new name with its values and run \`npx secretless-ai protect-mcp\`.${gone}`;
}

function otherIdReason(reads: { client: string; server: string }): string {
  return `its binding does not match the one stored for ${pairName(reads)}. If this entry is yours, ${STORE_AGAIN}`;
}

/** Why a server's secrets were not stored, or it was not bound: the store refused its binding. */
function bindingNotStoredReason(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return `the binding could not be stored (${escapeForDisplay(message.split('\n')[0])}); run \`npx secretless-ai protect-mcp\` again once the store accepts writes`;
}

/**
 * Why the vault refuses the client or server name a protected server's
 * wrapper reads its secrets by, or undefined when it takes both.
 */
function refusedNameReason(reads: { client: string; server: string }): string | undefined {
  for (const [label, name] of [['client', reads.client], ['server', reads.server]] as const) {
    const problem = mcpNameProblem(name);
    if (problem !== undefined) {
      return `its wrapper reads its secrets by the ${label} name ${quotedName(name)}, which the store refuses, since ${problem}`;
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

/**
 * Why the secrets in the env of a server in a project-level config, the
 * project's .mcp.json included, are left there, or undefined when they are
 * stored. Such a value is stored only under a name that holds no stored
 * secret, `stored` being the secrets stored under `reads`: it never adds to or
 * replaces them. The reason names the env names stored there, never a value.
 */
function projectStoredReason(
  config: McpServerMapLocation,
  stored: Record<string, string>,
  reads: { client: string; server: string },
): string | undefined {
  const storedKeys = Object.keys(stored).sort();
  if (config.projectPath === undefined || storedKeys.length === 0) return undefined;
  return `${storedUnder(storedKeys, reads)}, and a value from a project-level config is stored only under a name that holds no stored secret`;
}

/**
 * Why the secrets in the env of a server that does not yet run through the
 * wrapper are left there, or undefined when they are stored. `stored` is what
 * is stored under `reads`, the name they would be stored under. They are
 * stored only when each env name stored there is one of the server's
 * `secrets` with the same value: storing would replace a stored value, and
 * the wrapper would give the server a stored secret it does not have. The
 * reason names each env name stored there that is not the server's own,
 * never a value.
 */
function unwrappedStoredReason(
  stored: Record<string, string>,
  secrets: Record<string, string>,
  reads: { client: string; server: string },
): string | undefined {
  const storedKeys = Object.keys(stored).sort();
  const otherValue = storedKeys.filter((key) => Object.prototype.hasOwnProperty.call(secrets, key) && secrets[key] !== stored[key]);
  const notInEnv = storedKeys.filter((key) => !Object.prototype.hasOwnProperty.call(secrets, key));
  const parts: string[] = [];
  if (otherValue.length > 0) {
    parts.push(`${storedUnder(otherValue, reads)} with ${otherValue.length === 1 ? 'another value' : 'other values'}`);
  }
  if (notInEnv.length > 0) {
    const notIn = notInEnv.length === 1 ? 'is not in its env' : 'are not in its env';
    parts.push(otherValue.length > 0
      ? `${notInEnv.map(listedName).join(', ')} ${notInEnv.length === 1 ? 'is' : 'are'} stored there and ${notIn}`
      : `${storedUnder(notInEnv, reads)} and ${notIn}`);
  }
  return parts.length === 0 ? undefined : parts.join(', and ');
}

/** "<names> is stored under <client/server>", or "are" for more than one name. */
function storedUnder(envKeys: string[], reads: { client: string; server: string }): string {
  const names = envKeys.map(listedName).join(', ');
  return `${names} ${envKeys.length === 1 ? 'is' : 'are'} stored under ${listedName(`${reads.client}/${reads.server}`)}`;
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
