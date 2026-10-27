/**
 * MCP protection orchestrator — discover → classify → encrypt → rewrite.
 *
 * Ties together all MCP protection modules into a single function that
 * scans all MCP client configs, identifies plaintext secrets, encrypts
 * them into the vault, and rewrites configs to use the secretless-mcp wrapper.
 */

import * as fs from 'fs';
import * as path from 'path';
import { checkLaunchPlace, discoverMcpConfigsDetailed, rewrittenByProtectMcp, serverMapKey } from './discover';
import type { McpConfigDiscovery, McpConfigFile, McpServerEntry, UncheckedMcpServer, UnparsedMcpConfig } from './discover';
import { classifyEnvVars } from './classify';
import { BindingWriteRefusedError, McpVault, boundEntryName, commandDigest, expectBinding, isBindingId, isPerMachineStore, mcpNameProblem, newBindingId, ownsBinding } from './vault';
import type { McpBinding } from './vault';
import { BindingHomeIdError, ensureBindingHomeId, readBindingHomeId } from './binding-home-id';
import { moveConfigBackup, readConfigBackup, rewriteServerMaps, type ServerMapSecrets } from './rewrite';
import { compareVersions, isVersion, packageVersionAbove, readWrapperVersion } from './wrapper-version';
import { screenMcpEnvVars } from '../nanomind';
import { readWrapperArgv, withWrapperBinding, wrapperFlag } from '../argv';
import { resolveBackendType } from '../backends/config';
import type { SelectableBackendType } from '../backends/config';
import { effectiveBackendName } from '../backends/factory';
import { listedName, quotedName } from '../secret-value';
import { escapeForDisplay } from '../display-safe';
import { printedCommand } from '../printed-command';
import { VERSION } from '../commands/utils';

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
  /** When another secretless home stored that binding (see ownsBinding): why the server was left (ANOTHER_MACHINE_REASON). */
  reason?: string;
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
  /**
   * For a .mcp.json entry bound again after its project directory moved (see
   * movedEntry): the directory it was bound in. Its command and arguments are
   * the ones it was bound with: a moved entry whose command or arguments
   * changed is left.
   */
  movedFrom?: { directory: string };
}

/**
 * A bound server in a home config bound again this run: its command or
 * arguments changed since it was bound, and the binding takes the command it
 * has now; or, with `outOfDate`, it is at its binding's place and carried no
 * id or another one, and its binding's id is written into it, after the
 * binding takes its command where that changed (`commandChanged`).
 */
export interface ReboundMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
  outOfDate?: true;
  commandChanged?: true;
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
  /** A sentence on that entry's file when it is not present on this machine (see boundFileClause). */
  boundFile?: string;
  /** protect-mcp replaced that home binding with a new id (see replaceBinding): this entry no longer starts. */
  replaced?: true;
  /** Why protect-mcp could not replace that home binding, which is as it was: this entry still receives its secrets. */
  replaceError?: string;
  /** protect-mcp could not replace that home binding, nor store the old one back (see StoreBackFailure). */
  storeBackFailed?: StoreBackFailure;
}

/**
 * A replacement that stored the new binding, could not write its id into the
 * bound entry's file, and could not store the old binding back either: the
 * store holds a binding no entry carries, so neither the bound entry nor a
 * copy of it starts until protect-mcp runs again where that file can be
 * written. The file, and the write's error as a line may show it (firstLine).
 */
export interface StoreBackFailure {
  file: string;
  error: string;
}

/**
 * A project-level config, in the directory protect-mcp runs in or in one
 * above it, in which the check the wrapper runs before it starts an entry
 * from that directory (checkLaunchPlace) found the id of a home binding whose
 * entry is in its file, with what protect-mcp did: the binding replaced, or
 * why not. With `unchecked`, the check could not read the file for the id,
 * and nothing was replaced. The file is read for the id only: no entry in it
 * is parsed, and nothing is written into it.
 */
export interface BindingCopyFile {
  /** The file, as the check names it. */
  file: string;
  /** The entry the binding names. */
  boundTo: McpBoundEntry;
  /** Why the check could not read the file for the id, as it says it (McpPlaceVerdict). */
  unchecked?: string;
  /** protect-mcp replaced the binding with a new id (see replaceBinding): a copy of it no longer starts. */
  replaced?: true;
  /** Why protect-mcp could not replace the binding, which is as it was. */
  replaceError?: string;
  /** protect-mcp could not replace the binding, nor store the old one back (see StoreBackFailure). */
  storeBackFailed?: StoreBackFailure;
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

/**
 * A server that ran through another build's wrapper, re-pointed this run to
 * the wrapper of the build that runs protect-mcp (see repointsToThisBuild):
 * only its command changed.
 */
export interface RepointedMcpServer extends McpServerMapLocation {
  client: string;
  /** Server name as written in the config */
  server: string;
}

/** A project-level config protect-mcp leaves as it is (see rewrittenByProtectMcp). */
export interface ProjectLevelMcpConfig {
  client: string;
  filePath: string;
  /** The path from the project directory. */
  projectPath: string;
  /** This run read it for the id of a home binding (see BindingCopyFile), and wrote nothing into it. */
  checkedForCopy?: true;
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
  /** Project-level configs found from this directory to hold a home binding's id, or not readable for it (see BindingCopyFile). */
  copyFiles: BindingCopyFile[];
  /** Servers that ran through another build's wrapper, re-pointed to this build's (see RepointedMcpServer). */
  repointed: RepointedMcpServer[];
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
 *    already runs through it keeps its args, and its command unless that
 *    names another build's wrapper, which is re-pointed to this build's (see
 *    repointsToThisBuild); the secrets stored for it are removed from its
 *    env. A file with a server that ran
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
/** Where a protect-mcp run keeps its store and its backups, and the key its store is built with. */
interface ProtectPaths {
  /** The secretless home: the directory of the store, the backups and the home's id (see binding-home-id.ts). */
  dataDir: string;
  vaultDir: string;
  backupDir: string;
  vaultKey?: string;
}

function protectPaths(options: ProtectOptions): ProtectPaths {
  const home = options.homeDir;
  if (home && !path.isAbsolute(home)) {
    throw new Error(`homeDir must be an absolute path, got: "${home}"`);
  }
  const dataDir = options.dataDir ?? path.join(
    home ?? (process.env.HOME ?? process.env.USERPROFILE ?? '/tmp'),
    '.secretless-ai',
  );

  // Derive a deterministic vault key from homeDir when provided (testing),
  // otherwise give none, as the wrapper gives none when its args name no
  // --vault-dir or --vault-key: both then build one store for one backend,
  // and for `local` it is the platform keychain while no backend is
  // configured, where there is one, and otherwise LocalBackend's encrypted
  // file under its default machine-based key.
  const vaultKey = home
    ? `${home}-secretless-mcp-${process.env.USER ?? 'default'}`
    : undefined;

  return {
    dataDir,
    vaultDir: path.join(dataDir, 'mcp-vault'),
    backupDir: path.join(dataDir, 'mcp-backups'),
    ...(vaultKey === undefined ? {} : { vaultKey }),
  };
}

/** The store a protect-mcp run stores in. */
function protectVault(options: ProtectOptions, paths: ProtectPaths): McpVault {
  return new McpVault({
    storeDir: paths.vaultDir,
    ...(paths.vaultKey ? { key: paths.vaultKey } : {}),
    ...(options.backendType ? { backendType: options.backendType } : {}),
  });
}

/**
 * What a protect-mcp run reads before it writes anything, from what discovery
 * found: the configs it rewrites, the names protected servers read by, the
 * stores, and the binder its plans are made with. protectMcp and
 * planMcpBindings both start from it.
 */
interface ProtectSetup {
  configs: McpConfigFile[];
  unparsed: UnparsedMcpConfig[];
  projectLevel: ProjectLevelMcpConfig[];
  nameHolders: Map<string, McpConfigFile>;
  readers: Map<string, McpConfigFile[]>;
  stores: WrapperStores;
  /** The version of this build: a binding records it, and an entry on a wrapper that reads a lower one is re-pointed. */
  version: string | null;
  binder: Binder;
}

function protectSetup(
  options: ProtectOptions,
  discovered: McpConfigDiscovery,
  vault: Binder['vault'],
  paths: ProtectPaths,
): ProtectSetup {
  // A project-level config other than .mcp.json is left as it is and
  // returned by name (see rewrittenByProtectMcp).
  const configs = discovered.configs.filter(rewrittenByProtectMcp);
  const unparsed = discovered.unparsed.filter(rewrittenByProtectMcp);
  const projectLevel: ProjectLevelMcpConfig[] = [];
  for (const { client, filePath, projectPath } of [...discovered.configs, ...discovered.unparsed]) {
    if (projectPath !== undefined && !rewrittenByProtectMcp({ projectPath })) {
      projectLevel.push({ client, filePath, projectPath });
    }
  }

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
    keyed: paths.vaultKey !== undefined,
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
  const version = packageVersionAbove(__dirname);
  // The secretless home's id is read here and never created: protect-mcp
  // creates it before the first binding it stores (see storeBindingOf).
  const homeId = readBindingHomeId(paths.dataDir);
  const binder: Binder = {
    vault,
    discovered,
    rewrittenReaders,
    stores,
    backupDir: paths.backupDir,
    home: {
      dir: paths.dataDir,
      ...(homeId.state === 'present' ? { id: homeId.id } : {}),
      ...(homeId.state === 'unusable' ? { unusable: homeId.error } : {}),
    },
    bindings: new Map(),
    boundBy: version ?? 'unknown',
    wrapperPath: options.wrapperPath,
    backendType: options.backendType,
  };
  return { configs, unparsed, projectLevel, nameHolders, readers, stores, version, binder };
}

/**
 * Why the secrets in the env of a server that runs through the wrapper,
 * `secrets`, are left there, or undefined when this run stores them (or
 * there are none). They are stored under the name its wrapper reads by,
 * only where unmovedReason gives no reason, and only where storing neither
 * adds a project-level value to stored secrets (projectStoredReason) nor
 * replaces a stored value with another one (storedValueReason).
 */
async function wrappedStoreReason(
  setup: ProtectSetup,
  config: McpConfigFile,
  server: McpServerEntry,
  secrets: Record<string, string>,
): Promise<string | undefined> {
  const secretKeys = Object.keys(secrets);
  if (secretKeys.length === 0) return undefined;
  const readerCount = setup.readers.get(protectedVaultName(config.client, server))?.length ?? 0;
  const reason = unmovedReason(config.client, server, readerCount, setup.stores);
  if (reason !== undefined) return reason;
  // A value from a project-level config is stored only under a name that
  // holds no stored secret, so it neither adds to nor replaces the secrets
  // stored under that name.
  const reads = wrapperReads(config.client, server);
  const stored = await setup.binder.vault.getServerSecrets(reads.client, reads.server);
  const projectReason = projectStoredReason(config, stored, reads);
  if (projectReason !== undefined) return projectReason;
  // The wrapper gives the server a value stored under an env name in place
  // of the one in its env, so storing another value under that name would
  // change the credential the server is given.
  const differing = secretKeys.filter((key) =>
    Object.prototype.hasOwnProperty.call(stored, key) && stored[key] !== secrets[key]);
  return differing.length > 0 ? storedValueReason(differing, reads) : undefined;
}

export async function protectMcp(options: ProtectOptions): Promise<ProtectResult> {
  const paths = protectPaths(options);
  const vault = protectVault(options, paths);
  const { backupDir } = paths;

  // 1. Discover all MCP configs.
  const discovered = discoverMcpConfigsDetailed(options.homeDir, options.projectDir);
  const setup = protectSetup(options, discovered, vault, paths);
  const { configs, unparsed, projectLevel, nameHolders, readers, version, binder } = setup;

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
    copyFiles: [],
    repointed: [],
    projectLevel,
  };
  // The pairs whose binding this run replaced, or tried to: once per pair in a run.
  const replacedPairs = new Set<string>();

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
      // The servers on another build's wrapper, re-pointed in this file's write.
      const repoint: string[] = [];

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
          // On another build's wrapper: re-pointed to this build's in the
          // same write as its binding, whatever this run does about that.
          if (repointsToThisBuild(server.command, options.wrapperPath, version)) repoint.push(server.name);
          // Whether a secret in its env may be stored, and why not.
          const storeReason = await wrappedStoreReason(setup, config, server, classified.secrets);

          // The binding is stored before any secret (see applyBinding), and
          // whether or not a secret in its env is stored.
          const plan = await bindWrapped(binder, config, server, secretKeys.length > 0 && storeReason === undefined);
          if (plan.kind === 'left') result.unbound.push({ ...location, reason: plan.reason });
          if (plan.kind === 'copy') {
            const boundFile = boundFileClause(binder, plan.binding);
            result.copies.push({ ...location, boundTo: boundEntry(plan.binding), ...(boundFile === '' ? {} : { boundFile }) });
          }
          if (plan.kind === 'replace') {
            replacedPairs.add(`${reads.client}/${reads.server}`);
            const outcome = await replaceBinding(binder, plan, reads);
            result.copies.push({ ...location, boundTo: boundEntry(plan.binding), ...replaceFields(outcome) });
          }
          const bound = await applyBinding(binder, plan, config, server, bindings, result);
          if (!bound && (plan.kind === 'bind' || plan.kind === 'rebind' || plan.kind === 'stale')) {
            result.unbound.push({ ...location, reason: binder.lastReason ?? bindingNotStoredReason('unknown error') });
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
              : (binder.lastReason ?? bindingNotStoredReason('unknown error'));
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
        // names this entry is its own, where this secretless home stored it
        // (see ownsBinding): it is bound again in place. One another home
        // stored is that home's, wherever it points, and is left as it is.
        const found = await bindingOf(binder, reads);
        const own = found !== undefined && isBoundEntry(found, config, server.name) && ownedHere(binder, found);
        const existing = own ? undefined : found;
        if (existing !== undefined && !(orphanedBinding(binder, existing) && scopeOf(config) === existing.scope)) {
          result.sharedName.push({
            client: config.client,
            ...mapLocation(config),
            server: server.name,
            protectedIn: { filePath: existing.file, ...(existing.projectKey === undefined ? {} : { projectKey: existing.projectKey }) },
            boundTo: boundEntry(existing),
            ...(ownedHere(binder, existing) ? {} : { reason: ANOTHER_MACHINE_REASON(reads) }),
          });
          continue;
        }

        // The binding is stored before the secrets: a store that refuses it
        // leaves no secret stored without one.
        const id = newBindingId();
        const digest = commandDigest(server.command, server.args);
        try {
          await storeBindingOf(binder, reads, newBinding(binder, config, server.name, id, digest), found);
        } catch (err) {
          const reason = notStoredReason(err, bindingValues({ id, commandDigest: digest }, found));
          result.unmoved.push({ client: config.client, ...mapLocation(config), server: server.name, reason });
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

      if (
        Object.keys(serverSecrets).length > 0 || Object.keys(storedEnvKeys).length > 0
        || Object.keys(bindings).length > 0 || repoint.length > 0
      ) {
        maps.push({ ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }), serverSecrets, storedEnvKeys, bindings, repoint });
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
      for (const moved of rewriteResult.repointed ?? []) {
        const config = fileConfigs.find((c) => c.projectKey === moved.projectKey);
        if (config !== undefined) result.repointed.push({ client: config.client, ...mapLocation(config), server: moved.server });
      }
    }
  }

  // 3. A home binding the wrapper's own check finds in a copy from this
  // directory, in a project-level config this run does not rewrite or in one
  // above it, is replaced as a copy in a config it rewrites is (see
  // replaceFoundBindings).
  const checked = new Set<string>();
  await replaceFoundBindings(
    binder,
    configs,
    { startDir: options.projectDir ?? process.cwd(), ...(options.homeDir === undefined ? {} : { home: options.homeDir }) },
    replacedPairs,
    result,
    checked,
  );
  for (const config of projectLevel) {
    if ([...checked].some((file) => sameFile(file, config.filePath))) config.checkedForCopy = true;
  }

  return result;
}

/**
 * Copies found by the wrapper's own check. For each home binding whose entry is
 * in its file as this run read it, the check the wrapper runs before it starts
 * that entry from the directory this run is in: checkLaunchPlace, the function
 * mcp-status runs through checkStart, with that directory as the start. A
 * project-level config that holds the binding's id there, in that directory or
 * in one above it, has the binding replaced (replaceBinding), as a copy in a
 * config this run rewrites has it: once per pair in a run, however many
 * configs hold it, and not for a pair this run already replaced or tried to.
 * A config the check could not read for the id replaces nothing and is named.
 * These configs are read for the id only, as the check reads them: no entry in
 * them is parsed and nothing is written into them, and only the record and
 * the bound entry change. `checked` gets each config the check read.
 */
async function replaceFoundBindings(
  binder: Binder,
  configs: McpConfigFile[],
  place: { startDir: string; home?: string },
  replaced: Set<string>,
  result: ProtectResult,
  checked: Set<string>,
): Promise<void> {
  for (const config of configs) {
    if (scopeOf(config) !== 'home') continue;
    for (const server of config.servers) {
      if (!server.alreadyProtected) continue;
      // As bindWrapped reads it: a pair the store refuses, or one its wrapper
      // reads from another store, is not this run's to replace.
      const reads = wrapperReads(config.client, server);
      if (refusedNameReason(reads) !== undefined || storeMismatchReason(server, binder.stores) !== undefined) continue;
      const pair = `${reads.client}/${reads.server}`;
      if (replaced.has(pair)) continue;
      const binding = await bindingOf(binder, reads);
      if (binding === undefined || binding.scope !== 'home' || !isBoundEntry(binding, config, server.name)) continue;
      const plan = replacePlan(binder, binding);
      if (plan === undefined || plan.kind !== 'replace') continue;
      replaced.add(pair);
      const verdict = checkLaunchPlace(binding, { ...place, onChecked: (file) => checked.add(file) });
      if (verdict.refused === 'copy-found') {
        const outcome = await replaceBinding(binder, plan, reads);
        result.copyFiles.push({ file: verdict.file, boundTo: boundEntry(binding), ...replaceFields(outcome) });
      } else if (verdict.refused === 'copy-unchecked') {
        result.copyFiles.push({ file: verdict.file, boundTo: boundEntry(binding), unchecked: verdict.why });
      }
    }
  }
}

/**
 * What protect-mcp does for the binding of a server that runs through the
 * wrapper, as mcp-status names it under the server's line: nothing (`bound`),
 * bind it, bind it again with its command (`rebind`), write its binding's id
 * into it again (`stale`), leave it with why, report it as a copy of the
 * entry it names, or replace that entry's binding. Names and places only:
 * never an id, a digest or a value.
 */
export type McpBindingFix =
  | { kind: 'bound' }
  | { kind: 'bind' }
  | { kind: 'rebind' }
  | { kind: 'stale' }
  | { kind: 'left'; reason: string }
  | { kind: 'copy'; boundTo: McpBoundEntry }
  | { kind: 'replace'; boundTo: McpBoundEntry };

/**
 * protect-mcp's plan for the binding of each server that runs through the
 * wrapper in the configs it rewrites, made as protectMcp makes it (its
 * setup, its store reasons and bindWrapped, in its order) and carried out by
 * nothing: the store and the backups are read, and nothing is stored or
 * written. The plans are made on a copy of what discovery found, with what
 * an earlier plan of the run changes there as protect-mcp leaves it (see
 * planned). Where protect-mcp's store would be a local store whose directory
 * does not exist, none is built, since building one writes into its
 * directory: the plans are made against a store that holds nothing, as
 * protect-mcp finds it. Keyed by the entries of `discovered`.
 */
export async function planMcpBindings(
  options: ProtectOptions,
  discovered: McpConfigDiscovery,
): Promise<Map<McpServerEntry, McpBindingFix>> {
  const fixes = new Map<McpServerEntry, McpBindingFix>();
  const wrapped = (config: McpConfigFile) => rewrittenByProtectMcp(config) && config.servers.some((server) => server.alreadyProtected);
  if (!discovered.configs.some(wrapped)) return fixes;
  const paths = protectPaths(options);
  const vault = resolveBackendType(options.backendType) === 'local' && !fs.existsSync(paths.vaultDir)
    ? emptyStore(storeName('local', paths.vaultKey !== undefined))
    : protectVault(options, paths);
  const run = structuredClone(discovered);
  const original = new Map<McpServerEntry, McpServerEntry>();
  run.configs.forEach((config, i) => config.servers.forEach((server, j) => original.set(server, discovered.configs[i].servers[j])));
  const setup = protectSetup(options, run, vault, paths);
  for (const [, fileConfigs] of configsByFile(setup.configs)) {
    for (const config of fileConfigs) {
      for (const server of config.servers) {
        if (!server.alreadyProtected) continue;
        const secrets = classifyEnvVars(server.env).secrets;
        const storeReason = await wrappedStoreReason(setup, config, server, secrets);
        const plan = unstoredPlan(
          setup.binder,
          await bindWrapped(setup.binder, config, server, Object.keys(secrets).length > 0 && storeReason === undefined),
        );
        planned(setup.binder, config, server, plan);
        const entry = original.get(server);
        if (entry !== undefined) fixes.set(entry, bindingFix(plan));
      }
    }
  }
  return fixes;
}

/**
 * A plan as protect-mcp carries it out while the secretless home's id file
 * cannot be used: it stores no binding (see storeBindingOf), so a plan that
 * would store one leaves the entry with why, and a replacement leaves the
 * copy reported. Any other plan, and every plan while the file can be used
 * or is absent, is as it is.
 */
function unstoredPlan(binder: Binder, plan: BindingPlan): BindingPlan {
  const unusable = binder.home.unusable;
  if (unusable === undefined) return plan;
  if (plan.kind === 'replace') return { kind: 'copy', binding: plan.binding };
  const stores = plan.kind === 'bind' || plan.kind === 'rebind'
    || (plan.kind === 'stale' && plan.binding.commandDigest !== plan.digest);
  return stores ? { kind: 'left', reason: HOME_ID_UNUSABLE(unusable) } : plan;
}

/**
 * What a plan changes in the run when protect-mcp carries it out, made in
 * memory only, so the plans after it are made as protect-mcp makes them: the
 * binding a bind, rebind or stale plan stores for the pair, and for a
 * replaced binding the new id, stored for the pair and written into the
 * bound entry's args (see applyBinding and replaceBinding).
 */
function planned(binder: Binder, config: McpConfigFile, server: McpServerEntry, plan: BindingPlan): void {
  const reads = wrapperReads(config.client, server);
  const pair = `${reads.client}/${reads.server}`;
  if (plan.kind === 'bind') binder.bindings.set(pair, { ...newBinding(binder, config, server.name, plan.id, plan.digest), boundOn: planHomeId(binder) });
  if (plan.kind === 'rebind' || plan.kind === 'stale') {
    const stores = plan.kind === 'rebind' || plan.binding.commandDigest !== plan.digest;
    binder.bindings.set(pair, stores ? { ...plan.binding, commandDigest: plan.digest, boundOn: planHomeId(binder) } : plan.binding);
  }
  if (plan.kind === 'replace') {
    const id = newBindingId();
    binder.bindings.set(pair, { ...plan.binding, id, boundOn: planHomeId(binder) });
    plan.owner.server.args = withWrapperBinding(plan.owner.server.args, id) ?? plan.owner.server.args;
  }
}

/**
 * The id a binding a plan stores carries (see planned): this secretless
 * home's, or, where its file is absent, one held in memory only, as
 * protect-mcp creates the file before the first binding it stores. A plan
 * never creates the file.
 */
function planHomeId(binder: Binder): string {
  return (binder.home.id ??= newBindingId());
}

/** A plan as mcp-status names it: its kind, and the reason or the entry it names. */
function bindingFix(plan: BindingPlan): McpBindingFix {
  switch (plan.kind) {
    case 'bound':
    case 'bind':
    case 'rebind':
    case 'stale':
      return { kind: plan.kind };
    case 'left':
      return { kind: 'left', reason: plan.reason };
    case 'copy':
    case 'replace':
      return { kind: plan.kind, boundTo: boundEntry(plan.binding) };
  }
}

/**
 * A store that holds nothing, for plans made where protect-mcp's local store
 * does not exist yet. A plan stores nothing, so nothing writes to it.
 */
function emptyStore(backendName: string): Binder['vault'] {
  return {
    backendName,
    getBinding: async () => undefined,
    getServerSecrets: async () => ({}),
    storeBinding: async () => {
      throw new Error('a plan stores nothing');
    },
  };
}

/**
 * Which wrapper the command of a server that runs through one names, as
 * protect-mcp's re-point and mcp-status both read it: `this` when it is this
 * build's wrapper file, `wrapperPath`, or its real path is; `version` with the
 * version the wrapper it names reads, as that wrapper reads its own
 * (readWrapperVersion), from the directory of the real path; or `unread`. A
 * bare or relative command is never this build's file, since its client
 * resolves it, and neither is a path that no longer exists: both are
 * `unread`, as is a wrapper that reads no version.
 */
export type WrapperBuild = { build: 'this' } | { build: 'version'; version: string } | { build: 'unread' };

export function wrapperBuild(command: string, wrapperPath: string): WrapperBuild {
  if (command === wrapperPath) return { build: 'this' };
  if (!path.isAbsolute(command)) return { build: 'unread' };
  let real: string;
  try {
    real = fs.realpathSync(command);
  } catch {
    return { build: 'unread' };
  }
  if (sameFile(real, wrapperPath)) return { build: 'this' };
  const version = readWrapperVersion(path.dirname(real));
  return isVersion(version) ? { build: 'version', version } : { build: 'unread' };
}

/**
 * Whether protect-mcp re-points a server that runs through a wrapper to this
 * build's, `wrapperPath`: its command is not this build's wrapper file, and
 * the wrapper it names does not read a version at or above this build's,
 * `version` (see wrapperBuild). Versions are compared by semver: an equal
 * version is this build's checks at another install path, and a higher one
 * is never replaced. A wrapper with no version read is re-pointed; where this
 * build reads none, a wrapper that reads one is left.
 */
export function repointsToThisBuild(command: string, wrapperPath: string, version: string | null): boolean {
  const theirs = wrapperBuild(command, wrapperPath);
  if (theirs.build === 'this') return false;
  if (theirs.build === 'unread') return true;
  if (version === null || !isVersion(version)) return false;
  return (compareVersions(theirs.version, version) ?? 0) < 0;
}

/**
 * The first secretless-ai version whose wrapper checks an entry's binding
 * before it starts the entry's server: the version the binding is released
 * in. No release of it exists yet.
 */
export const FIRST_BINDING_VERSION = '0.24.0';

/**
 * Whether the wrapper a server runs through checks its binding, so the
 * checks this build's wrapper runs (checkStart) say whether it starts: this
 * build's file, or a wrapper that reads a version at or above
 * FIRST_BINDING_VERSION or at or above this build's, `version` (an equal
 * version is this build's checks). Any other wrapper, and one whose version
 * is not read, makes none of those checks, so mcp-status computes no start
 * clause for it.
 */
export function wrapperChecksBinding(theirs: WrapperBuild, version: string | null): boolean {
  if (theirs.build === 'this') return true;
  if (theirs.build === 'unread') return false;
  if ((compareVersions(theirs.version, FIRST_BINDING_VERSION) ?? -1) >= 0) return true;
  return version !== null && isVersion(version) && (compareVersions(theirs.version, version) ?? -1) >= 0;
}

/**
 * The state of a server that runs through the wrapper, by where the binding
 * stored for the pair it reads, `record`, points relative to its entry, first
 * match winning: (a) no record: `unbound` in a config protect-mcp rewrites,
 * `not-rewritten` in a project-level config it does not; (b) `elsewhere`: the
 * record's place is not this entry's (isBoundEntry: file by real path,
 * ~/.claude.json project key, and server name), whatever its --binding holds,
 * with whether that is the record's id (compared here, never printed); (c)
 * `stale-id`: at the record's place, with no --binding or another id; (d)
 * `command-changed`: place and id equal, and the command after its `--` is
 * not the one the record was bound with; (e) `bound`. Whether the wrapper
 * starts the entry is not a state: checkStart computes it.
 */
export type McpBindingState =
  | { state: 'unbound' }
  | { state: 'not-rewritten' }
  | { state: 'elsewhere'; binding: McpBinding; carriesRecordId: boolean }
  | { state: 'stale-id'; binding: McpBinding }
  | { state: 'command-changed'; binding: McpBinding }
  | { state: 'bound'; binding: McpBinding };

export function bindingState(
  record: McpBinding | undefined,
  config: McpServerMapLocation,
  server: Pick<McpServerEntry, 'name' | 'args'>,
): McpBindingState {
  if (record === undefined) return rewrittenByProtectMcp(config) ? { state: 'unbound' } : { state: 'not-rewritten' };
  const read = readWrapperArgv(server.args);
  const entryId = wrapperFlag(read, '--binding');
  const carriesRecordId = isBindingId(entryId) && entryId === record.id;
  if (!isBoundEntry(record, config, server.name)) return { state: 'elsewhere', binding: record, carriesRecordId };
  if (!carriesRecordId) return { state: 'stale-id', binding: record };
  if (read.child === undefined || record.commandDigest !== commandDigest(read.child.command, read.child.args)) {
    return { state: 'command-changed', binding: record };
  }
  return { state: 'bound', binding: record };
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

/**
 * What binding a server needs from this run: its store, what discovery found,
 * and the bindings read so far. A plan's store may hold nothing (see
 * planMcpBindings).
 */
interface Binder {
  vault: Pick<McpVault, 'backendName' | 'getBinding' | 'getServerSecrets' | 'storeBinding'>;
  discovered: { configs: McpConfigFile[]; unparsed: UnparsedMcpConfig[] };
  /** The servers that run through the wrapper in the configs this run rewrites, by the name they read by. */
  rewrittenReaders: Map<string, Array<{ config: McpConfigFile; server: McpServerEntry }>>;
  stores: WrapperStores;
  backupDir: string;
  /**
   * The secretless home this run stores bindings from: its directory, its id
   * (see binding-home-id.ts) once read or created, and why the id file could
   * not be used when it was read. The id is read when the run starts and is
   * created, where it is absent, before the first binding the run stores
   * (see storeBindingOf); a plan never creates it.
   */
  home: { dir: string; id?: string; unusable?: BindingHomeIdError };
  /** The binding of each pair read this run, by `client/server`, as this run leaves it. */
  bindings: Map<string, McpBinding | undefined>;
  /** The secretless-ai version this run is, for McpBinding.boundBy. */
  boundBy: string;
  /** Why the binding applyBinding last stored was not stored (see notStoredReason). */
  lastReason?: string;
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
  /**
   * This entry, in a home config, is at its binding's place and carries no id
   * or another one: the binding's id is written into its args, after the
   * binding takes its command where that changed.
   */
  | { kind: 'stale'; binding: McpBinding; digest: string }
  /**
   * This entry is bound in place: a new binding, and its id in the entry's
   * args. `movedFrom`: the binding of this entry before its project directory
   * moved, whose backup is filed under this file first (see movedEntry).
   */
  | { kind: 'bind'; id: string; digest: string; tookOver?: McpBinding; movedFrom?: McpBinding }
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
 * takes it over; a .mcp.json entry carrying its id after its project directory
 * moved is bound again (see movedEntry) when its command and arguments are the
 * ones it was bound with, and left when they changed. At the binding's place
 * with no id or another one: a home entry is given the binding's id, since its
 * file is the operator's and the id's only other copy is in it; a .mcp.json
 * entry is left, since its file comes with the repository.
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
    // A binding another secretless home stored (see ownsBinding) is never
    // written over, given a new id, taken over or written into an entry:
    // this entry is bound to it only where it carries its id and command,
    // and is otherwise left with why, or reported as a copy.
    const owned = ownedHere(binder, binding);
    if (carriesId && here) {
      if (binding.commandDigest === digest) return { kind: 'bound' };
      if (!owned) return { kind: 'left', reason: ANOTHER_MACHINE_REASON(reads), binding };
      if (scopeOf(config) === 'home') return { kind: 'rebind', binding, digest };
      return { kind: 'left', reason: changedProjectCommandReason(), binding };
    }
    if (carriesId && (await movedEntry(binder, config, reads, binding))) {
      // The id and the backup are evidence about the old file, not about the
      // command now in this one: a moved entry is bound again only to the
      // command it was bound with, and one whose command changed is left as
      // it is, as a .mcp.json entry at its own place is.
      if (binding.commandDigest !== digest) return { kind: 'left', reason: MOVED_COMMAND_CHANGED(path.dirname(binding.file)), binding };
      return placed(config, server, { kind: 'bind', id: newBindingId(), digest, movedFrom: binding });
    }
    if (!here && orphanedBinding(binder, binding)) {
      // The binding's entry is gone: the one entry that reads the pair, of
      // its scope, takes it over, and where several read it none does.
      const others = otherReaders(binder, reads, server);
      if (others.length > 0) return { kind: 'left', reason: otherReadersReason(reads, others), binding };
      if (scopeOf(config) === binding.scope) {
        return placed(config, server, { kind: 'bind', id: newBindingId(), digest, tookOver: binding });
      }
    }
    if (carriesId) return replacePlan(binder, binding) ?? { kind: 'copy', binding };
    if (!owned) return { kind: 'left', reason: ANOTHER_MACHINE_REASON(reads), binding };
    if (here && binding.scope === 'home') {
      const args = rawServerArgs(config, server.name);
      if (args === undefined || withWrapperBinding(args, binding.id) === undefined) return { kind: 'left', reason: NO_BINDING_ARG };
      return { kind: 'stale', binding, digest };
    }
    if (here) return { kind: 'left', reason: otherIdReason(reads), binding };
    return { kind: 'left', reason: boundElsewhereReason(reads, binding, boundFileClause(binder, binding)), binding };
  }

  const others = otherReaders(binder, reads, server);
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

/** Why an entry whose args cannot take an id in place is left. */
const NO_BINDING_ARG = 'its args do not take a --binding before the -- that ends its wrapper\'s own args';

/**
 * A plan that writes an id into an entry's args, when the args take it in
 * place (see withWrapperBinding), and otherwise one that leaves the entry.
 */
function placed(config: McpConfigFile, server: McpServerEntry, plan: Extract<BindingPlan, { kind: 'bind' }>): BindingPlan {
  const args = rawServerArgs(config, server.name);
  if (args === undefined || withWrapperBinding(args, plan.id) === undefined) {
    return { kind: 'left', reason: NO_BINDING_ARG };
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
 * that leaves it, and when the binding was not stored, with why in
 * binder.lastReason.
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
  // A moved entry's backup is filed under this file before its binding is
  // stored, so mcp-unprotect restores it here, and put back as it was when
  // the store refuses the binding.
  let unmove: (() => void) | undefined;
  try {
    if (plan.kind === 'rebind') {
      await storeBindingOf(binder, reads, {
        ...plan.binding,
        commandDigest: plan.digest,
        boundAt: new Date().toISOString(),
        boundBy: binder.boundBy,
      }, plan.binding);
      result.rebound.push(location);
      return true;
    }
    if (plan.kind === 'stale') {
      // The binding takes the entry's command before its id is written into
      // the entry, so a store that refuses it leaves the entry as it is.
      const commandChanged = plan.binding.commandDigest !== plan.digest;
      if (commandChanged) {
        await storeBindingOf(binder, reads, {
          ...plan.binding,
          commandDigest: plan.digest,
          boundAt: new Date().toISOString(),
          boundBy: binder.boundBy,
        }, plan.binding);
      }
      bindings[server.name] = plan.binding.id;
      result.rebound.push({ ...location, outOfDate: true, ...(commandChanged ? { commandChanged: true as const } : {}) });
      return true;
    }
    if (plan.movedFrom !== undefined) unmove = moveConfigBackup(plan.movedFrom.file, config.filePath, binder.backupDir);
    await storeBindingOf(binder, reads, newBinding(binder, config, server.name, plan.id, plan.digest), plan.movedFrom ?? plan.tookOver);
  } catch (err) {
    try {
      unmove?.();
    } catch {
      // The line this leads to names the store's error.
    }
    binder.lastReason = notStoredReason(err, plan.kind === 'bind'
      ? bindingValues({ id: plan.id, commandDigest: plan.digest }, plan.tookOver, plan.movedFrom)
      : bindingValues(plan.binding, { id: plan.binding.id, commandDigest: plan.digest }));
    return false;
  }
  bindings[server.name] = plan.id;
  const moved = plan.movedFrom;
  result.bound.push({
    ...location,
    ...(plan.tookOver === undefined ? {} : { tookOver: boundEntry(plan.tookOver) }),
    ...(moved === undefined ? {} : { movedFrom: { directory: path.dirname(moved.file) } }),
  });
  return true;
}

/**
 * For a copy of an entry bound in a home config: the plan that replaces the
 * binding, where this secretless home stored it (see ownsBinding), that entry
 * is in its file as this run read it, and its args take an id in place. A
 * project binding is left as it is: its copy is reported, and the wrapper
 * refuses it from a directory where it is visible. So is a binding another
 * home stored, which this run never gives a new id.
 */
function replacePlan(binder: Binder, binding: McpBinding): BindingPlan | undefined {
  if (binding.scope !== 'home' || !ownedHere(binder, binding)) return undefined;
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
 * What replaceBinding did. Not replaced, two ways: the binding is as it was,
 * since the store refused the new one (`store-refused`), the secretless
 * home's id file could not be used so none was stored (`home-id`, with the
 * reason HOME_ID_UNUSABLE gives), the store's binding, read again, was not
 * the one the plan read or another home stored it, so none was stored
 * (`refused`, with the reason BINDING_NOT_AS_READ gives), or the bound
 * entry's file could not be written and the old binding was stored back
 * (`stored-back`); or the file
 * could not be written and storing the old binding back failed too
 * (`not-stored-back`), so the store holds a binding no entry carries. Each
 * error as a line may show it (firstLine).
 */
type ReplaceOutcome =
  | { kind: 'replaced' }
  | { kind: 'store-refused'; error: string }
  | { kind: 'home-id'; reason: string }
  | { kind: 'refused'; reason: string }
  | { kind: 'stored-back'; file: string; error: string }
  | { kind: 'not-stored-back'; file: string; error: string };

/**
 * Replace a home binding a copy of its entry carries: a new id is stored for
 * the pair, with the same entry and command, before it is written into the
 * bound entry's args, so the copy, which keeps the old id, no longer starts.
 * A store that refuses the new binding leaves the entry as it is; a file that
 * cannot be written gets the old binding stored back, where the store takes
 * it (see ReplaceOutcome).
 */
async function replaceBinding(
  binder: Binder,
  plan: Extract<BindingPlan, { kind: 'replace' }>,
  reads: { client: string; server: string },
): Promise<ReplaceOutcome> {
  const id = newBindingId();
  const held = bindingValues({ id, commandDigest: plan.binding.commandDigest }, plan.binding);
  let stored: McpBinding;
  try {
    stored = await storeBindingOf(binder, reads, { ...plan.binding, id, boundAt: new Date().toISOString(), boundBy: binder.boundBy }, plan.binding);
  } catch (err) {
    if (err instanceof BindingHomeIdError) return { kind: 'home-id', reason: HOME_ID_UNUSABLE(err) };
    if (err instanceof BindingWriteRefusedError) return { kind: 'refused', reason: BINDING_NOT_AS_READ(err) };
    return { kind: 'store-refused', error: firstLine(err, held) };
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
    const written = { file: config.filePath, error: firstLine(err, held) };
    try {
      await storeBindingOf(binder, reads, plan.binding, stored);
    } catch {
      // The store keeps the new binding, which no entry carries; the line
      // this leads to says so, and names the file and the write's error.
      return { kind: 'not-stored-back', ...written };
    }
    return { kind: 'stored-back', ...written };
  }
  // Later in this run, the bound entry is read as its file now holds it.
  server.args = withWrapperBinding(server.args, id) ?? server.args;
  return { kind: 'replaced' };
}

/** A replacement's outcome as the fields of the copy it was made for (see CopiedBindingMcpServer, BindingCopyFile). */
function replaceFields(outcome: ReplaceOutcome): { replaced?: true; replaceError?: string; storeBackFailed?: StoreBackFailure } {
  switch (outcome.kind) {
    case 'replaced':
      return { replaced: true };
    case 'store-refused':
      return { replaceError: `the store refused the new binding (${outcome.error})` };
    case 'home-id':
    case 'refused':
      return { replaceError: outcome.reason };
    case 'stored-back':
      return { replaceError: `${listedName(outcome.file)} could not be written (${outcome.error})` };
    case 'not-stored-back':
      return { storeBackFailed: { file: outcome.file, error: outcome.error } };
  }
}

/**
 * What a line prints in place of a store's or a write's error message that
 * could hold the binding (see firstLine): the store's message was withheld
 * because it could hold the binding.
 */
export const STORE_MESSAGE_WITHHELD = "the store's message was withheld, since it could hold the binding";

/** A run of 32 or more hex characters: a binding id is 32, a command digest 64. */
const HEX_RUN = /[0-9a-f]{32,}/i;

/**
 * The first line of an error's message, as a line may show it, or
 * STORE_MESSAGE_WITHHELD where the message holds any of `held` (the ids and
 * command digests of the bindings being stored) or a run of 32 or more hex
 * characters. A detector behind each backend's own control, never the
 * control: a backend's store error never carries the value it was asked to
 * store, and a withheld line on a backend's real error is a defect there.
 */
function firstLine(err: unknown, held: readonly string[]): string {
  const message = err instanceof Error ? err.message : String(err);
  if (HEX_RUN.test(message) || held.some((value) => value !== '' && message.includes(value))) {
    return STORE_MESSAGE_WITHHELD;
  }
  return escapeForDisplay(message.split('\n')[0]);
}

/** The ids and command digests of bindings, the values firstLine withholds a message for. */
function bindingValues(...bindings: Array<Pick<McpBinding, 'id' | 'commandDigest'> | undefined>): string[] {
  return bindings.flatMap((binding) => (binding === undefined ? [] : [binding.id, binding.commandDigest]));
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

/**
 * Store a pair's binding, with the secretless home's id as its `boundOn`,
 * and return it as stored. It is the one function that writes a binding.
 * `expected` is the binding the plan read for the pair, or undefined where it
 * read none: the store's binding is read again first, and where it is not
 * `expected`, or is one this home did not store (see ownsBinding), nothing is
 * written (BindingWriteRefusedError, see expectBinding). The plans give the
 * reasons for what they leave; this stops a write that goes around them. No
 * binding is stored without the home's id: it is created here, where it is
 * absent, before the first binding a run stores, and a run that cannot read
 * or create it stores none (BindingHomeIdError).
 *
 * @internal Exported for the cells that call it over a binding another home
 * stored.
 */
export async function storeBindingOf(
  binder: Pick<Binder, 'vault' | 'bindings' | 'home'>,
  reads: { client: string; server: string },
  binding: McpBinding,
  expected: McpBinding | undefined,
): Promise<McpBinding> {
  await expectBinding(binder.vault, reads, expected, binder.home.id);
  binder.home.id ??= ensureBindingHomeId(binder.home.dir);
  const stored: McpBinding = { ...binding, boundOn: binder.home.id };
  await binder.vault.storeBinding(reads.client, reads.server, stored);
  binder.bindings.set(`${reads.client}/${reads.server}`, stored);
  return stored;
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
export function sameFile(a: string, b: string): boolean {
  if (path.resolve(a) === path.resolve(b)) return true;
  try {
    return fs.realpathSync(a) === fs.realpathSync(b);
  } catch {
    return false;
  }
}

/** Whether this secretless home stored a binding, in the store this run reads (see ownsBinding). */
function ownedHere(binder: Pick<Binder, 'vault' | 'home'>, binding: McpBinding): boolean {
  return ownsBinding(binder.vault.backendName, binding, binder.home.id);
}

/** Whether one server in the configs this run rewrites runs through the wrapper reading this pair. */
function soleReader(binder: Binder, reads: { client: string; server: string }): boolean {
  return (binder.rewrittenReaders.get(`${reads.client}/${reads.server}`) ?? []).length === 1;
}

/** The other servers in the configs this run rewrites that run through the wrapper reading this pair. */
function otherReaders(
  binder: Binder,
  reads: { client: string; server: string },
  server: McpServerEntry,
): Array<{ config: McpConfigFile; server: McpServerEntry }> {
  return (binder.rewrittenReaders.get(`${reads.client}/${reads.server}`) ?? []).filter((r) => r.server !== server);
}

/**
 * Whether the entry a binding this secretless home stored (see ownsBinding)
 * names is no longer in its config: its file is one this run read, and the
 * server map there holds no server of that name; or, for a home binding, its
 * file does not exist on this machine (a home config's path is fixed by the
 * home directory, so the entry is gone). A file this run did not read, one in
 * another project directory or one that could not be parsed, may still hold
 * it. A binding another home stored is never taken over: its entry is on
 * that home's machine.
 */
function orphanedBinding(binder: Binder, binding: McpBinding): boolean {
  if (!ownedHere(binder, binding)) return false;
  const inFile = (config: { filePath: string; projectKey?: string }) => sameFile(config.filePath, binding.file);
  if (binder.discovered.unparsed.some((u) => inFile(u) && (u.projectKey === undefined || u.projectKey === binding.projectKey))) {
    return false;
  }
  const fileConfigs = binder.discovered.configs.filter(inFile);
  if (fileConfigs.length === 0) {
    return binding.scope === 'home' && recordFileState(binding).state === 'absent';
  }
  const map = fileConfigs.find((config) => config.projectKey === binding.projectKey);
  if (map === undefined) return true;
  return !map.servers.some((s) => s.name === binding.server) && !map.unchecked.some((s) => s.name === binding.server);
}

/**
 * The state of the file a binding names, on this machine: `present` when
 * stat answers, `absent` when it fails with ENOENT or ENOTDIR, and `unknown`,
 * with the error code, when it fails for another reason, such as a directory
 * this run cannot search. stat follows a symlink, so a dangling one is absent.
 * protect-mcp's lines and mcp-status's states both read it, never the id.
 */
export type RecordFileState = { state: 'present' } | { state: 'absent' } | { state: 'unknown'; code: string };

export function recordFileState(binding: Pick<McpBinding, 'file'>): RecordFileState {
  try {
    fs.statSync(binding.file);
    return { state: 'present' };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? 'unknown error';
    return code === 'ENOENT' || code === 'ENOTDIR' ? { state: 'absent' } : { state: 'unknown', code };
  }
}

/**
 * Whether a .mcp.json entry carrying a project binding's id, where the
 * binding names another file, is the binding's own entry, moved with its
 * project directory: the file the binding names does not exist on this
 * machine, this secretless home stored the binding (see ownsBinding), the
 * entry is the one entry of the configs this run rewrites that reads the
 * pair, and this machine's backup of the file the binding names holds a
 * server of the binding's name whose env holds every name stored under the
 * pair at an equal value. A copy made while the original exists, and a
 * binding another home stored, are never taken this way.
 */
async function movedEntry(
  binder: Binder,
  config: McpConfigFile,
  reads: { client: string; server: string },
  binding: McpBinding,
): Promise<boolean> {
  if (scopeOf(config) !== 'project' || binding.scope !== 'project') return false;
  if (!soleReader(binder, reads) || !ownedHere(binder, binding)) return false;
  if (recordFileState(binding).state !== 'absent') return false;
  const stored = await binder.vault.getServerSecrets(reads.client, reads.server);
  return backupHoldsSecrets(binder.backupDir, binding.file, binding.server, stored);
}

/**
 * The clause a line naming a bound entry ends with when the entry's file does
 * not exist on this machine and the store is this machine's alone.
 */
const FILE_GONE = (file: string): string => `${listedName(file)} no longer exists.`;

/**
 * The clause for a bound entry's file absent here when the store is shared
 * between machines: the entry may be on another machine, so it states that
 * the file was not found on this one, and that `backend` is read from other
 * machines as well, so the binding may be in use there. Nothing of the
 * file's history, and no remedy.
 */
const FILE_NOT_FOUND_HERE = (file: string, backend: string): string =>
  `${listedName(file)} was not found on this machine; the ${backend} backend is read from other machines as well, so that binding may be in use there.`;

/**
 * The clause for the file of an entry bound by a binding this secretless home
 * stored in a store several machines read, absent here: the file this home
 * bound is gone from this machine. The words are FILE_NOT_FOUND_HERE's, the
 * clause for such a store.
 */
const OWNED_FILE_GONE_HERE = (file: string, backend: string): string => FILE_NOT_FOUND_HERE(file, backend);

/**
 * The clause for a bound entry's file that could not be checked: what was
 * checked, whether the file exists, then the error code, and nothing of a
 * missing file.
 */
const FILE_UNCHECKED = (file: string, code: string): string => `Whether ${listedName(file)} exists could not be checked (${escapeForDisplay(code)}).`;

/**
 * The sentence a line naming a bound entry carries about the entry's file
 * (see recordFileState), or '' when there is none. For a binding another
 * secretless home stored (see ownsBinding), ANOTHER_MACHINE_CLAUSE, whatever
 * the file's state here. For one this home stored, nothing when the file is
 * present, and when it is not: absent with a store that is this machine's
 * alone (FILE_GONE), absent with a store several machines read
 * (OWNED_FILE_GONE_HERE), or not checked, with the error code.
 */
function boundFileClause(binder: Binder, binding: McpBinding): string {
  if (!ownedHere(binder, binding)) return ANOTHER_MACHINE_CLAUSE(binding.file);
  const file = recordFileState(binding);
  if (file.state === 'present') return '';
  if (file.state === 'unknown') return FILE_UNCHECKED(binding.file, file.code);
  const backend = binder.vault.backendName;
  return isPerMachineStore(backend) ? FILE_GONE(binding.file) : OWNED_FILE_GONE_HERE(binding.file, backend);
}

/**
 * Whether protect-mcp's backup of a config file, the file as it was before
 * protect-mcp first changed it, holds a server of this name whose env holds
 * every secret in `stored` with the same value. A pair with no name stored
 * proves nothing, so it is never held: an entry is bound to an empty pair only
 * when this run stores its values from its env.
 */
function backupHoldsSecrets(backupDir: string, filePath: string, serverName: string, stored: Record<string, string>): boolean {
  if (Object.keys(stored).length === 0) return false;
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

/** `command` as a reason names it: for this build (see printed-command.ts). */
const cliCommand = (command: string): string => printedCommand(command, VERSION);

/** The end of a reason whose fix is to store the server's secrets from its env again. */
const STORE_AGAIN = (): string => `put the server's values in its env, and run \`${cliCommand('protect-mcp')}\`.`;

function changedProjectCommandReason(): string {
  return 'its command or arguments changed since it was bound, and a project-level entry is bound again only when protect-mcp stores its values. '
    + `If you made the change, ${STORE_AGAIN()}`;
}

/**
 * Why a .mcp.json entry carrying its binding's id after its project directory
 * moved (see movedEntry) is left when its command or arguments differ from
 * the ones it was bound with: the difference and the directory it was bound
 * in, then the fix. Nothing is stored or moved for it.
 */
const MOVED_COMMAND_CHANGED = (directory: string): string =>
  `its command or arguments changed since it was bound in ${listedName(directory)}, the project directory it moved from, `
  + 'and a moved entry is bound only when its command and arguments are the ones it was bound with. '
  + `If you made the change, ${STORE_AGAIN()}`;

function otherReadersReason(
  reads: { client: string; server: string },
  others: Array<{ config: McpConfigFile; server: McpServerEntry }>,
): string {
  const entries = others.map(({ config, server }) =>
    boundEntryName({ server: server.name, file: config.filePath, ...(config.projectKey === undefined ? {} : { projectKey: config.projectKey }) }));
  return `${pairName(reads)} is also read by ${entries.join('; ')}, and the secrets stored under a name are bound to one entry only. `
    + `Keep one of these entries, remove the others, and run \`${cliCommand('protect-mcp')}\`; to run another as well, add it again under a new name with its values.`;
}

function notInBackupReason(reads: { client: string; server: string }): string {
  return `the secrets stored under ${pairName(reads)} are not in protect-mcp's backup of this file, and a project-level entry is bound only to values protect-mcp stores from its file. `
    + `If this entry is yours, ${STORE_AGAIN()}`;
}

/** `fileClause`: what boundFileClause says of the bound entry's file, or ''. */
function boundElsewhereReason(reads: { client: string; server: string }, binding: McpBinding, fileClause: string): string {
  const file = fileClause === '' ? '' : ` ${fileClause}`;
  return `the secrets stored under ${pairName(reads)} are bound to ${boundEntryName(binding)}. `
    + `To run this server as well, add it again under a new name with its values and run \`${cliCommand('protect-mcp')}\`.${file}`;
}

/**
 * The end of a reason whose fix is the server added again under a new name,
 * where storing its values again would not bind it: the pair still holds
 * values, and a project-level value is stored only into an empty pair.
 */
const ADD_UNDER_NEW_NAME = (): string =>
  `If this entry is yours, add the server again under a new name with its values, remove this entry, and run \`${cliCommand('protect-mcp')}\`.`;

/**
 * Why protect-mcp leaves an entry whose pair's binding this secretless home
 * did not store (see ownsBinding), whether or not the file that binding
 * names exists here. It says four things: the pair's name; that protect-mcp
 * in another secretless home bound it, on another machine or on this one
 * before its ~/.secretless-ai was replaced; that protect-mcp and
 * mcp-unprotect on this machine leave that binding as it is; and how to run
 * the server here: under another name, with its own values. It never says
 * the bound entry no longer exists, and names no command that deletes a
 * binding.
 */
export const ANOTHER_MACHINE_REASON = (reads: { client: string; server: string }): string =>
  `the secrets stored under ${pairName(reads)} were bound by protect-mcp in another secretless home: on another machine, `
  + 'or on this one before its ~/.secretless-ai was replaced. protect-mcp and mcp-unprotect on this machine leave that binding as it is. '
  + `To run this server here, add it again under a new name with its own values and run \`${cliCommand('protect-mcp')}\`.`;

/**
 * The clause a line naming the entry a binding names ends with when this
 * secretless home did not store that binding (see boundFileClause), whatever
 * the state of that entry's file here: protect-mcp in another secretless
 * home bound that entry, on another machine or on this one before its
 * ~/.secretless-ai was replaced, and the file is a path there; protect-mcp
 * and mcp-unprotect on this machine leave that binding as it is. It never
 * says the file no longer exists, and names no command that deletes a
 * binding.
 */
export const ANOTHER_MACHINE_CLAUSE = (file: string): string =>
  'That entry was bound by protect-mcp in another secretless home, on another machine or on this one before its ~/.secretless-ai was replaced, '
  + `and ${listedName(file)} is a path there. protect-mcp and mcp-unprotect on this machine leave that binding as it is.`;

/** For a .mcp.json entry at its binding's place that carries no id or another one (a home one is bound again). */
function otherIdReason(reads: { client: string; server: string }): string {
  return `its binding does not match the one stored for ${pairName(reads)}. ${ADD_UNDER_NEW_NAME()}`;
}

/** Why a server's secrets were not stored, or it was not bound: the store refused its binding, with the store's error as firstLine gives it. */
function bindingNotStoredReason(storeError: string): string {
  return `the binding could not be stored (${storeError}); run \`${cliCommand('protect-mcp')}\` again once the store accepts writes`;
}

/**
 * Why no binding was stored when the secretless home's id file could not be
 * used (see BindingHomeIdError): the file, and that it holds no id, or the
 * errno code of the read or create that failed. Never what the file holds.
 * A run that cannot read or create the id stores no binding, every entry it
 * would bind is left with the error, and the file is never overwritten.
 */
export const HOME_ID_UNUSABLE = (error: BindingHomeIdError): string =>
  error.problem.kind === 'malformed'
    ? `${listedName(error.file)} does not hold a secretless home id, so no binding was stored, and protect-mcp does not overwrite it`
    : `${listedName(error.file)} could not be read or created (${error.problem.code}), so no binding was stored`;

/**
 * Why a binding was not stored when the store's binding for the pair, read
 * again just before the write, is not the one this run's plan read, or is one
 * this secretless home did not store (BindingWriteRefusedError): for one
 * another home stored, ANOTHER_MACHINE_REASON; for one that changed after it
 * was read, that nothing was written over it, and that protect-mcp, run
 * again, plans from what the store then holds. It never names a value.
 */
export const BINDING_NOT_AS_READ = (error: BindingWriteRefusedError): string =>
  error.why === 'not-owned'
    ? ANOTHER_MACHINE_REASON(error)
    : `the binding stored for ${pairName(error)} changed after this run read it, so nothing was written over it; run \`${cliCommand('protect-mcp')}\` again`;

/**
 * Why a binding was not stored, from what storing it threw: HOME_ID_UNUSABLE,
 * BINDING_NOT_AS_READ, or the store's error as firstLine gives it.
 */
function notStoredReason(err: unknown, held: readonly string[]): string {
  if (err instanceof BindingHomeIdError) return HOME_ID_UNUSABLE(err);
  if (err instanceof BindingWriteRefusedError) return BINDING_NOT_AS_READ(err);
  return bindingNotStoredReason(firstLine(err, held));
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
