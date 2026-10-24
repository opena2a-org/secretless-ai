import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { isBoundEntry, protectMcp, sameFile } from '../mcp/protect';
import type {
  BoundMcpServer,
  CopiedBindingMcpServer,
  ProtectResult,
  ReboundMcpServer,
  RefusedNameMcpServer,
  SharedNameMcpServer,
  UnboundMcpServer,
  UnmovedMcpServer,
} from '../mcp/protect';
import { checkLaunchPlace, discoverMcpConfigsDetailed, mcpConfigLocations, rewrittenByProtectMcp } from '../mcp/discover';
import type { McpPlaceVerdict, McpServerEntry, UncheckedMcpServer, UnparsedMcpConfig } from '../mcp/discover';
import { classifyEnvVars } from '../mcp/classify';
import { restoreConfig } from '../mcp/rewrite';
import { McpVault, boundEntryName, checkLaunch, isPerMachineStore } from '../mcp/vault';
import type { McpBinding, McpLaunchVerdict } from '../mcp/vault';
import { resolveBackendType } from '../backends/config';
import { effectiveBackendName } from '../backends/factory';
import type { SelectableBackendType } from '../backends/config';
import { listedName } from '../secret-value';
import { escapeForDisplay } from '../display-safe';
import { EXIT_USAGE, readWrapperArgv, wrapperFlag } from '../argv';
import type { WrapperArgv } from '../argv';

function getWrapperPath(): string {
  return path.resolve(__dirname, '..', 'mcp-wrapper.js');
}

/**
 * A config as output names it: a home config by its client and full path, a
 * project-level config by its client and its path from the project, and a
 * bare mcp.json, whose client is not established, by that path alone. The
 * server map of one project in ~/.claude.json also names that project, as
 * `claude-code (/home/you/.claude.json, project /home/you/app)`.
 */
function configLabel(config: { client: string; filePath: string; projectPath?: string; projectKey?: string }): string {
  const where = config.projectPath ?? config.filePath;
  if (config.projectKey !== undefined) return `${config.client} (${where}, project ${listedName(config.projectKey)})`;
  return config.client === 'unknown' ? where : `${config.client} (${where})`;
}

/**
 * The answer when no config was found: every path looked in, generated from
 * the discovery list (home paths with ~, project paths from the project
 * directory), then the verdict.
 */
function printNoConfigFound(): void {
  console.log('  Looked in:');
  for (const location of mcpConfigLocations()) {
    console.log(`    ${location.scope === 'home' ? path.join('~', location.relativePath) : location.relativePath}`);
  }
  console.log();
  console.log('  No MCP configurations found.\n');
}

/**
 * List each MCP config that exists but could not be read or parsed. A command
 * that passes over one names it: the servers in it, and any plaintext secrets
 * there, were not acted on, so leaving it out reads as clean or absent.
 */
function printUnparsedConfigs(unparsed: UnparsedMcpConfig[], marker: string): void {
  for (const config of unparsed) {
    console.log(`  ${configLabel(config)}`);
    console.log(`    ? ${marker}: ${config.reason}`);
    console.log();
  }
}

/** The count of configs printUnparsedConfigs listed, what was not done to them, and the command to run once they are fixed. */
function printUnparsedFix(count: number, consequence: string, command: string): void {
  console.log(`  ${count} config(s) could not be parsed, so ${consequence}.`);
  console.log(`  Fix the file(s) above, then run \`npx secretless-ai ${command}\` again.\n`);
}

/**
 * One line for each server entry with a part that could not be read. That part
 * was not checked for secrets, so the server is never listed as clean.
 */
function printUncheckedServers(servers: UncheckedMcpServer[]): void {
  for (const server of servers) {
    console.log(`    ? ${listedName(server.name)}: ${server.part} not checked: ${server.reason}`);
  }
}

/** The count of servers printUncheckedServers listed, the shape that can be read, and the command to run once they are fixed. */
function printUncheckedFix(count: number, command: string): void {
  console.log(`  ${count} server(s) have a part that could not be read, so it was not checked for secrets.`);
  console.log('  A server is a JSON object, and its env is a JSON object of string values.');
  console.log(`  Fix the entries above, then run \`npx secretless-ai ${command}\` again.\n`);
}

/** One line for each server, under the label of its config, in the order given. */
function printUnderConfigs<T extends { client: string; filePath: string; projectPath?: string; projectKey?: string }>(
  servers: T[],
  line: (server: T) => string,
): void {
  let label: string | undefined;
  for (const server of servers) {
    const next = configLabel(server);
    if (next !== label) {
      if (label !== undefined) console.log();
      console.log(`  ${next}`);
      label = next;
    }
    console.log(line(server));
  }
  console.log();
}

/**
 * Each server protect-mcp left because a protected server reads its secrets
 * by the same name, under its config and naming the config of that server,
 * then why and what to do.
 */
function printSharedNameServers(servers: SharedNameMcpServer[]): void {
  printUnderConfigs(servers, (server) => {
    if (server.boundTo !== undefined) {
      const pair = listedName(`${server.client}/${server.server}`);
      return `    ? ${listedName(server.server)}: not protected: the secrets stored under ${pair} are bound to ${boundEntryName(server.boundTo)}`;
    }
    const holder = configLabel({ client: server.client, ...server.protectedIn });
    return `    ? ${listedName(server.server)}: not protected: its name is taken by a protected server in ${holder}`;
  });
  console.log(`  ${servers.length} server(s) were not protected, so their secrets are still in plaintext.`);
  console.log('  Secrets are stored under the client and server name, and a protected server reads its secrets by that name.');
  console.log('  Rename each server listed above, then run `npx secretless-ai protect-mcp` again.\n');
}

/**
 * Each server protect-mcp left because the store refuses its name, under its
 * config and with why, then what to do.
 */
function printRefusedNameServers(servers: RefusedNameMcpServer[]): void {
  printUnderConfigs(servers, (server) => `    ? ${listedName(server.server)}: not protected: ${server.reason}`);
  console.log(`  ${servers.length} server(s) were not protected, so their secrets are still in plaintext.`);
  console.log('  The store takes only A-Z, a-z, 0-9, - and _ in a server name.');
  console.log('  Rename each server listed above, then run `npx secretless-ai protect-mcp` again.\n');
}

/**
 * Each server with secrets protect-mcp left in its env, wrapped or not, under
 * its config and with why, then what to do.
 */
function printUnmovedServers(servers: UnmovedMcpServer[]): void {
  printUnderConfigs(servers, (server) => `    ? ${listedName(server.server)}: secrets not moved: ${server.reason}`);
  console.log(`  ${servers.length} server(s) have secrets in plaintext in their env that were not encrypted.`);
  console.log('  Move each value out of its file and rotate it, then run `npx secretless-ai mcp-status` again.\n');
}

/** `, project <key>` for an entry kept for one project in ~/.claude.json, otherwise nothing. */
function projectSuffix(entry: { projectKey?: string }): string {
  return entry.projectKey === undefined ? '' : `, project ${listedName(entry.projectKey)}`;
}

/**
 * The servers protect-mcp bound this run, under their configs: bound in
 * place, bound in place of a server no longer in its config, and bound again
 * after their command changed. Then the count.
 */
function printBoundServers(bound: BoundMcpServer[], rebound: ReboundMcpServer[]): void {
  const lines = [
    ...bound.map((server) => ({
      ...server,
      line: server.tookOver === undefined
        ? `    + ${listedName(server.server)}: bound`
        : `    + ${listedName(server.server)}: bound (took over the binding of server "${listedName(server.tookOver.server)}", no longer in ${listedName(server.tookOver.file)}${projectSuffix(server.tookOver)})`,
    })),
    ...rebound.map((server) => ({
      ...server,
      line: `    ~ ${listedName(server.server)}: its command or arguments changed since it was bound; bound again`,
    })),
  ];
  printUnderConfigs(inConfigOrder(lines), (server) => server.line);
  console.log(`  ${lines.length} server(s) bound to their config entries.\n`);
}

/**
 * The servers that run through the wrapper and are not bound, under their
 * configs with why, then the count and what the lines are for.
 */
function printUnboundServers(servers: UnboundMcpServer[]): void {
  printUnderConfigs(servers, (server) => `    ? ${listedName(server.server)}: not bound: ${server.reason}`);
  console.log(`  ${servers.length} server(s) run through the wrapper but are not bound, so the wrapper does not start them. Each line above says what to change.\n`);
}

/**
 * The servers that carry the binding of another entry, under their configs:
 * those whose home binding protect-mcp replaced, which no longer start, and
 * the others, which receive that entry's secrets. Then the counts.
 */
function printCopiedBindings(servers: CopiedBindingMcpServer[]): void {
  const remove = 'Remove this entry; to run the server here as well, add it again under a new name with its values and run `npx secretless-ai protect-mcp`.';
  printUnderConfigs(servers, (server) => {
    if (server.replaced) {
      return `    ? ${listedName(server.server)}: a copy of a bound entry: it carried the binding of ${boundEntryName(server.boundTo)}; the binding was replaced, and this entry no longer starts. ${remove}`;
    }
    const failed = server.replaceError === undefined ? '' : ` The binding could not be replaced: ${server.replaceError}.`;
    return `    ? ${listedName(server.server)}: a copy of a bound entry: it carries the binding of ${boundEntryName(server.boundTo)}, so the wrapper gives it that server's secrets.${failed} ${remove}`;
  });
  const replaced = servers.filter((server) => server.replaced).length;
  if (servers.length > replaced) console.log(`  ${servers.length - replaced} server(s) are copies of a bound entry and receive its secrets.`);
  if (replaced > 0) console.log(`  ${replaced} copied binding(s) replaced; those copies no longer start.`);
  console.log();
}

/** The binding lists of a protect-mcp run, each only when it has a server. */
function printBindingLists(result: ProtectResult): void {
  if (result.bound.length > 0 || result.rebound.length > 0) printBoundServers(result.bound, result.rebound);
  if (result.unbound.length > 0) printUnboundServers(result.unbound);
  if (result.copies.length > 0) printCopiedBindings(result.copies);
}

/** Entries reordered so the ones under one config label are together, labels in the order first seen. */
function inConfigOrder<T extends { client: string; filePath: string; projectPath?: string; projectKey?: string }>(entries: T[]): T[] {
  const labels = [...new Set(entries.map((entry) => configLabel(entry)))];
  return labels.flatMap((label) => entries.filter((entry) => configLabel(entry) === label));
}

export async function runProtectMcp(args: string[]): Promise<number> {
  console.log('\n  Secretless MCP Protection\n');

  const wrapperPath = getWrapperPath();

  // Parse --backend flag
  let backendType: SelectableBackendType | undefined;
  const backendIdx = args.indexOf('--backend');
  if (backendIdx !== -1 && args[backendIdx + 1]) {
    const val = args[backendIdx + 1];
    if (val === 'local' || val === 'keychain' || val === '1password' || val === 'vault' || val === 'gcp-sm') {
      backendType = val;
    } else {
      // Refused before any config is read, so EXIT_USAGE, as `setup` and
      // `backend set` refuse a backend type they do not take (#471).
      console.error(`  Unknown backend type: ${escapeForDisplay(val)}. Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.\n`);
      return EXIT_USAGE;
    }
  }

  try {
    const result = await protectMcp({ wrapperPath, backendType });
    const { unparsed, unchecked, sharedName, refusedName, unmoved, projectLevel } = result;
    const notChecked = () => {
      if (sharedName.length > 0) {
        printSharedNameServers(sharedName);
      }
      if (refusedName.length > 0) {
        printRefusedNameServers(refusedName);
      }
      if (unmoved.length > 0) {
        printUnmovedServers(unmoved);
      }
      if (unchecked.length > 0) {
        let servers = 0;
        for (const config of unchecked) {
          console.log(`  ${configLabel(config)}`);
          printUncheckedServers(config.servers);
          console.log();
          servers += config.servers.length;
        }
        printUncheckedFix(servers, 'protect-mcp');
      }
      if (unparsed.length > 0) {
        printUnparsedConfigs(unparsed, 'not checked');
        printUnparsedFix(unparsed.length, 'the servers in them were not checked', 'protect-mcp');
      }
      // A project-level config is left as it is, so `mcp-status` is where its servers are listed.
      if (projectLevel.length > 0) {
        for (const config of projectLevel) {
          console.log(`  ${configLabel(config)}`);
          console.log('    ? not checked: project-level config: see mcp-status');
          console.log();
        }
        console.log(`  ${projectLevel.length} project-level config(s) were not checked, so no secret in them was encrypted.`);
        console.log("  protect-mcp would write this machine's wrapper path into them, and these files are usually committed.");
        console.log('  Run `npx secretless-ai mcp-status` to list their servers.\n');
      }
    };

    if (result.clientsScanned === 0) {
      if (unparsed.length > 0 || projectLevel.length > 0) {
        notChecked();
        return 0;
      }
      printNoConfigFound();
      return 0;
    }

    console.log(`  Scanned ${result.clientsScanned} client(s)\n`);

    if (result.secretsFound === 0) {
      // A server left in plaintext because its name is taken or refused, or
      // because its secrets were not moved into the store its wrapper reads
      // from, was found with secrets in it, so none of the lines below is
      // true of it.
      if (sharedName.length > 0 || refusedName.length > 0 || unmoved.length > 0) {
        console.log('  No plaintext secrets were encrypted.\n');
        printBindingLists(result);
        notChecked();
        return 0;
      }
      // "Already clean." covers every server in every config, so it is not
      // printed over a config, or a part of a server entry, that was not read.
      if (unchecked.length > 0) {
        console.log('  No plaintext secrets found in the parts of the MCP configs that were read.\n');
        printBindingLists(result);
        notChecked();
        return 0;
      }
      if (unparsed.length > 0) {
        console.log('  No plaintext secrets found in the MCP configs that were read.\n');
        printBindingLists(result);
        notChecked();
        return 0;
      }
      if (projectLevel.length > 0) {
        console.log('  No plaintext secrets found in the MCP configs that were checked.\n');
        printBindingLists(result);
        notChecked();
        return 0;
      }
      console.log('  No plaintext secrets found in MCP configs. Already clean.\n');
      printBindingLists(result);
      return 0;
    }

    for (const server of result.servers) {
      console.log(`  + ${server.client}/${server.server}`);
      for (const key of server.secretKeys) {
        console.log(`      ${listedName(key)} (encrypted)`);
      }
    }
    console.log();

    console.log(`  ${result.secretsFound} secret(s) encrypted across ${result.serversProtected} server(s).`);
    if (result.alreadyProtected > 0) {
      console.log(`  ${result.alreadyProtected} server(s) already protected.`);
    }
    console.log();
    printBindingLists(result);
    notChecked();
    // Show injection warnings from NanoMind guard (if available)
    if (result.injectionWarnings.length > 0) {
      console.log(`  WARNING: ${result.injectionWarnings.length} potential prompt injection(s) detected:\n`);
      for (const w of result.injectionWarnings) {
        console.log(`    ! ${w.client}/${w.server} -> ${listedName(w.key)}`);
        console.log(`      Type: ${w.injectionType} (${w.severity})`);
      }
      console.log();
      console.log('  Review these env vars. They may contain injected instructions');
      console.log('  that could manipulate AI tool behavior.\n');
    }

    // Only while every server that runs through the wrapper is bound: the
    // wrapper starts no other.
    if (result.unbound.length === 0 && !result.copies.some((copy) => copy.replaced)) {
      console.log('  Protected servers start as before.');
    }
    console.log('  Run `npx secretless-ai mcp-status` to check status anytime.');
    console.log('  Run `npx secretless-ai mcp-unprotect` to restore originals.\n');
    return 0;
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

/** The backends the wrapper takes as --backend (parseArgs in mcp-wrapper.ts). */
const WRAPPER_BACKENDS = ['local', 'keychain', '1password', 'vault', 'gcp-sm'];

/**
 * The store a wrapped entry's wrapper reads, built from the entry's args as
 * the wrapper builds it: its --backend or the configured backend, and its
 * --vault-dir and --vault-key or their defaults. Undefined where the wrapper
 * stops before it reads a binding: an unknown --backend, or a local store
 * whose directory is missing, which is not created here (building the local
 * backend writes into it). One vault is built per store.
 */
function wrapperVault(read: WrapperArgv, vaults: Map<string, McpVault>): McpVault | undefined {
  if ((read.values.get('--backend') ?? []).some((value) => !WRAPPER_BACKENDS.includes(value))) return undefined;
  const home = os.homedir();
  let vaultDir = wrapperFlag(read, '--vault-dir') ?? '';
  let vaultKey = wrapperFlag(read, '--vault-key') ?? '';
  if (vaultDir && !vaultKey) vaultKey = `${home}-secretless-${process.env.USER ?? 'default'}`;
  if (!vaultDir) vaultDir = path.join(home, '.secretless-ai', 'mcp-vault');
  const backendType = wrapperFlag(read, '--backend') || resolveBackendType();
  if (backendType === 'local' && !fs.existsSync(vaultDir)) return undefined;
  const store = JSON.stringify([backendType, vaultDir, vaultKey]);
  let vault = vaults.get(store);
  if (!vault) {
    vault = new McpVault({ storeDir: vaultDir, ...(vaultKey ? { key: vaultKey } : {}), backendType });
    vaults.set(store, vault);
  }
  return vault;
}

/** The pair a wrapped entry's wrapper reads its secrets by, and the store it reads them from. */
interface WrapperRead {
  read: WrapperArgv;
  client: string;
  server: string;
  vault: McpVault;
}

/**
 * What a wrapped entry's wrapper reads, or undefined where the wrapper stops
 * before it reads anything: no command after its `--`, an empty --client or
 * --server, or no store (see wrapperVault).
 */
function wrapperRead(entry: McpServerEntry, vaults: Map<string, McpVault>): WrapperRead | undefined {
  const read = readWrapperArgv(entry.args);
  const client = wrapperFlag(read, '--client') ?? '';
  const server = wrapperFlag(read, '--server') ?? '';
  if (read.child === undefined || !client || !server) return undefined;
  const vault = wrapperVault(read, vaults);
  return vault ? { read, client, server, vault } : undefined;
}

/**
 * Whether the wrapper starts a wrapped entry, from checkLaunch and
 * checkLaunchPlace, the functions the wrapper runs before it reads a secret,
 * with this process's directory as the start directory: the verdicts, nothing
 * where the wrapper stops before those checks, or the store's error where
 * reading the binding failed (the wrapper then starts nothing either).
 */
async function entryLaunch(
  entry: McpServerEntry,
  vaults: Map<string, McpVault>,
): Promise<{ verdict?: McpLaunchVerdict; place?: McpPlaceVerdict; error?: string }> {
  const reads = wrapperRead(entry, vaults);
  if (!reads?.read.child) return {};
  try {
    const verdict = await checkLaunch(reads.vault, {
      client: reads.client,
      server: reads.server,
      binding: wrapperFlag(reads.read, '--binding'),
      command: reads.read.child.command,
      args: reads.read.child.args,
    });
    return verdict.refused === false ? { verdict, place: checkLaunchPlace(verdict.binding) } : { verdict };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

export async function runMcpStatus(): Promise<number> {
  console.log('\n  Secretless MCP Status\n');

  // Report where secrets actually go, matching `backend` and `secret list`.
  const backend = effectiveBackendName(resolveBackendType());
  console.log(`  Backend: ${backend}\n`);

  const { configs, unparsed } = discoverMcpConfigsDetailed();

  if (configs.length === 0 && unparsed.length === 0) {
    printNoConfigFound();
    return 0;
  }

  let protectedCount = 0;
  let exposedCount = 0;
  let uncheckedCount = 0;
  // Exposed servers in the project-level configs protect-mcp leaves as they are.
  let leftExposedCount = 0;
  const leftExposedFiles = new Set<string>();
  // Wrapped entries the wrapper does not start, by why: not bound (no binding,
  // another entry's binding, or a changed command), or in a project-level
  // config protect-mcp does not rewrite; and those it starts with another
  // entry's secrets.
  let notBoundCount = 0;
  let otherEntryCount = 0;
  let projectLevelCount = 0;
  const projectLevelFiles = new Set<string>();
  // Bound entries the wrapper does not start from this directory (see
  // checkLaunchPlace), by the scope of their binding.
  const placeRefused = { home: 0, project: 0 };
  const vaults = new Map<string, McpVault>();

  for (const config of configs) {
    console.log(`  ${configLabel(config)}`);
    // A server with a part that could not be read is never listed as clean or
    // protected: a plaintext secret in that part was not looked for.
    const unchecked = new Set(config.unchecked.map((server) => server.name));
    // Names are written as escapes where they hold a control character: a
    // project-level config arrives with the repository it is in.
    for (const server of config.servers) {
      // The env of a server that runs through the wrapper is classified too:
      // the wrapper does not take a value out of the file, so a plaintext
      // secret added to its env stays on disk.
      const secretCount = Object.keys(classifyEnvVars(server.env).secrets).length;
      const name = listedName(server.name);
      if (secretCount > 0) {
        console.log(`    ! ${name}: EXPOSED (${secretCount} plaintext secret(s))`);
        if (rewrittenByProtectMcp(config)) {
          exposedCount++;
        } else {
          leftExposedCount++;
          leftExposedFiles.add(config.projectPath ?? config.filePath);
        }
      } else if (unchecked.has(server.name)) {
        // Neither protected nor clean: the line printUncheckedServers writes
        // below names the part of its entry that was not read.
      } else if (server.alreadyProtected) {
        protectedCount++;
        // Whether the wrapper starts this entry comes from checkLaunch, the
        // function the wrapper runs, so the two never disagree on it.
        const launch = await entryLaunch(server, vaults);
        const verdict = launch.verdict;
        const place = launch.place;
        if (verdict && verdict.refused === false && place && place.refused !== false) {
          const holder = isBoundEntry(verdict.binding, config, server.name)
            ? 'protected and bound'
            : `carries the binding of the entry for ${boundEntryName(verdict.binding)}`;
          console.log(`    ? ${name}: ${holder}, but ${placeState(place)}, so the wrapper does not start it`);
          placeRefused[verdict.binding.scope]++;
        } else if (verdict && verdict.refused === false) {
          if (isBoundEntry(verdict.binding, config, server.name)) {
            console.log(`    + ${name}: protected and bound`);
          } else {
            console.log(
              `    ? ${name}: carries the binding of the entry for ${boundEntryName(verdict.binding)}, so the wrapper starts it with that entry's secrets`,
            );
            otherEntryCount++;
          }
        } else if (!rewrittenByProtectMcp(config)) {
          console.log(
            `    ? ${name}: runs through the wrapper from a config protect-mcp does not rewrite, so it is never bound and the wrapper does not start it`,
          );
          projectLevelCount++;
          projectLevelFiles.add(config.projectPath ?? config.filePath);
        } else if (launch.error !== undefined) {
          console.log(
            `    ? ${name}: protected, but its binding could not be read (${escapeForDisplay(launch.error)}), so the wrapper does not start it`,
          );
        } else if (verdict?.refused === 'other-binding') {
          console.log(
            `    ? ${name}: the secrets it reads are bound to the entry for ${boundEntryName(verdict.binding)}, so the wrapper does not start it`,
          );
          notBoundCount++;
        } else if (verdict?.refused === 'other-command') {
          console.log(
            `    ? ${name}: protected, but its command or arguments changed since it was bound, so the wrapper does not start it`,
          );
          notBoundCount++;
        } else {
          console.log(`    ? ${name}: protected, not bound, so the wrapper does not start it`);
          notBoundCount++;
        }
      } else {
        console.log(`    * ${name}: clean (no secrets in env)`);
      }
    }
    printUncheckedServers(config.unchecked);
    uncheckedCount += config.unchecked.length;
    console.log();
  }

  // A config that could not be parsed is never reported as clean or absent:
  // its servers, and any plaintext secrets in them, were not checked.
  printUnparsedConfigs(unparsed, 'not checked');

  if (exposedCount > 0) {
    console.log('  Run `npx secretless-ai protect-mcp` to encrypt exposed secrets.\n');
  } else if (protectedCount > 0) {
    console.log(`  All protected servers use the ${backend} backend for secret storage.\n`);
  }
  if (notBoundCount > 0) {
    console.log(`  ${notBoundCount} protected server(s) are not bound, so the wrapper does not start them.`);
    console.log(
      '  Run `npx secretless-ai protect-mcp` to bind the entries it protected; it names each entry it cannot bind, and why.\n',
    );
  }
  if (otherEntryCount > 0) {
    console.log(
      `  ${otherEntryCount} server(s) start with secrets bound to another entry. Remove each one unless it should start with those secrets.\n`,
    );
  }
  if (placeRefused.home + placeRefused.project > 0) {
    console.log(
      `  ${placeRefused.home + placeRefused.project} bound server(s) do not start from this directory; each line above says why.`,
    );
    if (placeRefused.home > 0) {
      console.log(
        '  Run `npx secretless-ai protect-mcp` to replace each home binding found outside its own entry; a copy of it then no longer starts.',
      );
    }
    if (placeRefused.project > 0) {
      console.log('  Remove each copy of a project binding named above; protect-mcp does not replace a project binding.');
    }
    console.log();
  }
  if (projectLevelCount > 0) {
    console.log(
      `  ${projectLevelCount} server(s) run through the wrapper from project-level configs protect-mcp does not rewrite, so they do not start: ${[...projectLevelFiles].map(listedName).join(', ')}.`,
    );
    console.log(
      "  protect-mcp binds entries only in home configs and in a project's .mcp.json; to run one of these servers, add it to one of those and run `npx secretless-ai protect-mcp`.\n",
    );
  }
  if (leftExposedCount > 0) {
    console.log(
      `  ${leftExposedCount} exposed server(s) are in project-level configs that protect-mcp does not rewrite: ${[...leftExposedFiles].join(', ')}.`,
    );
    console.log("  protect-mcp would write this machine's wrapper path into them, and these files are usually committed.");
    console.log('  Move each value out of its file and rotate it, then run `npx secretless-ai mcp-status` again.\n');
  }
  if (uncheckedCount > 0) {
    printUncheckedFix(uncheckedCount, 'mcp-status');
  }
  if (unparsed.length > 0) {
    printUnparsedFix(unparsed.length, 'the servers in them were not checked', 'mcp-status');
  }
  return 0;
}

/** Why checkLaunchPlace refused an entry, for its mcp-status line: paths only, never the id. */
function placeState(place: Exclude<McpPlaceVerdict, { refused: false }>): string {
  switch (place.refused) {
    case 'outside-project':
      return `its binding is to the project in ${listedName(place.project)}, and this directory is ${listedName(place.startDir)}`;
    case 'project-unresolved':
      return `its binding is to the project in ${listedName(place.project)}, and ${listedName(place.path)} could not be resolved (${place.code})`;
    case 'start-unresolved':
      return `this directory could not be resolved (${place.code})`;
    case 'copy-found':
      return `its binding also appears in ${listedName(place.file)}`;
    case 'copy-unchecked':
      return `${listedName(place.file)} could not be checked for a copy of its binding (${place.why})`;
  }
}

/**
 * The line for a pair mcp-unprotect leaves because its binding names an entry
 * in a file this run did not restore: that entry's location.
 */
const LEFT_BOUND_UNRESTORED = (label: string, entry: string): string =>
  `  ? ${label}: left in the store; it is bound to ${entry}, which this run did not restore.`;

/**
 * The line for a pair with no binding that mcp-unprotect leaves in a store
 * shared between machines.
 */
const LEFT_SHARED_UNBOUND = (label: string, backend: string): string =>
  `  ? ${label}: left in the store; it has no binding, and an entry on another machine may read it from the ${backend} backend.`;

/**
 * After a file is restored, each pair its wrapped entries read is deleted
 * from the store, with its binding, only where an entry of that server's name
 * in the restored file holds every name stored under the pair at an equal
 * value, and the pair's binding is absent or names an entry in a file this
 * run restored (`restoredFiles`): the file then has them, and no entry
 * outside the restored files loses them. In a store shared between machines,
 * a pair with no binding is left: an entry on another machine may read it.
 * Any other pair is left, and its line names the stored names the file does
 * not hold, or the entry its binding names (names and paths only).
 */
async function clearRestoredPairs(
  reads: Array<{ filePath: string; reads: WrapperRead }>,
  restoredFiles: readonly string[],
): Promise<void> {
  const restored = discoverMcpConfigsDetailed().configs;
  // A pair is looked at once per store.
  const done = new Map<McpVault, Set<string>>();
  for (const { filePath, reads: pair } of reads) {
    const pairs = done.get(pair.vault) ?? new Set<string>();
    done.set(pair.vault, pairs);
    const key = JSON.stringify([pair.client, pair.server]);
    if (pairs.has(key)) continue;
    pairs.add(key);
    const label = listedName(`${pair.client}/${pair.server}`);
    let stored: Record<string, string>;
    try {
      stored = await pair.vault.getServerSecrets(pair.client, pair.server);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`  ? ${label}: left in the store; it could not be read (${escapeForDisplay(msg)}).`);
      continue;
    }
    const names = Object.keys(stored).sort();
    if (names.length === 0) continue;
    const entries = restored
      .filter((config) => config.filePath === filePath)
      .flatMap((config) => config.servers)
      .filter((entry) => entry.name === pair.server);
    const notHeld =
      entries
        .map((entry) => names.filter((name) => entry.env[name] !== stored[name]))
        .sort((a, b) => a.length - b.length)[0] ?? names;
    if (notHeld.length > 0) {
      console.log(
        `  ? ${label}: left in the store: ${notHeld.map(listedName).join(', ')}. The restored file does not hold these values.`,
      );
      continue;
    }
    let found: McpBinding | undefined;
    try {
      found = await pair.vault.getBinding(pair.client, pair.server);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`  ? ${label}: left in the store; it could not be read (${escapeForDisplay(msg)}).`);
      continue;
    }
    const binding = found;
    if (binding === undefined && !isPerMachineStore(pair.vault.backendName)) {
      console.log(LEFT_SHARED_UNBOUND(label, pair.vault.backendName));
      continue;
    }
    if (binding !== undefined && !restoredFiles.some((file) => sameFile(file, binding.file))) {
      console.log(LEFT_BOUND_UNRESTORED(label, boundEntryName(binding)));
      continue;
    }
    await pair.vault.removeServerSecrets(pair.client, pair.server);
    console.log(
      `  - Deleted from the store: ${label} (${names.length} name(s); the restored file holds the same values)`,
    );
  }
}

export async function runMcpUnprotect(): Promise<number> {
  console.log('\n  Secretless MCP Unprotect\n');

  const home = os.homedir();
  const backupDir = path.join(home, '.secretless-ai', 'mcp-backups');

  // protect-mcp leaves a project-level config other than .mcp.json as it is,
  // so there is no backup of one to restore.
  const discovered = discoverMcpConfigsDetailed();
  const configs = discovered.configs.filter(rewrittenByProtectMcp);
  // A backup is of a whole file, so a file with several server maps (the top
  // level and each project of ~/.claude.json) is restored once, and a part of
  // it that could not be parsed is restored with the rest of it.
  const files = [...new Set(configs.map((config) => config.filePath))];
  const unparsed = discovered.unparsed.filter(
    (config) => rewrittenByProtectMcp(config) && !files.includes(config.filePath),
  );
  // The pairs each file's wrapped entries read, taken before the file is
  // restored: the restored file no longer names them.
  const vaults = new Map<string, McpVault>();
  const wrapped = configs.flatMap((config) =>
    config.servers
      .filter((entry) => entry.alreadyProtected)
      .map((entry) => ({ filePath: config.filePath, reads: wrapperRead(entry, vaults) })),
  );
  const restoredFiles: string[] = [];
  const cleared: Array<{ filePath: string; reads: WrapperRead }> = [];

  for (const filePath of files) {
    if (restoreConfig(filePath, backupDir)) {
      console.log(`  + Restored: ${filePath}`);
      restoredFiles.push(filePath);
      for (const entry of wrapped) {
        if (entry.filePath === filePath && entry.reads) cleared.push({ filePath, reads: entry.reads });
      }
    }
  }
  await clearRestoredPairs(cleared, restoredFiles);
  const restored = restoredFiles.length;

  // A config that could not be parsed was not looked at, so "no backups"
  // covers only the configs that were read.
  if (restored > 0) {
    console.log(`\n  Restored ${restored} config(s) to original state.\n`);
  } else if (unparsed.length === 0) {
    console.log('  No backups found to restore.\n');
  } else if (files.length > 0) {
    console.log('  No backups found to restore for the configs that were read.\n');
  }
  if (unparsed.length > 0) {
    printUnparsedConfigs(unparsed, 'not restored');
    printUnparsedFix(unparsed.length, 'no backup of them was restored', 'mcp-unprotect');
  }
  return 0;
}
