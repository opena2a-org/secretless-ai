import * as path from 'path';
import { protectMcp } from '../mcp/protect';
import type { SharedNameMcpServer } from '../mcp/protect';
import { discoverMcpConfigsDetailed, mcpConfigLocations, rewrittenByProtectMcp } from '../mcp/discover';
import type { UncheckedMcpServer, UnparsedMcpConfig } from '../mcp/discover';
import { classifyEnvVars } from '../mcp/classify';
import { restoreConfig } from '../mcp/rewrite';
import { resolveBackendType } from '../backends/config';
import { effectiveBackendName } from '../backends/factory';
import type { SelectableBackendType } from '../backends/config';
import { listedName } from '../secret-value';
import { escapeForDisplay } from '../display-safe';

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

/**
 * Each server protect-mcp left because a protected server reads its secrets
 * by the same name, under its config and naming the config of that server,
 * then why and what to do.
 */
function printSharedNameServers(servers: SharedNameMcpServer[]): void {
  let label: string | undefined;
  for (const server of servers) {
    const next = configLabel(server);
    if (next !== label) {
      if (label !== undefined) console.log();
      console.log(`  ${next}`);
      label = next;
    }
    const holder = configLabel({ client: server.client, ...server.protectedIn });
    console.log(`    ? ${listedName(server.server)}: not protected: its name is taken by a protected server in ${holder}`);
  }
  console.log();
  console.log(`  ${servers.length} server(s) were not protected, so their secrets are still in plaintext.`);
  console.log('  Secrets are stored under the client and server name, and a protected server reads its secrets by that name.');
  console.log('  Rename each server listed above, then run `npx secretless-ai protect-mcp` again.\n');
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
      console.error(`  Unknown backend type: ${escapeForDisplay(val)}. Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.\n`);
      return 1;
    }
  }

  try {
    const result = await protectMcp({ wrapperPath, backendType });
    const { unparsed, unchecked, sharedName, projectLevel } = result;
    const notChecked = () => {
      if (sharedName.length > 0) {
        printSharedNameServers(sharedName);
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
      // A server left in plaintext because its name is taken was found with
      // secrets in it, so none of the lines below is true of it.
      if (sharedName.length > 0) {
        console.log('  No plaintext secrets were encrypted.\n');
        notChecked();
        return 0;
      }
      // "Already clean." covers every server in every config, so it is not
      // printed over a config, or a part of a server entry, that was not read.
      if (unchecked.length > 0) {
        console.log('  No plaintext secrets found in the parts of the MCP configs that were read.\n');
        notChecked();
        return 0;
      }
      if (unparsed.length > 0) {
        console.log('  No plaintext secrets found in the MCP configs that were read.\n');
        notChecked();
        return 0;
      }
      if (projectLevel.length > 0) {
        console.log('  No plaintext secrets found in the MCP configs that were checked.\n');
        notChecked();
        return 0;
      }
      console.log('  No plaintext secrets found in MCP configs. Already clean.\n');
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

    console.log('  MCP servers will start normally — no workflow changes needed.');
    console.log('  Run `npx secretless-ai mcp-status` to check status anytime.');
    console.log('  Run `npx secretless-ai mcp-unprotect` to restore originals.\n');
    return 0;
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

export function runMcpStatus(): number {
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

  for (const config of configs) {
    console.log(`  ${configLabel(config)}`);
    // A server with a part that could not be read is never listed as clean:
    // a plaintext secret in that part was not looked for.
    const unchecked = new Set(config.unchecked.map((server) => server.name));
    // Names are written as escapes where they hold a control character: a
    // project-level config arrives with the repository it is in.
    for (const server of config.servers) {
      if (server.alreadyProtected) {
        console.log(`    + ${listedName(server.name)}: protected`);
        protectedCount++;
      } else {
        const secretCount = Object.keys(classifyEnvVars(server.env).secrets).length;
        if (secretCount > 0) {
          console.log(`    ! ${listedName(server.name)}: EXPOSED (${secretCount} plaintext secret(s))`);
          if (rewrittenByProtectMcp(config)) {
            exposedCount++;
          } else {
            leftExposedCount++;
            leftExposedFiles.add(config.projectPath ?? config.filePath);
          }
        } else if (!unchecked.has(server.name)) {
          console.log(`    * ${listedName(server.name)}: clean (no secrets in env)`);
        }
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

export function runMcpUnprotect(): number {
  console.log('\n  Secretless MCP Unprotect\n');

  const os = require('os');
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
  let restored = 0;

  for (const filePath of files) {
    if (restoreConfig(filePath, backupDir)) {
      console.log(`  + Restored: ${filePath}`);
      restored++;
    }
  }

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
