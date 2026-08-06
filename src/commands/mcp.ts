import * as path from 'path';
import { protectMcp } from '../mcp/protect';
import { discoverMcpConfigs } from '../mcp/discover';
import { classifyEnvVars } from '../mcp/classify';
import { restoreConfig } from '../mcp/rewrite';
import { resolveBackendType } from '../backends/config';
import { effectiveBackendName } from '../backends/factory';
import type { SelectableBackendType } from '../backends/config';

function getWrapperPath(): string {
  return path.resolve(__dirname, '..', 'mcp-wrapper.js');
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
      console.error(`  Unknown backend type: ${val}. Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.\n`);
      return 1;
    }
  }

  try {
    const result = await protectMcp({ wrapperPath, backendType });
    if (result.clientsScanned === 0) {
      console.log('  No MCP configurations found.\n');
      console.log('  Looked for configs from: Claude Desktop, Cursor, Claude Code, VS Code, Windsurf');
      console.log('  Supported clients: Claude Desktop, Cursor, Claude Code, VS Code, Windsurf\n');
      return 0;
    }

    console.log(`  Scanned ${result.clientsScanned} client(s)\n`);

    if (result.secretsFound === 0) {
      console.log('  No plaintext secrets found in MCP configs. Already clean.\n');
      return 0;
    }

    for (const server of result.servers) {
      console.log(`  + ${server.client}/${server.server}`);
      for (const key of server.secretKeys) {
        console.log(`      ${key} (encrypted)`);
      }
    }
    console.log();

    console.log(`  ${result.secretsFound} secret(s) encrypted across ${result.serversProtected} server(s).`);
    if (result.alreadyProtected > 0) {
      console.log(`  ${result.alreadyProtected} server(s) already protected.`);
    }
    console.log();
    // Show injection warnings from NanoMind guard (if available)
    if (result.injectionWarnings.length > 0) {
      console.log(`  WARNING: ${result.injectionWarnings.length} potential prompt injection(s) detected:\n`);
      for (const w of result.injectionWarnings) {
        console.log(`    ! ${w.client}/${w.server} -> ${w.key}`);
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

  const configs = discoverMcpConfigs();

  if (configs.length === 0) {
    console.log('  No MCP configurations found.\n');
    return 0;
  }

  let protectedCount = 0;
  let exposedCount = 0;

  for (const config of configs) {
    console.log(`  ${config.client} (${config.filePath})`);
    for (const server of config.servers) {
      if (server.alreadyProtected) {
        console.log(`    + ${server.name}: protected`);
        protectedCount++;
      } else {
        const secretCount = Object.keys(classifyEnvVars(server.env).secrets).length;
        if (secretCount > 0) {
          console.log(`    ! ${server.name}: EXPOSED (${secretCount} plaintext secret(s))`);
          exposedCount++;
        } else {
          console.log(`    * ${server.name}: clean (no secrets in env)`);
        }
      }
    }
    console.log();
  }

  if (exposedCount > 0) {
    console.log('  Run `npx secretless-ai protect-mcp` to encrypt exposed secrets.\n');
  } else if (protectedCount > 0) {
    console.log(`  All protected servers use the ${backend} backend for secret storage.\n`);
  }
  return 0;
}

export function runMcpUnprotect(): number {
  console.log('\n  Secretless MCP Unprotect\n');

  const os = require('os');
  const home = os.homedir();
  const backupDir = path.join(home, '.secretless-ai', 'mcp-backups');

  const configs = discoverMcpConfigs();
  let restored = 0;

  for (const config of configs) {
    if (restoreConfig(config.filePath, backupDir)) {
      console.log(`  + Restored: ${config.filePath}`);
      restored++;
    }
  }

  if (restored === 0) {
    console.log('  No backups found to restore.\n');
  } else {
    console.log(`\n  Restored ${restored} config(s) to original state.\n`);
  }
  return 0;
}
