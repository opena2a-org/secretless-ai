#!/usr/bin/env node

/**
 * secretless-mcp — Lightweight MCP server wrapper.
 *
 * Decrypts secrets from the Secretless vault, injects them as env vars,
 * and spawns the real MCP server. Designed to add <10ms overhead.
 *
 * Usage:
 *   secretless-mcp --server <name> --client <client> [--vault-dir <path>] [--vault-key <key>] -- <command> [args...]
 */

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import { McpVault } from './mcp/vault';
import { resolveBackendType } from './backends/config';

function parseArgs(argv: string[]): {
  server: string;
  client: string;
  vaultDir: string;
  vaultKey: string;
  backend: string;
  childCommand: string;
  childArgs: string[];
} | null {
  let server = '';
  let client = '';
  let vaultDir = '';
  let vaultKey = '';
  let backend = '';
  let separatorIdx = -1;

  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--') { separatorIdx = i; break; }
    if (argv[i] === '--server' && argv[i + 1]) { server = argv[++i]; continue; }
    if (argv[i] === '--client' && argv[i + 1]) { client = argv[++i]; continue; }
    if (argv[i] === '--vault-dir' && argv[i + 1]) { vaultDir = argv[++i]; continue; }
    if (argv[i] === '--vault-key' && argv[i + 1]) { vaultKey = argv[++i]; continue; }
    if (argv[i] === '--backend' && argv[i + 1]) {
      const val = argv[++i];
      if (val !== 'local' && val !== 'keychain' && val !== '1password') {
        process.stderr.write(`secretless-mcp: Unknown backend: ${val}. Use 'local', 'keychain', or '1password'.\n`);
        process.exit(1);
      }
      backend = val;
      continue;
    }
  }

  if (separatorIdx === -1 || separatorIdx >= argv.length - 1) return null;

  const home = os.homedir();
  if (!vaultDir) vaultDir = path.join(home, '.secretless-ai', 'mcp-vault');
  if (!vaultKey) vaultKey = `${home}-secretless-${process.env.USER ?? 'default'}`;

  return {
    server,
    client,
    vaultDir,
    vaultKey,
    backend,
    childCommand: argv[separatorIdx + 1],
    childArgs: argv.slice(separatorIdx + 2),
  };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (!args) {
    process.stderr.write('secretless-mcp: Usage: secretless-mcp --server <name> --client <client> -- <command> [args...]\n');
    process.exit(1);
  }

  // Resolve backend: explicit --backend flag > config file > default ('local').
  // This ensures that switching backends via `backend set 1password` applies
  // to existing MCP configs that were written without a --backend flag.
  const backendType = args.backend || resolveBackendType();

  // Validate vault directory exists (only needed for local backend)
  if (backendType === 'local') {
    if (!fs.existsSync(args.vaultDir)) {
      process.stderr.write(`secretless-mcp: Vault directory not found: ${args.vaultDir}\n`);
      process.stderr.write(`secretless-mcp: Run 'npx secretless-ai mcp-protect' to set up MCP secret protection.\n`);
      process.exit(1);
    }
  }

  // Load secrets from vault
  let secrets: Record<string, string> = {};
  try {
    const vault = new McpVault({
      storeDir: args.vaultDir,
      key: args.vaultKey,
      backendType,
    });
    secrets = await vault.getServerSecrets(args.client, args.server);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`secretless-mcp: Failed to load secrets for ${args.client}/${args.server}: ${msg}\n`);
    process.stderr.write(`secretless-mcp: Run 'npx secretless-ai mcp-unprotect' to restore original configs.\n`);
    process.exit(1);
  }

  // Merge secrets into env (secrets override existing env vars)
  const childEnv = { ...process.env, ...secrets };

  // Spawn the real MCP server
  const child = spawn(args.childCommand, args.childArgs, {
    env: childEnv,
    stdio: ['inherit', 'inherit', 'inherit'],
  });

  // Forward signals
  const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT', 'SIGHUP'];
  for (const sig of signals) {
    process.on(sig, () => child.kill(sig));
  }

  // Forward exit code
  child.on('close', (code) => {
    process.exit(code ?? 1);
  });

  child.on('error', (err) => {
    process.stderr.write(`secretless-mcp: Failed to start ${args.childCommand}: ${err.message}\n`);
    process.stderr.write(`secretless-mcp: Run 'npx secretless-ai mcp-unprotect' to restore original configs.\n`);
    process.exit(1);
  });
}

main();
