/**
 * MCP config backup and rewrite module.
 *
 * Backs up original MCP config files before modification,
 * rewrites configs to replace server commands with the secretless-mcp wrapper,
 * and provides restore capability to undo protection.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RewriteResult {
  serversRewritten: number;
  backupPath: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Validates server/client names contain only safe characters. */
const SAFE_NAME = /^[a-zA-Z0-9_\-]+$/;

/**
 * Check if a server command indicates it is already wrapped by secretless-mcp.
 */
function isProtectedCommand(command: string, wrapperPath: string): boolean {
  if (command === 'secretless-mcp') return true;
  if (command.endsWith('/secretless-mcp')) return true;
  if (command === wrapperPath) return true;
  return false;
}

/**
 * Derive a deterministic backup filename from a config file path.
 * Uses the first 12 hex chars of the SHA-256 hash of the path.
 */
function backupFilename(configPath: string): string {
  const hash = crypto.createHash('sha256').update(configPath).digest('hex');
  return `${hash}.json`;
}

/**
 * Read and parse the manifest.json from the backup directory.
 * Returns an empty object if the manifest does not exist.
 */
function readManifest(backupDir: string): Record<string, string> {
  const manifestPath = path.join(backupDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) return {};
  try {
    return JSON.parse(fs.readFileSync(manifestPath, 'utf-8')) as Record<string, string>;
  } catch {
    return {};
  }
}

/**
 * Write the manifest.json to the backup directory.
 */
function writeManifest(backupDir: string, manifest: Record<string, string>): void {
  const manifestPath = path.join(backupDir, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(manifestPath, 0o600);
}

// ---------------------------------------------------------------------------
// Main functions
// ---------------------------------------------------------------------------

/**
 * Rewrite an MCP config file to wrap server commands with the secretless-mcp wrapper.
 *
 * For each server entry in `mcpServers`:
 * - Skips servers that are already protected
 * - Skips servers with no secrets in `serverSecrets`
 * - Replaces the command with `wrapperPath`
 * - Restructures args to pass original command through the wrapper
 * - Removes secret env vars, keeps non-secret ones
 *
 * Creates a backup of the original file before any modifications.
 *
 * @param configPath    - Absolute path to the MCP config file
 * @param client        - Client identifier (e.g. 'cursor', 'claude-desktop')
 * @param serverSecrets - Map of serverName → {envKey: value} for secrets to protect
 * @param wrapperPath   - Path to the secretless-mcp wrapper binary
 * @param backupDir     - Directory to store backup files and manifest
 * @param backendType   - Optional backend type to pass to the wrapper (omitted for 'local')
 * @returns Result with count of servers rewritten and path to backup file
 */
export function rewriteConfig(
  configPath: string,
  client: string,
  serverSecrets: Record<string, Record<string, string>>,
  wrapperPath: string,
  backupDir: string,
  backendType?: string,
): RewriteResult {
  // Read and parse the config file
  const content = fs.readFileSync(configPath, 'utf-8');
  const config = JSON.parse(content) as Record<string, unknown>;

  const mcpServers = config['mcpServers'] as Record<string, Record<string, unknown>> | undefined;
  if (!mcpServers || typeof mcpServers !== 'object') {
    return { serversRewritten: 0, backupPath: null };
  }

  // Determine which servers need rewriting
  let serversRewritten = 0;

  for (const [serverName, serverDef] of Object.entries(mcpServers)) {
    const command = typeof serverDef['command'] === 'string' ? serverDef['command'] : '';
    const args = Array.isArray(serverDef['args'])
      ? (serverDef['args'] as unknown[]).filter((a): a is string => typeof a === 'string')
      : [];

    // Skip if already protected
    if (isProtectedCommand(command, wrapperPath)) continue;

    // Validate server name for defense in depth
    if (!SAFE_NAME.test(serverName)) continue;

    // Skip if no secrets for this server
    const secrets = serverSecrets[serverName];
    if (!secrets || Object.keys(secrets).length === 0) continue;

    // Build new args: ['--server', name, '--client', client, [--backend type], '--', originalCommand, ...originalArgs]
    const newArgs = [
      '--server', serverName,
      '--client', client,
      ...(backendType && backendType !== 'local' ? ['--backend', backendType] : []),
      '--',
      command,
      ...args,
    ];

    // Remove secret env vars, keep non-secret ones
    const env = (serverDef['env'] && typeof serverDef['env'] === 'object')
      ? { ...(serverDef['env'] as Record<string, string>) }
      : {};

    for (const secretKey of Object.keys(secrets)) {
      delete env[secretKey];
    }

    // Apply changes
    serverDef['command'] = wrapperPath;
    serverDef['args'] = newArgs;
    serverDef['env'] = env;

    serversRewritten++;
  }

  // If nothing was rewritten, don't create backup or modify file
  if (serversRewritten === 0) {
    return { serversRewritten: 0, backupPath: null };
  }

  // Create backup directory with restricted permissions
  fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });

  // Save backup of original content
  const bkFilename = backupFilename(configPath);
  const bkPath = path.join(backupDir, bkFilename);
  fs.writeFileSync(bkPath, content, { mode: 0o600 });
  fs.chmodSync(bkPath, 0o600);

  // Update manifest
  const manifest = readManifest(backupDir);
  manifest[configPath] = bkPath;
  writeManifest(backupDir, manifest);

  // Write modified config back
  const newContent = JSON.stringify(config, null, 2) + '\n';
  fs.writeFileSync(configPath, newContent, { mode: 0o600 });
  fs.chmodSync(configPath, 0o600);

  return { serversRewritten, backupPath: bkPath };
}

/**
 * Restore an MCP config file from its backup.
 *
 * Looks up the config path in the backup manifest and copies the backup
 * content back to the original location.
 *
 * @param configPath - Absolute path to the config file to restore
 * @param backupDir  - Directory containing backup files and manifest
 * @returns true if restored, false if no backup found
 */
export function restoreConfig(configPath: string, backupDir: string): boolean {
  const manifest = readManifest(backupDir);
  const bkPath = manifest[configPath];

  if (!bkPath || !fs.existsSync(bkPath)) {
    return false;
  }

  const backupContent = fs.readFileSync(bkPath, 'utf-8');

  // Verify backup is valid JSON before restoring
  try {
    JSON.parse(backupContent);
  } catch {
    return false;
  }

  fs.writeFileSync(configPath, backupContent);

  return true;
}
