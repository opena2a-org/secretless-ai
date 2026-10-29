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
import { runsThroughSecretlessWrapper, serverMapKey } from './discover';
import { withWrapperBinding } from '../argv';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RewriteResult {
  serversRewritten: number;
  /** Servers that already ran through the wrapper and had their --binding set (see bindServers). */
  serversBound?: number;
  /** Servers whose command was set to the wrapper path in this write (see ServerMapSecrets.repoint). Absent when none. */
  repointed?: Array<{ projectKey?: string; server: string }>;
  backupPath: string | null;
}

/** The secrets to move out of one server map of a config, by server name. */
export interface ServerMapSecrets {
  /**
   * The key under `projects` whose entry holds this server map, as in
   * ~/.claude.json (see McpConfigFile.projectKey). Absent for the server map
   * at the top level of the file.
   */
  projectKey?: string;
  /** Map of serverName → {envKey: value} for secrets to protect */
  serverSecrets: Record<string, Record<string, string>>;
  /**
   * Map of serverName → env keys to remove, for a server that already runs
   * through the wrapper: those secrets were stored under the name its wrapper
   * reads by, so only its env changes and its command and args are left as
   * they are.
   */
  storedEnvKeys?: Record<string, string[]>;
  /**
   * Map of serverName → the id of the binding protect-mcp stored for the
   * pair the server reads (see McpBinding). A server wrapped by this rewrite
   * gets `--binding <id>` in its new args; a server that already runs through
   * the wrapper has its --binding set in place (see bindServers).
   */
  bindings?: Record<string, string>;
  /**
   * Servers that run through another build's wrapper, by name: their command
   * is set to the wrapper path in this write, and nothing else of them changes
   * (see repointServers).
   */
  repoint?: string[];
}

export interface RewriteOptions {
  /**
   * Keep the backup of this file an earlier run wrote, when there is one that
   * restoreConfig can read, in place of backing the file up as it is now.
   * protect-mcp asks for this when the file already has a server that runs
   * through the wrapper, as a file an earlier run rewrote has, and the backup
   * that run wrote is the file as it was before protect-mcp changed it. Each
   * run that rewrote the file replaced its backup, so mcp-unprotect restored
   * the file as the last run found it, with the servers earlier runs
   * protected still running through the wrapper (#513).
   */
  keepBackup?: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Validates server/client names contain only safe characters. */
const SAFE_NAME = /^[a-zA-Z0-9_\-]+$/;

// ---------------------------------------------------------------------------
// Backup encryption (prevents plaintext secret leakage in backup files)
// ---------------------------------------------------------------------------

const SALT_FILE = '.salt';

/**
 * Load or create a 16-byte random salt for backup key derivation.
 */
function loadOrCreateBackupSalt(dir: string): Buffer {
  const saltPath = path.join(dir, SALT_FILE);
  try {
    const existing = fs.readFileSync(saltPath);
    if (existing.length === 16) return existing;
  } catch {
    // Salt file does not exist yet — will be created below
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const salt = crypto.randomBytes(16);
  fs.writeFileSync(saltPath, salt, { mode: 0o600 });
  return salt;
}

function deriveBackupKey(backupDir: string): Buffer {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  const keyMaterial = `${home}-secretless-mcp-backup-${process.env.USER ?? 'default'}`;
  const salt = loadOrCreateBackupSalt(backupDir);
  return crypto.scryptSync(keyMaterial, salt, 32, { N: 16384, r: 8, p: 1 });
}

/**
 * Derive the legacy (pre-salt) backup key via single SHA-256.
 * Used only during migration when restoring old backups.
 */
function deriveLegacyBackupKey(): Buffer {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  const keyMaterial = `${home}-secretless-mcp-backup-${process.env.USER ?? 'default'}`;
  return crypto.createHash('sha256').update(keyMaterial).digest();
}

function encryptBackup(plaintext: string, key: Buffer): Buffer {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]);
}

function decryptBackup(data: Buffer, key: Buffer): string {
  const iv = data.subarray(0, 16);
  const tag = data.subarray(16, 32);
  const ciphertext = data.subarray(32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ciphertext) + decipher.final('utf-8');
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
 * For each server entry in the server map, under the key serverMapKey names
 * (the key discovery read the secrets from):
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
  return rewriteServerMaps(configPath, client, [{ serverSecrets }], wrapperPath, backupDir, backendType);
}

/**
 * Rewrite one or more server maps of an MCP config file, each as rewriteConfig
 * rewrites the map at the top level of a file: that map for a ServerMapSecrets
 * without a projectKey, and the map in the entry of that project under
 * `projects` for one with it. The keys in a map's storedEnvKeys are removed
 * from the env of the servers they are listed for, which keep their command
 * and args, and the servers in its repoint have their command set to
 * `wrapperPath`. The file is read, backed up and written once, so the backup is
 * the file as it was before any of its maps was rewritten, unless
 * options.keepBackup keeps the one an earlier run wrote.
 */
export function rewriteServerMaps(
  configPath: string,
  client: string,
  maps: readonly ServerMapSecrets[],
  wrapperPath: string,
  backupDir: string,
  backendType?: string,
  options?: RewriteOptions,
): RewriteResult {
  // Read and parse the config file
  const content = fs.readFileSync(configPath, 'utf-8');
  const config = JSON.parse(content) as Record<string, unknown>;

  let serversRewritten = 0;
  let serversBound = 0;
  const repointed: Array<{ projectKey?: string; server: string }> = [];
  for (const { projectKey, serverSecrets, storedEnvKeys, bindings, repoint } of maps) {
    const container = projectKey === undefined ? config : projectEntry(config, projectKey);
    if (container === undefined) continue;
    serversRewritten += wrapServers(container, client, serverSecrets, wrapperPath, backendType, bindings);
    if (storedEnvKeys !== undefined) serversRewritten += removeEnvKeys(container, storedEnvKeys);
    if (bindings !== undefined) {
      // A server wrapped above already carries its id in its new args.
      const wrapped = Object.entries(bindings).filter(([name]) => !Object.prototype.hasOwnProperty.call(serverSecrets, name));
      serversBound += bindServers(container, Object.fromEntries(wrapped));
    }
    if (repoint !== undefined) {
      for (const server of repointServers(container, repoint, wrapperPath)) {
        repointed.push({ ...(projectKey === undefined ? {} : { projectKey }), server });
      }
    }
  }

  // If nothing was rewritten, don't create backup or modify file
  if (serversRewritten === 0 && serversBound === 0 && repointed.length === 0) {
    return { serversRewritten: 0, serversBound: 0, backupPath: null };
  }

  // Create backup directory with restricted permissions
  fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });

  const manifest = readManifest(backupDir);
  const earlier = manifest[configPath];
  let bkPath: string;
  if (options?.keepBackup === true && readBackup(earlier, backupDir) !== undefined) {
    bkPath = earlier;
  } else {
    // Save encrypted backup of original content (prevents plaintext secret leakage)
    bkPath = path.join(backupDir, backupFilename(configPath));
    const backupKey = deriveBackupKey(backupDir);
    const encryptedBackup = encryptBackup(content, backupKey);
    fs.writeFileSync(bkPath, encryptedBackup, { mode: 0o600 });
    fs.chmodSync(bkPath, 0o600);

    // Update manifest
    manifest[configPath] = bkPath;
    writeManifest(backupDir, manifest);
  }

  // Write modified config back
  const newContent = JSON.stringify(config, null, 2) + '\n';
  fs.writeFileSync(configPath, newContent, { mode: 0o600 });
  fs.chmodSync(configPath, 0o600);

  return { serversRewritten, serversBound, ...(repointed.length === 0 ? {} : { repointed }), backupPath: bkPath };
}

/** The entry of one project under `projects`, when it is a JSON object. */
function projectEntry(config: Record<string, unknown>, projectKey: string): Record<string, unknown> | undefined {
  const projects = config['projects'];
  if (!projects || typeof projects !== 'object' || Array.isArray(projects)) return undefined;
  if (!Object.prototype.hasOwnProperty.call(projects, projectKey)) return undefined;
  const entry = (projects as Record<string, unknown>)[projectKey];
  return entry && typeof entry === 'object' && !Array.isArray(entry) ? (entry as Record<string, unknown>) : undefined;
}

/**
 * Wrap the servers of one server map, the one in `container` under the key
 * serverMapKey names, as rewriteConfig describes. Returns how many were
 * rewritten; the caller writes the file.
 */
function wrapServers(
  container: Record<string, unknown>,
  client: string,
  serverSecrets: Record<string, Record<string, string>>,
  wrapperPath: string,
  backendType?: string,
  bindings?: Record<string, string>,
): number {
  const key = serverMapKey(container);
  const mcpServers = (key === undefined ? undefined : container[key]) as Record<string, Record<string, unknown>> | undefined;
  if (!mcpServers || typeof mcpServers !== 'object') {
    return 0;
  }

  // Determine which servers need rewriting
  let serversRewritten = 0;

  for (const [serverName, serverDef] of Object.entries(mcpServers)) {
    const command = typeof serverDef['command'] === 'string' ? serverDef['command'] : '';
    const args = Array.isArray(serverDef['args'])
      ? (serverDef['args'] as unknown[]).filter((a): a is string => typeof a === 'string')
      : [];

    // Skip a server that already runs through a wrapper, as discovery counts it
    if (runsThroughSecretlessWrapper(command, wrapperPath)) continue;

    // Validate server name for defense in depth
    if (!SAFE_NAME.test(serverName)) continue;

    // Skip if no secrets for this server
    const secrets = serverSecrets[serverName];
    if (!secrets || Object.keys(secrets).length === 0) continue;

    // Build new args: ['--server', name, '--client', client, [--backend type], [--binding id], '--', originalCommand, ...originalArgs]
    const bindingId = bindings !== undefined && Object.prototype.hasOwnProperty.call(bindings, serverName)
      ? bindings[serverName]
      : undefined;
    const newArgs = [
      '--server', serverName,
      '--client', client,
      ...(backendType && backendType !== 'local' ? ['--backend', backendType] : []),
      ...(bindingId === undefined ? [] : ['--binding', bindingId]),
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

  return serversRewritten;
}

/**
 * Set the binding id of servers that already run through the wrapper, in the
 * server map of `container` under the key serverMapKey names: `--binding
 * <id>` inserted immediately before the `--` that ends the wrapper's own args,
 * or the value of the --binding the wrapper reads replaced where it stands
 * (see withWrapperBinding). Nothing else of the entry changes: not its
 * command, not its env, not the order of its other args. The caller names
 * only servers that run through the wrapper. Returns how many servers
 * changed; the caller writes the file.
 */
export function bindServers(container: Record<string, unknown>, bindings: Record<string, string>): number {
  const key = serverMapKey(container);
  const mcpServers = key === undefined ? undefined : container[key];
  if (!mcpServers || typeof mcpServers !== 'object') return 0;

  let serversChanged = 0;
  for (const [serverName, id] of Object.entries(bindings)) {
    if (!Object.prototype.hasOwnProperty.call(mcpServers, serverName)) continue;
    const serverDef = (mcpServers as Record<string, unknown>)[serverName];
    if (!serverDef || typeof serverDef !== 'object' || Array.isArray(serverDef)) continue;
    const args = (serverDef as Record<string, unknown>)['args'];
    if (!Array.isArray(args) || !args.every((a): a is string => typeof a === 'string')) continue;
    const next = withWrapperBinding(args, id);
    if (next === undefined || JSON.stringify(next) === JSON.stringify(args)) continue;
    (serverDef as Record<string, unknown>)['args'] = next;
    serversChanged++;
  }
  return serversChanged;
}

/**
 * Set to `wrapperPath` the command of servers that run through another
 * build's wrapper, in the server map of `container` under the key
 * serverMapKey names. Nothing else of an entry changes: not its args, so not
 * the digest of the command after its `--`, not its env, not the order of its
 * keys. A server is changed only when its command runs through a secretless
 * wrapper (see runsThroughSecretlessWrapper) and is not `wrapperPath`. Returns
 * the names of the servers changed; the caller writes the file.
 */
function repointServers(container: Record<string, unknown>, names: readonly string[], wrapperPath: string): string[] {
  const key = serverMapKey(container);
  const mcpServers = key === undefined ? undefined : container[key];
  if (!mcpServers || typeof mcpServers !== 'object') return [];

  const changed: string[] = [];
  for (const name of names) {
    if (!Object.prototype.hasOwnProperty.call(mcpServers, name)) continue;
    const serverDef = (mcpServers as Record<string, unknown>)[name];
    if (!serverDef || typeof serverDef !== 'object' || Array.isArray(serverDef)) continue;
    const command = (serverDef as Record<string, unknown>)['command'];
    if (typeof command !== 'string' || command === wrapperPath || !runsThroughSecretlessWrapper(command, wrapperPath)) continue;
    (serverDef as Record<string, unknown>)['command'] = wrapperPath;
    changed.push(name);
  }
  return changed;
}

/**
 * Remove env keys from servers of one server map, the one in `container`
 * under the key serverMapKey names, leaving each server's command and args as
 * they are. Returns how many servers had a key removed; the caller writes the
 * file.
 */
function removeEnvKeys(container: Record<string, unknown>, envKeys: Record<string, string[]>): number {
  const key = serverMapKey(container);
  const mcpServers = key === undefined ? undefined : container[key];
  if (!mcpServers || typeof mcpServers !== 'object') return 0;

  let serversChanged = 0;
  for (const [serverName, keys] of Object.entries(envKeys)) {
    if (!Object.prototype.hasOwnProperty.call(mcpServers, serverName)) continue;
    const serverDef = (mcpServers as Record<string, unknown>)[serverName];
    if (!serverDef || typeof serverDef !== 'object') continue;
    const env = (serverDef as Record<string, unknown>)['env'];
    if (!env || typeof env !== 'object' || Array.isArray(env)) continue;

    const present = keys.filter((envKey) => Object.prototype.hasOwnProperty.call(env, envKey));
    for (const envKey of present) delete (env as Record<string, unknown>)[envKey];
    if (present.length > 0) serversChanged++;
  }
  return serversChanged;
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
  const backupContent = readBackup(readManifest(backupDir)[configPath], backupDir);
  if (backupContent === undefined) {
    return false;
  }

  fs.writeFileSync(configPath, backupContent, { mode: 0o600 });
  fs.chmodSync(configPath, 0o600);

  return true;
}

/**
 * The content of the backup of a config file that restoreConfig writes back:
 * the file as it was before protect-mcp first changed it, or undefined when
 * there is none or it is not valid JSON. protect-mcp reads it to tell whether
 * the secrets stored for a project-level entry came from that file.
 */
export function readConfigBackup(configPath: string, backupDir: string): string | undefined {
  return readBackup(readManifest(backupDir)[configPath], backupDir);
}

/**
 * File the backup kept for `fromPath` under `toPath` in the manifest, for a
 * config file that moved, so restoreConfig restores it at its new path.
 * Returns what puts the manifest back as it was, or undefined, with nothing
 * changed, when the manifest names no backup for `fromPath`.
 */
export function moveConfigBackup(fromPath: string, toPath: string, backupDir: string): (() => void) | undefined {
  const manifest = readManifest(backupDir);
  if (!Object.prototype.hasOwnProperty.call(manifest, fromPath)) return undefined;
  const before = { ...manifest };
  manifest[toPath] = manifest[fromPath];
  delete manifest[fromPath];
  writeManifest(backupDir, manifest);
  return () => writeManifest(backupDir, before);
}

/**
 * The content of the backup at `bkPath`, as restoreConfig writes it back, or
 * undefined when there is no backup there or it is not valid JSON.
 */
function readBackup(bkPath: string | undefined, backupDir: string): string | undefined {
  if (!bkPath || !fs.existsSync(bkPath)) {
    return undefined;
  }

  const rawBackup = fs.readFileSync(bkPath);
  let backupContent: string;

  // Try decrypting: new scrypt key first, then legacy SHA-256 key, then plaintext
  try {
    const backupKey = deriveBackupKey(backupDir);
    backupContent = decryptBackup(rawBackup, backupKey);
  } catch {
    try {
      // Legacy SHA-256 encrypted backup
      const legacyKey = deriveLegacyBackupKey();
      backupContent = decryptBackup(rawBackup, legacyKey);
      legacyKey.fill(0);
    } catch {
      // Legacy plaintext backup — still support reading it
      backupContent = rawBackup.toString('utf-8');
    }
  }

  // Verify backup is valid JSON before restoring
  try {
    JSON.parse(backupContent);
  } catch {
    return undefined;
  }

  return backupContent;
}
