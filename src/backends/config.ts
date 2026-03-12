/**
 * Backend configuration manager.
 *
 * Reads and writes the user's backend preference from ~/.secretless-ai/config.json.
 * Resolution priority: explicit CLI flag > config file > default ('local').
 */

import * as fs from 'fs';
import * as path from 'path';
import type { BackendType } from './types';

/** Writable backend types that can be selected by the user. */
export type SelectableBackendType = 'local' | 'keychain' | '1password' | 'vault' | 'gcp-sm';

const CONFIG_FILENAME = 'config.json';
const DEFAULT_BACKEND: SelectableBackendType = 'local';

/** Default cache TTL: 5 minutes (in seconds). */
export const DEFAULT_CACHE_TTL_SECONDS = 300;

interface SecretlessConfig {
  backend?: SelectableBackendType;
  /** Cache TTL in seconds. 0 = disabled. Default: 300 (5 minutes). */
  cacheTtl?: number;
}

function configDir(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  return path.join(home, '.secretless-ai');
}

function configPath(): string {
  return path.join(configDir(), CONFIG_FILENAME);
}

/** Read the current backend configuration. Returns undefined if no config file exists. */
export function readBackendConfig(): SelectableBackendType | undefined {
  try {
    const raw = fs.readFileSync(configPath(), 'utf-8');
    const config = JSON.parse(raw) as SecretlessConfig;
    if (config.backend === 'local' || config.backend === 'keychain' || config.backend === '1password' || config.backend === 'vault' || config.backend === 'gcp-sm') {
      return config.backend;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/** Write the backend preference to the config file. */
export function writeBackendConfig(backend: SelectableBackendType): void {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const fp = configPath();
  let config: SecretlessConfig = {};
  try {
    const raw = fs.readFileSync(fp, 'utf-8');
    config = JSON.parse(raw) as SecretlessConfig;
  } catch {
    // No existing config or invalid JSON — start fresh
  }

  config.backend = backend;
  const tmpPath = fp + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmpPath, fp);
}

/**
 * Resolve which backend type to use.
 *
 * Priority: explicit flag > config file > default ('local').
 */
export function resolveBackendType(explicitFlag?: string): SelectableBackendType {
  if (explicitFlag === 'local' || explicitFlag === 'keychain' || explicitFlag === '1password' || explicitFlag === 'vault' || explicitFlag === 'gcp-sm') {
    return explicitFlag;
  }
  return readBackendConfig() ?? DEFAULT_BACKEND;
}

/** Read the cache TTL from config (in seconds). Returns default if not set. */
export function readCacheTtl(): number {
  try {
    const raw = fs.readFileSync(configPath(), 'utf-8');
    const config = JSON.parse(raw) as SecretlessConfig;
    if (typeof config.cacheTtl === 'number' && config.cacheTtl >= 0) {
      return config.cacheTtl;
    }
    return DEFAULT_CACHE_TTL_SECONDS;
  } catch {
    return DEFAULT_CACHE_TTL_SECONDS;
  }
}

/** Write the cache TTL to the config file (in seconds). 0 = disabled. */
export function writeCacheTtl(ttlSeconds: number): void {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const fp = configPath();
  let config: SecretlessConfig = {};
  try {
    const raw = fs.readFileSync(fp, 'utf-8');
    config = JSON.parse(raw) as SecretlessConfig;
  } catch {
    // No existing config or invalid JSON — start fresh
  }

  config.cacheTtl = ttlSeconds;
  const tmpPath = fp + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmpPath, fp);
}

/**
 * Parse a human-readable duration string into seconds.
 * Supports: "5m", "1h", "1d", "300", "off" (0), "0".
 * Returns -1 if the format is invalid.
 */
export function parseDuration(input: string): number {
  const trimmed = input.trim().toLowerCase();
  if (trimmed === 'off' || trimmed === '0') return 0;

  // Pure number = seconds
  if (/^\d+$/.test(trimmed)) return parseInt(trimmed, 10);

  // Number + unit
  const match = trimmed.match(/^(\d+)\s*(s|m|h|d)$/);
  if (!match) return -1;

  const amount = parseInt(match[1], 10);
  switch (match[2]) {
    case 's': return amount;
    case 'm': return amount * 60;
    case 'h': return amount * 3600;
    case 'd': return amount * 86400;
    default: return -1;
  }
}

/**
 * Format a TTL in seconds as a human-readable string.
 */
export function formatTtl(seconds: number): string {
  if (seconds <= 0) return 'off';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${seconds / 60}m`;
  if (seconds < 86400) return `${seconds / 3600}h`;
  return `${seconds / 86400}d`;
}
