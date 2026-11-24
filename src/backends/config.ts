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
    if (isSelectableBackendType(config.backend)) {
      return config.backend;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * The version of secretless-ai that is running. Read only when a config names
 * an unsupported backend: the MCP wrapper runs from a copy of dist/ with no
 * package.json above it, and loading this module must not fail there.
 */
function installedVersion(): string {
  try {
    return String(require('../../package.json').version);
  } catch {
    return 'unknown';
  }
}

/**
 * The first release that implemented each backend this version implements.
 * A config written by a later release can name a backend that is not here;
 * the first release that has it is then later than this one.
 */
export const BACKEND_FIRST_VERSION: Readonly<Record<SelectableBackendType, string>> = {
  local: '0.8.0',
  keychain: '0.8.0',
  '1password': '0.8.0',
  vault: '0.10.0',
  'gcp-sm': '0.11.4',
};

function isSelectableBackendType(value: unknown): value is SelectableBackendType {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(BACKEND_FIRST_VERSION, value);
}

/** A configured backend this version does not implement (#182). */
export interface UnsupportedBackend {
  /** The backend the config file names, as written. */
  name: string;
  /** The version of secretless-ai that is running. */
  installedVersion: string;
  /** The first release that implements it, when this version knows one. */
  firstSupportedVersion: string | null;
}

/**
 * Raised by every command that reads or writes secrets while the config file
 * names a backend this version does not implement. Nothing is read from or
 * written to another store in its place: a write that lands in a store the
 * user did not choose reports success and is found by nothing.
 */
export class UnsupportedBackendError extends Error {
  readonly backend: UnsupportedBackend;

  constructor(backend: UnsupportedBackend) {
    super(unsupportedBackendMessage(backend));
    this.backend = backend;
  }
}

/** `<name> (unsupported by secretless-ai <version>)`, the form `status` shows. */
export function describeUnsupportedBackend(backend: UnsupportedBackend): string {
  return `${backend.name} (unsupported by secretless-ai ${backend.installedVersion})`;
}

function unsupportedBackendMessage(backend: UnsupportedBackend): string {
  const since = backend.firstSupportedVersion
    ? `It is supported from secretless-ai ${backend.firstSupportedVersion}.`
    : `No version up to ${backend.installedVersion} supports it; the first that does is later than this one.`;
  return [
    `Configured backend "${backend.name}" is not supported by secretless-ai ${backend.installedVersion}, the installed version.`,
    `  ${since}`,
    '',
    '  Nothing was read from or written to another store in its place.',
    '',
    `  Verify:  cat ${configPath()}`,
    `  Fix:     install a version that supports "${backend.name}"`,
    '  Or choose a backend this version has:',
    '  Fix:     secretless-ai backend set local',
  ].join('\n');
}

/**
 * The backend the config file names when this version does not implement it,
 * else undefined. A missing file, a file that does not parse and a file with
 * no `backend` key all name no backend.
 */
export function readUnsupportedBackend(): UnsupportedBackend | undefined {
  let config: SecretlessConfig;
  try {
    config = JSON.parse(fs.readFileSync(configPath(), 'utf-8')) as SecretlessConfig;
  } catch {
    return undefined;
  }
  if (config === null || typeof config !== 'object' || !('backend' in config)) return undefined;
  const named: unknown = (config as { backend?: unknown }).backend;
  if (named === undefined || isSelectableBackendType(named)) return undefined;
  const name = typeof named === 'string' ? named : JSON.stringify(named);
  return { name, installedVersion: installedVersion(), firstSupportedVersion: null };
}

/**
 * Read the existing config for a read-modify-write.
 *
 * "Missing" and "present but unparseable" are different answers and must not
 * collapse into the same `{}`. Starting fresh over a file we failed to parse
 * silently drops every sibling key — set the backend and `cacheTtl` is gone,
 * set the TTL and the backend reverts to `local`. For a tool that decides
 * where credentials get written, quietly resetting that choice is the same
 * class of defect as `init` clobbering settings.json (#122): a destructive
 * write reported as a success.
 *
 * Throws when the file exists and cannot be parsed. Callers surface the
 * message; nothing is written.
 */
function readConfigForUpdate(fp: string): SecretlessConfig {
  let raw: string;
  try {
    raw = fs.readFileSync(fp, 'utf-8');
  } catch {
    return {}; // No existing config — a fresh document is correct here.
  }

  if (raw.trim() === '') return {};

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `${fp} is not valid JSON, so it was left unchanged (${(err as Error).message}). `
      + `Fix or delete the file, then retry.`,
    );
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(
      `${fp} does not contain a JSON object, so it was left unchanged. `
      + `Fix or delete the file, then retry.`,
    );
  }

  return parsed as SecretlessConfig;
}

function writeConfig(fp: string, config: SecretlessConfig): void {
  const tmpPath = fp + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmpPath, fp);
}

/** Write the backend preference to the config file. */
export function writeBackendConfig(backend: SelectableBackendType): void {
  const dir = configDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const fp = configPath();
  const config = readConfigForUpdate(fp);
  config.backend = backend;
  writeConfig(fp, config);
}

/**
 * Resolve which backend type to use.
 *
 * Priority: explicit flag > config file > default ('local').
 * Throws UnsupportedBackendError when no flag names a backend and the config
 * file names one this version does not implement.
 */
export function resolveBackendType(explicitFlag?: string): SelectableBackendType {
  if (isSelectableBackendType(explicitFlag)) {
    return explicitFlag;
  }
  // A config naming a backend this version does not implement is a choice the
  // user made, not an absent one: answering with the default would put every
  // secret in a store they never chose (#182).
  const unsupported = readUnsupportedBackend();
  if (unsupported) throw new UnsupportedBackendError(unsupported);
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
  const config = readConfigForUpdate(fp);
  config.cacheTtl = ttlSeconds;
  writeConfig(fp, config);
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
