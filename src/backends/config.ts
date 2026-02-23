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
export type SelectableBackendType = 'local' | 'keychain' | '1password';

const CONFIG_FILENAME = 'config.json';
const DEFAULT_BACKEND: SelectableBackendType = 'local';

interface SecretlessConfig {
  backend?: SelectableBackendType;
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
    if (config.backend === 'local' || config.backend === 'keychain' || config.backend === '1password') {
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
  if (explicitFlag === 'local' || explicitFlag === 'keychain' || explicitFlag === '1password') {
    return explicitFlag;
  }
  return readBackendConfig() ?? DEFAULT_BACKEND;
}
